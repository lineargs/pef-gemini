"""Stage 1: Email Ingestion, Deduplication, Pending Label, & MIME Extraction.

Triggered by Pub/Sub topic `email-watch`.
Uses incremental, paginated `users.history.list` (with a `messages.list` fallback when
the stored cursor is missing or expired) so burst emails are not dropped, applies the
amber `Pending` label within <2s, and publishes normalized email context to
`email-analyze`.

Retry safety: each message is claimed with a short lease, marked `published` only
after the publish succeeds, and released on failure, and the history cursor only
advances once the whole batch is handled. With `--retry` on the trigger, a transient
failure is redelivered instead of leaving the email stuck in `Pending`.
"""

from __future__ import annotations

import base64
from email.utils import parseaddr
import html
import json
import logging
import os
import re
import time
from typing import Any

try:
    import functions_framework
except ImportError:  # Fallback for local zero-dependency offline runs

    class _FFStub:
        @staticmethod
        def cloud_event(fn: Any) -> Any:
            return fn

    functions_framework = _FFStub()  # type: ignore[assignment]

try:
    import tldextract

    _TLD_EXTRACTOR = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())
except ImportError:
    tldextract = None  # type: ignore[assignment]
    _TLD_EXTRACTOR = None

logging.basicConfig(level=logging.INFO)  # local runs; a no-op once the framework has set up logging
logger = logging.getLogger(__name__)
# On Cloud Run, functions-framework configures the root logger at WARNING before this
# module loads, so basicConfig above does nothing there. Set this logger's own level so
# INFO lines ("Analyzed message …", "Verdict for message …") reach Cloud Logging.
logger.setLevel(logging.INFO)

URL_REGEX = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
MULTI_PART_SUFFIXES = {"co.uk", "ac.uk", "gov.uk", "org.uk", "com.au", "co.nz"}
IGNORED_URL_PREFIXES = (
    "http://www.w3.org/",
    "https://www.w3.org/",
    "http://schemas.microsoft.com/",
    "https://schemas.microsoft.com/",
    "http://schemas.openxmlformats.org/",
    "https://schemas.openxmlformats.org/",
    "http://ns.adobe.com/",
    "https://ns.adobe.com/",
)
TEXT_ATTACHMENT_EXTENSIONS = (
    ".txt",
    ".csv",
    ".html",
    ".htm",
    ".md",
    ".json",
    ".xml",
    ".eml",
)

_ds_client: Any | None = None
_publisher_client: Any | None = None


def _get_datastore_client() -> Any:
    global _ds_client
    if _ds_client is None:
        from google.cloud import datastore

        project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
        _ds_client = datastore.Client(project=project_id)
    return _ds_client


def _get_publisher_client() -> Any:
    global _publisher_client
    if _publisher_client is None:
        from google.cloud import pubsub_v1

        _publisher_client = pubsub_v1.PublisherClient()
    return _publisher_client


def extract_urls(text: str) -> list[str]:
    """Extract unique HTTP/HTTPS URLs from text/HTML while preserving order."""
    if not text:
        return []
    unescaped = html.unescape(text)
    seen: set[str] = set()
    urls: list[str] = []
    for match in URL_REGEX.findall(unescaped):
        cleaned = match.rstrip(".,;:!?")
        lower_url = cleaned.lower()
        if any(lower_url.startswith(prefix) for prefix in IGNORED_URL_PREFIXES):
            continue
        if cleaned not in seen:
            seen.add(cleaned)
            urls.append(cleaned)
    return urls


def extract_sender_domain(from_header: str) -> str:
    """Safely extract registered domain from any RFC-5322 From header."""
    if not from_header:
        return ""
    _, email_addr = parseaddr(from_header)
    candidate = email_addr if "@" in email_addr else from_header
    host = candidate.split("@")[-1].strip("<> []").lower()
    if not host:
        return ""

    if _TLD_EXTRACTOR is not None:
        extracted = _TLD_EXTRACTOR(host)
        if extracted.domain and extracted.suffix:
            return f"https://{extracted.domain}.{extracted.suffix}"

    parts = [p for p in host.split(".") if p]
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return f"https://{'.'.join(parts[-3:])}"
    if len(parts) >= 2:
        return f"https://{'.'.join(parts[-2:])}"
    return f"https://{host}"


def _is_text_inspectable_attachment(filename: str, mime_type: str) -> bool:
    lower_name = (filename or "").lower()
    lower_mime = (mime_type or "").lower()
    return lower_name.endswith(TEXT_ATTACHMENT_EXTENSIONS) or lower_mime.startswith(
        "text/"
    )


def parse_gmail_mime_message(message: dict[str, Any]) -> dict[str, Any]:
    """Recursively extract headers, plain/HTML body, and attachments from a Gmail API message."""
    payload = message.get("payload", {})
    headers = {
        h["name"].lower(): h["value"] for h in payload.get("headers", []) if "name" in h
    }

    body_chunks: list[str] = []
    attachments: list[dict[str, Any]] = []

    def _walk_parts(part: dict[str, Any]) -> None:
        mime_type = part.get("mimeType", "")
        filename = part.get("filename", "")
        body = part.get("body", {})
        att_id = body.get("attachmentId")
        data_b64 = body.get("data")

        if filename and (att_id or data_b64):
            inline_content: str | None = None
            if data_b64 and _is_text_inspectable_attachment(filename, mime_type):
                inline_content = base64.urlsafe_b64decode(
                    data_b64.encode("utf-8")
                ).decode("utf-8", errors="replace")
            attachments.append(
                {
                    "attachmentId": att_id,
                    "filename": filename,
                    "mimeType": mime_type,
                    "content": inline_content,
                }
            )
            return

        if data_b64 and mime_type in ("text/plain", "text/html"):
            decoded = base64.urlsafe_b64decode(data_b64.encode("utf-8")).decode(
                "utf-8", errors="replace"
            )
            body_chunks.append(decoded)

        for subpart in part.get("parts", []):
            _walk_parts(subpart)

    _walk_parts(payload)
    body_text = "\n".join(body_chunks).strip()

    # Prefer text-inspectable attachments over inline images when selecting primary attachment
    primary_att: dict[str, Any] | None = None
    if attachments:
        text_atts = [
            a
            for a in attachments
            if _is_text_inspectable_attachment(a["filename"], a["mimeType"])
        ]
        primary_att = text_atts[0] if text_atts else attachments[0]

    return {
        "messageId": message.get("id", ""),
        "from": headers.get("from", ""),
        "subject": headers.get("subject", ""),
        "date": headers.get("date", ""),
        "body": body_text,
        "attachmentId": primary_att["attachmentId"] if primary_att else None,
        "attachmentFilename": primary_att["filename"] if primary_att else None,
        "attachmentMimeType": primary_att["mimeType"] if primary_att else None,
        "attachmentContent": primary_att["content"] if primary_att else None,
        "attachments": attachments,
    }


CLAIM_LEASE_SECONDS = int(os.environ.get("PEF_CLAIM_LEASE_SECONDS", "300"))
# After this many failed attempts a message is parked as `failed` so one poison
# message cannot block every later message in the mailbox.
MAX_MESSAGE_ATTEMPTS = int(os.environ.get("PEF_MAX_MESSAGE_ATTEMPTS", "5"))
# Keep published payloads well under Pub/Sub's 10 MB limit; analyze truncates to the
# same size before calling Gemini, and the Safe Browsing Lookup API takes <= 500 URLs.
MAX_TEXT_CHARS = 32_000
MAX_URLS = 500
STATUS_PROCESSING = "processing"
STATUS_PUBLISHED = "published"
STATUS_SKIPPED = "skipped"
STATUS_FAILED = "failed"
FINAL_STATUSES = (STATUS_PUBLISHED, STATUS_SKIPPED, STATUS_FAILED)


class LeaseHeldError(RuntimeError):
    """Raised so Pub/Sub redelivers while another invocation's lease is unexpired.

    If that invocation crashed (timeout, OOM, instance kill) it never released its
    claim; acknowledging this notification would leave the message unprocessed until
    some unrelated mailbox change. Raising lets Pub/Sub's backoff retry past the lease.
    """


def _is_final_entity(entity: Any) -> bool:
    if entity is None:
        return False
    status = entity.get("status")
    # Entities written by older versions only carry `processed=True`.
    return status in FINAL_STATUSES or (status is None and bool(entity.get("processed")))


def _claim_message(ds: Any, message_id: str, now: int | None = None) -> bool:
    """Atomically claim a message for processing using a short lease.

    Returns False if the message is finished (published, skipped or failed) or if
    another invocation holds an unexpired lease. A crashed invocation's lease expires
    after PEF_CLAIM_LEASE_SECONDS (keep it above the function timeout), so a retry can
    take the message over. Each claim counts an attempt; after PEF_MAX_MESSAGE_ATTEMPTS
    the message is parked as `failed` (it keeps its Pending label, i.e. "not scanned")
    instead of blocking the mailbox. A message is only marked `published` after the
    publish succeeds (see `_mark_message`).
    """
    from google.cloud import datastore

    now = int(time.time()) if now is None else now
    with ds.transaction():
        key = ds.key("emailNotifications", message_id)
        entity = ds.get(key)
        if _is_final_entity(entity):
            return False
        attempts = int(entity.get("attempts", 0)) if entity is not None else 0
        if entity is not None and int(entity.get("leaseUntil", 0)) > now:
            return False
        claim = entity if entity is not None else datastore.Entity(key=key)
        if attempts >= MAX_MESSAGE_ATTEMPTS:
            claim.update({"status": STATUS_FAILED, "processed": True, "processedAt": now})
            ds.put(claim)
            logger.error(
                "PEF_MESSAGE_FAILED: message %s failed %d times; parked as `failed` "
                "(left labelled Pending).",
                message_id,
                attempts,
            )
            return False
        claim.update(
            {
                "status": STATUS_PROCESSING,
                "leaseUntil": now + CLAIM_LEASE_SECONDS,
                "claimedAt": now,
                "attempts": attempts + 1,
            }
        )
        ds.put(claim)
        return True


def _mark_message(ds: Any, message_id: str, status: str) -> None:
    """Record the final state of a claimed message (`published` or `skipped`)."""
    from google.cloud import datastore

    entity = datastore.Entity(key=ds.key("emailNotifications", message_id))
    entity.update(
        {"status": status, "processed": True, "processedAt": int(time.time())}
    )
    ds.put(entity)


def _is_finished(ds: Any, message_id: str) -> bool:
    """True if the message reached a final state (published, skipped or failed)."""
    return _is_final_entity(ds.get(ds.key("emailNotifications", message_id)))


def _release_claim(ds: Any, message_id: str) -> None:
    """Expire a claim after a failure so a retry can reprocess immediately.

    The entity (and its attempt count) is kept; only the lease is cleared.
    """
    try:
        key = ds.key("emailNotifications", message_id)
        with ds.transaction():
            entity = ds.get(key)
            if entity is not None and not _is_final_entity(entity):
                entity["leaseUntil"] = 0
                ds.put(entity)
    except Exception:  # Best effort: the lease expires on its own anyway.
        logger.exception("Could not release claim for %s", message_id)


def _is_not_found(exc: Exception) -> bool:
    status = getattr(getattr(exc, "resp", None), "status", None)
    return str(status) == "404"


def _get_label_id(ds: Any, label_name: str, email: str) -> str | None:
    """Direct O(1) Datastore key lookup for user's Gmail label ID."""
    entity = ds.get(ds.key(label_name, email))
    return entity.get("labelId") if entity else None


def _load_user_credentials(ds: Any, email: str) -> Any:
    from google.oauth2.credentials import Credentials

    entity = ds.get(ds.key("OAuthToken", email))
    if not entity or "token_json" not in entity:
        raise ValueError(f"No stored OAuth credentials found for {email}")
    return Credentials.from_authorized_user_info(json.loads(entity["token_json"]))


FALLBACK_SCAN_SIZE = int(os.environ.get("PEF_FALLBACK_SCAN_SIZE", "10"))


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _collect_inbox_message_ids(
    gmail: Any,
    ds: Any,
    email: str,
    notification_history_id: str | None,
) -> tuple[list[str], str | None]:
    """Return (new INBOX message IDs, history ID to store once they are processed).

    Uses incremental `history.list` from the stored `lastHistoryId`, following every
    `nextPageToken` so large bursts are not truncated. Falls back to scanning the most
    recent INBOX messages only when there is no stored cursor yet or the cursor has
    expired (history.list returns 404). Notifications caused by label changes (including
    our own Pending/Secured labels) produce no `messageAdded` records and therefore no
    work. The caller must persist the returned history ID only after every message has
    been handled, so a failed run is replayed from the same cursor on retry.
    """
    state_entity = ds.get(ds.key("MailboxWatchState", email))
    start_history_id = state_entity.get("lastHistoryId") if state_entity else None

    message_ids: list[str] = []
    newest_history_id = _as_int(notification_history_id)
    use_fallback = not start_history_id

    if start_history_id:
        page_token: str | None = None
        try:
            while True:
                kwargs: dict[str, Any] = {
                    "userId": "me",
                    "startHistoryId": str(start_history_id),
                    "historyTypes": ["messageAdded"],
                    "labelId": "INBOX",
                }
                if page_token:
                    kwargs["pageToken"] = page_token
                history_resp = gmail.users().history().list(**kwargs).execute()
                for record in history_resp.get("history", []):
                    for added in record.get("messagesAdded", []):
                        msg_id = added.get("message", {}).get("id")
                        if msg_id and msg_id not in message_ids:
                            message_ids.append(msg_id)
                newest_history_id = max(
                    newest_history_id, _as_int(history_resp.get("historyId"))
                )
                page_token = history_resp.get("nextPageToken")
                if not page_token:
                    break
        except Exception as exc:
            if not _is_not_found(exc):
                raise  # Transient error: let Pub/Sub retry with the same cursor.
            logger.warning(
                "Stored startHistoryId=%s for %s has expired; falling back to a scan "
                "of the latest %d INBOX messages.",
                start_history_id,
                email,
                FALLBACK_SCAN_SIZE,
            )
            use_fallback = True

    if use_fallback:
        list_res = (
            gmail.users()
            .messages()
            .list(userId="me", labelIds=["INBOX"], maxResults=FALLBACK_SCAN_SIZE)
            .execute()
        )
        for m in list_res.get("messages", []):
            if m.get("id") and m["id"] not in message_ids:
                message_ids.append(m["id"])

    # Never move the cursor backwards (Pub/Sub can deliver notifications out of order).
    if newest_history_id <= _as_int(start_history_id):
        return message_ids, None
    return message_ids, str(newest_history_id)


def _save_last_history_id(ds: Any, email: str, history_id: str) -> None:
    """Advance the stored history cursor (monotonic) after messages were handled."""
    from google.cloud import datastore

    key = ds.key("MailboxWatchState", email)
    with ds.transaction():
        entity = ds.get(key) or datastore.Entity(key=key)
        if _as_int(history_id) <= _as_int(entity.get("lastHistoryId")):
            return
        entity["email"] = email
        entity["lastHistoryId"] = str(history_id)
        entity["updatedAt"] = int(time.time())
        ds.put(entity)


def build_analysis_payload(raw_msg: dict[str, Any]) -> dict[str, Any]:
    """Normalize an ingested message into the payload sent to `email-analyze`."""
    sender = raw_msg.get("from", "")
    full_body = raw_msg.get("body") or ""
    # Extract URLs from the full body, then bound everything that is published.
    urls = extract_urls(full_body)[:MAX_URLS]
    body = full_body[:MAX_TEXT_CHARS]
    attachment_content = raw_msg.get("attachmentContent")
    if attachment_content is not None:
        attachment_content = str(attachment_content)[:MAX_TEXT_CHARS]
    sender_domain = extract_sender_domain(sender)
    has_attachment = bool(
        attachment_content
        or raw_msg.get("attachmentId")
        or raw_msg.get("attachmentFilename")
    )

    return {
        "messageID": raw_msg.get("messageId")
        or raw_msg.get("id")
        or raw_msg.get("messageID", "sim-msg-001"),
        "emailAddress": raw_msg.get("emailAddress", "demo@example.com"),
        "senderEmailAddress": sender,
        "senderDomain": sender_domain,
        "subject": raw_msg.get("subject", ""),
        "date": raw_msg.get("date", ""),
        "body": body,
        "urls": urls,
        "links": len(urls) > 0,
        "attachment": has_attachment,
        "attachmentFilename": raw_msg.get("attachmentFilename"),
        "attachmentContent": attachment_content,
        "simulated": bool(raw_msg.get("simulated", False)),
    }


def _publish_to_analyze(payload: dict[str, Any]) -> str:
    project_id = os.environ["GOOGLE_CLOUD_PROJECT"]
    topic_name = os.environ.get("TOPIC_EMAIL_ANALYZE", "email-analyze")
    publisher = _get_publisher_client()
    topic_path = publisher.topic_path(project_id, topic_name)
    future = publisher.publish(topic_path, json.dumps(payload).encode("utf-8"))
    return future.result(timeout=10)


def _is_auth_expired(exc: BaseException) -> bool:
    """True when Google no longer accepts the stored refresh token.

    That happens when the sign-in expired (7 days in Testing mode), was revoked, or the
    Google password changed; the fix is to sign in again at the onboarding URL. Logged
    with the PEF_AUTH_EXPIRED marker, which the alert deploy.sh creates matches on.
    """
    if "invalid_grant" in str(exc):
        return True
    try:
        from google.auth.exceptions import RefreshError
    except ImportError:  # pragma: no cover - google-auth ships with the client libraries
        return False
    return isinstance(exc, RefreshError) and not getattr(exc, "retryable", False)


@functions_framework.cloud_event
def email_ingest(cloud_event: Any) -> None:
    """Cloud Run Function entry point triggered by `email-watch` Pub/Sub topic."""
    pubsub_data = base64.b64decode(cloud_event.data["message"]["data"]).decode("utf-8")
    notification = json.loads(pubsub_data)

    # Mode 1: Direct / Simulated email injection (explicitly gated by ALLOW_SIMULATED_PAYLOADS)
    allow_simulated = (
        os.environ.get("ALLOW_SIMULATED_PAYLOADS", "false").lower() == "true"
    )
    if allow_simulated and (notification.get("simulated") or "body" in notification):
        payload = build_analysis_payload({**notification, "simulated": True})
        msg_id = _publish_to_analyze(payload)
        logger.info(
            "Published simulated email %s to email-analyze (pubsub_id=%s)",
            payload["messageID"],
            msg_id,
        )
        return

    # Mode 2: Live Gmail Push Notification
    email = notification["emailAddress"]
    try:
        _ingest_mailbox(email, notification.get("historyId"))
    except Exception as exc:
        if _is_auth_expired(exc):
            logger.error(
                "PEF_AUTH_EXPIRED: the Gmail sign-in for %s has expired or was revoked; "
                "open the onboarding URL to sign in again.",
                email,
            )
        raise  # Pub/Sub retries; after re-onboarding, a retry goes through.


def _ingest_mailbox(email: str, notification_history_id: Any) -> None:
    """Collect the mailbox's new INBOX messages and publish each one for analysis."""
    from googleapiclient.discovery import build

    ds = _get_datastore_client()
    creds = _load_user_credentials(ds, email)
    gmail = build("gmail", "v1", credentials=creds)

    candidate_ids, new_history_id = _collect_inbox_message_ids(
        gmail, ds, email, notification_history_id
    )
    if not candidate_ids:
        logger.info("No new INBOX messages for %s", email)
    else:
        pending_label_id = _get_label_id(ds, "Pending", email)
        leased_elsewhere: list[str] = []
        for msg_id in candidate_ids:
            if not _claim_message(ds, msg_id):
                if not _is_finished(ds, msg_id):
                    # Another invocation holds the lease (or crashed holding it).
                    # Do not move the cursor past this message, and raise at the end
                    # so Pub/Sub retries after the lease can have expired.
                    leased_elsewhere.append(msg_id)
                continue
            try:
                _ingest_one_message(gmail, email, msg_id, pending_label_id)
                _mark_message(ds, msg_id, STATUS_PUBLISHED)
            except Exception as exc:
                if _is_not_found(exc):
                    # Deleted or moved before we could read it: nothing to label.
                    logger.info("Message %s no longer exists; skipping.", msg_id)
                    _mark_message(ds, msg_id, STATUS_SKIPPED)
                    continue
                _release_claim(ds, msg_id)
                raise  # Pub/Sub redelivers; already-published messages are skipped.

        if leased_elsewhere:
            raise LeaseHeldError(
                f"Messages {leased_elsewhere} are leased by another invocation; "
                "retrying so they are not lost if that invocation crashed."
            )

    # Only advance the cursor once every message in this batch was handled.
    if new_history_id:
        _save_last_history_id(ds, email, new_history_id)


def _ingest_one_message(
    gmail: Any, email: str, msg_id: str, pending_label_id: str | None
) -> None:
    """Fetch, label as Pending, extract attachment text and publish one message."""
    full_msg = gmail.users().messages().get(userId="me", id=msg_id).execute()
    parsed = parse_gmail_mime_message(full_msg)
    parsed["emailAddress"] = email

    # Apply Pending label immediately (<2s NFR)
    if pending_label_id:
        gmail.users().messages().modify(
            userId="me",
            id=msg_id,
            body={"addLabelIds": [pending_label_id]},
        ).execute()

    # Fetch external text-inspectable attachment content if not already inline
    if (
        parsed["attachmentId"]
        and not parsed.get("attachmentContent")
        and _is_text_inspectable_attachment(
            parsed.get("attachmentFilename") or "",
            parsed.get("attachmentMimeType") or "",
        )
    ):
        att = (
            gmail.users()
            .messages()
            .attachments()
            .get(userId="me", messageId=msg_id, id=parsed["attachmentId"])
            .execute()
        )
        parsed["attachmentContent"] = base64.urlsafe_b64decode(
            att["data"].encode("utf-8")
        ).decode("utf-8", errors="replace")

    payload = build_analysis_payload(parsed)
    _publish_to_analyze(payload)
    logger.info("Ingested & published Gmail message %s for analysis.", msg_id)
