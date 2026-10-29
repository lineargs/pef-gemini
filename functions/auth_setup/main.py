"""Stage 0: OAuth2 Onboarding, Gmail Label Provisioning, & Push Notification Setup.

Modernized replacement for auth_init, auth_callback, and emailLabels, plus
automated daily `users.watch` renewal (`auth_renew_watch`) for Cloud Scheduler.
Deploys as HTTP-triggered Cloud Run Functions (Gen 2) with CSRF state & PKCE protection.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import time
from typing import Any

try:
    import functions_framework
except ImportError:

    class _FFStub:
        @staticmethod
        def http(fn: Any) -> Any:
            return fn

    functions_framework = _FFStub()  # type: ignore[assignment]

logging.basicConfig(level=logging.INFO)  # local runs; a no-op once the framework has set up logging
logger = logging.getLogger(__name__)
# On Cloud Run, functions-framework configures the root logger at WARNING before this
# module loads, so basicConfig above does nothing there. Set this logger's own level so
# INFO lines ("Analyzed message …", "Verdict for message …") reach Cloud Logging.
logger.setLevel(logging.INFO)

SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/spreadsheets",
]

PEF_LABELS = {
    "Pending": {"textColor": "#000000", "backgroundColor": "#ffd6a2"},
    "Secured": {"textColor": "#ffffff", "backgroundColor": "#16a765"},
    "Unsecured": {"textColor": "#ffffff", "backgroundColor": "#fb4c2f"},
}

OAUTH_STATE_TTL_SECONDS = 600
_ds_client: Any | None = None


def _get_datastore_client() -> Any:
    global _ds_client
    if _ds_client is None:
        from google.cloud import datastore

        project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
        _ds_client = datastore.Client(project=project_id)
    return _ds_client


def _json_response(
    payload: dict[str, Any], status_code: int = 200
) -> tuple[str, int, dict[str, str]]:
    return (
        json.dumps(payload),
        status_code,
        {"Content-Type": "application/json; charset=utf-8"},
    )


def _build_oauth_flow(state: str | None = None) -> Any:
    from google_auth_oauthlib.flow import Flow

    client_id = os.environ["GOOGLE_CLIENT_ID"]
    client_secret = os.environ["GOOGLE_CLIENT_SECRET"]
    redirect_uri = os.environ["GOOGLE_CALLBACK_URL"]

    client_config = {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [redirect_uri],
        }
    }
    flow = Flow.from_client_config(client_config, scopes=SCOPES, state=state)
    flow.redirect_uri = redirect_uri
    return flow


def _save_oauth_state(state: str, code_verifier: str | None = None) -> None:
    """Persist single-use OAuth2 state nonce and PKCE code_verifier in Datastore."""
    from google.cloud import datastore

    ds = _get_datastore_client()
    key = ds.key("OAuthState", state)
    entity = datastore.Entity(key=key, exclude_from_indexes=("code_verifier",))
    entity.update(
        {
            "created_at": int(time.time()),
            "code_verifier": code_verifier or "",
        }
    )
    ds.put(entity)


def _consume_oauth_state(state: str) -> tuple[bool, str | None]:
    """Atomically verify and delete a single-use OAuth2 state nonce."""
    if not state:
        return False, None
    ds = _get_datastore_client()
    key = ds.key("OAuthState", state)
    with ds.transaction():
        entity = ds.get(key)
        if entity is None:
            return False, None
        ds.delete(key)
        created_at = int(entity.get("created_at", 0))
        if int(time.time()) - created_at > OAUTH_STATE_TTL_SECONDS:
            return False, None
        code_verifier = entity.get("code_verifier") or None
        return True, code_verifier


def _is_email_allowed(email: str) -> bool:
    """Check comma-separated ALLOWED_EMAILS allowlist.

    Fails closed when ALLOWED_EMAILS is empty unless ALLOW_ANY_ONBOARDING_EMAIL=true
    is explicitly set, preventing unauthorized users from onboarding and consuming
    Gemini / Safe Browsing quota.
    """
    raw_allowed = os.environ.get("ALLOWED_EMAILS", "").strip()
    if not raw_allowed:
        return (
            os.environ.get("ALLOW_ANY_ONBOARDING_EMAIL", "false").lower() == "true"
        )
    allowed = {addr.strip().lower() for addr in raw_allowed.split(",") if addr.strip()}
    return email.strip().lower() in allowed


def save_user_credentials(email: str, creds: Any) -> None:
    """Persist user OAuth2 tokens in Cloud Datastore keyed by email."""
    from google.cloud import datastore

    ds = _get_datastore_client()
    key = ds.key("OAuthToken", email)
    entity = datastore.Entity(key=key, exclude_from_indexes=("token_json",))
    entity.update(
        {
            "email": email,
            "token_json": creds.to_json(),
            "updated_at": int(time.time()),
        }
    )
    ds.put(entity)


def _save_watch_state(email: str, watch_resp: dict[str, Any]) -> None:
    """Persist Gmail watch expiration, and seed the history cursor on first setup.

    The `lastHistoryId` cursor is owned by `email_ingest`, which advances it only after
    messages are processed. A daily renewal must not overwrite it with the mailbox's
    current historyId, or any mail that arrived while ingest was failing would be
    skipped. So the cursor is only written here when none exists yet.
    """
    from google.cloud import datastore

    ds = _get_datastore_client()
    key = ds.key("MailboxWatchState", email)
    with ds.transaction():
        entity = ds.get(key) or datastore.Entity(key=key)
        if not entity.get("lastHistoryId") and watch_resp.get("historyId"):
            entity["lastHistoryId"] = str(watch_resp["historyId"])
        entity["email"] = email
        entity["expiration"] = str(watch_resp.get("expiration", ""))
        entity["renewedAt"] = int(time.time())
        ds.put(entity)


def ensure_pef_labels(gmail_service: Any, email: str) -> dict[str, str]:
    """Create Pending, Secured, and Unsecured labels in Gmail and store IDs in Datastore."""
    from google.cloud import datastore

    ds = _get_datastore_client()
    existing_resp = gmail_service.users().labels().list(userId="me").execute()
    existing_by_name = {
        lbl["name"]: lbl["id"] for lbl in existing_resp.get("labels", [])
    }

    label_ids: dict[str, str] = {}
    for label_name, colors in PEF_LABELS.items():
        if label_name in existing_by_name:
            label_id = existing_by_name[label_name]
        else:
            created = (
                gmail_service.users()
                .labels()
                .create(
                    userId="me",
                    body={
                        "name": label_name,
                        "labelListVisibility": "labelShowIfUnread",
                        "messageListVisibility": "show",
                        "type": "user",
                        "color": colors,
                    },
                )
                .execute()
            )
            label_id = created["id"]

        label_ids[label_name] = label_id
        # Direct key storage: Key(label_name, email) for O(1) lookup
        key = ds.key(label_name, email)
        entity = datastore.Entity(key=key)
        entity.update({"email": email, "labelId": label_id})
        ds.put(entity)

    return label_ids


@functions_framework.http
def auth_init(request: Any) -> tuple[str, int, dict[str, str]]:
    """HTTP Cloud Function that redirects the user to Google's OAuth 2.0 consent screen."""
    state_nonce = secrets.token_urlsafe(32)
    flow = _build_oauth_flow(state=state_nonce)
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    _save_oauth_state(state=state, code_verifier=getattr(flow, "code_verifier", None))
    return ("Redirecting to Google OAuth2...", 302, {"Location": authorization_url})


@functions_framework.http
def auth_callback(request: Any) -> tuple[str, int, dict[str, str]]:
    """HTTP Cloud Function that handles OAuth2 callback, provisions labels, and starts Gmail watch."""
    try:
        state = request.args.get("state", "")
        code = request.args.get("code", "")
        if not state or not code:
            return _json_response(
                {
                    "status": "error",
                    "message": "Missing required OAuth2 state or code parameter.",
                },
                400,
            )

        valid_state, code_verifier = _consume_oauth_state(state)
        if not valid_state:
            return _json_response(
                {
                    "status": "error",
                    "message": "Invalid or expired OAuth2 state parameter.",
                },
                403,
            )

        from googleapiclient.discovery import build

        flow = _build_oauth_flow(state=state)
        if code_verifier:
            flow.code_verifier = code_verifier
        flow.fetch_token(code=code)
        creds = flow.credentials

        oauth2_service = build("oauth2", "v2", credentials=creds)
        user_info = oauth2_service.userinfo().get().execute()
        email = user_info["email"]

        if not _is_email_allowed(email):
            logger.warning("Rejected unauthorized email onboarding attempt: %s", email)
            return _json_response(
                {
                    "status": "error",
                    "message": "Email address is not authorized for onboarding. Configure ALLOWED_EMAILS.",
                },
                403,
            )

        save_user_credentials(email, creds)

        gmail_service = build("gmail", "v1", credentials=creds)
        label_ids = ensure_pef_labels(gmail_service, email)

        project_id = os.environ["GOOGLE_CLOUD_PROJECT"]
        topic_name = os.environ.get("TOPIC_EMAIL_WATCH", "email-watch")
        watch_resp = (
            gmail_service.users()
            .watch(
                userId="me",
                body={
                    "labelIds": ["INBOX"],
                    "topicName": f"projects/{project_id}/topics/{topic_name}",
                },
            )
            .execute()
        )
        _save_watch_state(email, watch_resp)

        return _json_response(
            {
                "status": "ok",
                "email": email,
                "labels": label_ids,
                "watchTopic": f"projects/{project_id}/topics/{topic_name}",
                "watchExpiration": watch_resp.get("expiration"),
                "message": "Successfully configured PEF v2 Gmail push notifications and labels.",
            },
            200,
        )
    except Exception:
        logger.exception("Error in auth_callback")
        return _json_response(
            {
                "status": "error",
                "message": "Authorization failed due to an internal server error.",
            },
            500,
        )


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


@functions_framework.http
def auth_renew_watch(request: Any) -> tuple[str, int, dict[str, str]]:
    """IAM-authenticated HTTP endpoint invoked daily by Cloud Scheduler to renew Gmail watches.

    Gmail `users.watch` subscriptions expire after 7 days; Google recommends calling
    `users.watch` at least once per day for every active mailbox.
    """
    try:
        from google.oauth2.credentials import Credentials
        from googleapiclient.discovery import build

        ds = _get_datastore_client()
        project_id = os.environ["GOOGLE_CLOUD_PROJECT"]
        topic_name = os.environ.get("TOPIC_EMAIL_WATCH", "email-watch")
        topic_path = f"projects/{project_id}/topics/{topic_name}"

        renewed: list[str] = []
        failed: list[str] = []
        query = ds.query(kind="OAuthToken")
        for entity in query.fetch():
            email = entity.get("email") or entity.key.name
            token_json = entity.get("token_json")
            if not email or not token_json:
                continue
            try:
                creds = Credentials.from_authorized_user_info(json.loads(token_json))
                gmail_service = build("gmail", "v1", credentials=creds)
                watch_resp = (
                    gmail_service.users()
                    .watch(
                        userId="me",
                        body={"labelIds": ["INBOX"], "topicName": topic_path},
                    )
                    .execute()
                )
                _save_watch_state(email, watch_resp)
                renewed.append(email)
            except Exception as exc:
                if _is_auth_expired(exc):
                    logger.error(
                        "PEF_AUTH_EXPIRED: the Gmail sign-in for %s has expired or was revoked; "
                        "open the onboarding URL to sign in again.",
                        email,
                    )
                else:
                    logger.exception("PEF_WATCH_RENEWAL_FAILED: could not renew the Gmail watch for %s", email)
                failed.append(email)

        return _json_response(
            {
                "status": "ok",
                "renewedCount": len(renewed),
                "failedCount": len(failed),
            },
            200 if not failed else 207,
        )
    except Exception:
        logger.exception("PEF_WATCH_RENEWAL_FAILED: error in auth_renew_watch")
        return _json_response(
            {"status": "error", "message": "Watch renewal failed."},
            500,
        )
