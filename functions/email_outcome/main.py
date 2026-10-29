"""Stage 3: Verdict Evaluation, Gmail Label Swap, & Audit Logging.

Triggered by Pub/Sub topic `email-outcome`.
Fixes the 2021 `if (total)` zero-score bug and O(N) Datastore scan, swaps the
`Pending` label for `Secured` or `Unsecured`, and records the full Gemini
explainability audit trail in Datastore and Google Sheets.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
from typing import Any

try:
    import functions_framework
except ImportError:

    class _FFStub:
        @staticmethod
        def cloud_event(fn: Any) -> Any:
            return fn

    functions_framework = _FFStub()  # type: ignore[assignment]

logging.basicConfig(level=logging.INFO)  # local runs; a no-op once the framework has set up logging
logger = logging.getLogger(__name__)
# On Cloud Run, functions-framework configures the root logger at WARNING before this
# module loads, so basicConfig above does nothing there. Set this logger's own level so
# INFO lines ("Analyzed message …", "Verdict for message …") reach Cloud Logging.
logger.setLevel(logging.INFO)

# 2021 MSc Thesis additive thresholds (k active AI checks * 0.95)
THRESHOLDS_BY_MAX_SCORE: dict[int, float] = {
    6: 3.80,  # Attachment and links (4 AI checks * 0.95)
    5: 2.85,  # Links, but no attachment (3 AI checks * 0.95)
    4: 2.85,  # Attachment, but no links (3 AI checks * 0.95)
    3: 1.90,  # No attachment and no links (2 AI checks * 0.95)
}

# Heuristic LLM cut-offs. These are hand-picked starting values, NOT calibrated:
# Gemini's self-reported scores are not probabilities. Tune them on a labelled set
# with `tools/evaluate.py --sweep` and override via environment variables.
DEFAULT_CONFIDENCE_CUTOFF = 0.85
DEFAULT_COMPONENT_CUTOFF = 0.90


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        logger.warning("Invalid %s; using default %.2f", name, default)
        return default


def confidence_cutoff() -> float:
    return _env_float("PEF_CONFIDENCE_CUTOFF", DEFAULT_CONFIDENCE_CUTOFF)


def component_cutoff() -> float:
    return _env_float("PEF_COMPONENT_CUTOFF", DEFAULT_COMPONENT_CUTOFF)

FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_ds_client: Any | None = None


def _get_datastore_client() -> Any:
    global _ds_client
    if _ds_client is None:
        from google.cloud import datastore

        project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
        _ds_client = datastore.Client(project=project_id)
    return _ds_client


def determine_verdict_label(
    total_score: float,
    maximum_score: int,
    gemini_is_phishing: bool = False,
    gemini_confidence: float = 0.0,
    domain_sb_malicious: bool = False,
    links_sb_malicious: bool = False,
    max_component_score: float = 0.0,
    confidence_threshold: float | None = None,
    component_threshold: float | None = None,
) -> str:
    """Return 'Unsecured' or 'Secured' combining:

    1. Deterministic known-threat override (Safe Browsing / Web Risk hit)
    2. 2021 MSc Thesis multi-factor threshold (`total_score >= k * 0.95`)
    3. Heuristic LLM semantic & single-vector cut-off (`gemini_is_phishing` with
       `gemini_confidence >= PEF_CONFIDENCE_CUTOFF` (0.85) or
       `max_component_score >= PEF_COMPONENT_CUTOFF` (0.90)), preventing a benign
       cover component (e.g. freemail domain or clean body text accompanying a
       malicious attachment) from diluting a high-confidence threat vector.
    """
    if domain_sb_malicious or links_sb_malicious:
        return "Unsecured"
    threshold = THRESHOLDS_BY_MAX_SCORE.get(maximum_score, 1.90)
    if total_score >= threshold:
        return "Unsecured"
    conf_cut = confidence_cutoff() if confidence_threshold is None else confidence_threshold
    comp_cut = component_cutoff() if component_threshold is None else component_threshold
    if gemini_is_phishing and (
        gemini_confidence >= conf_cut or max_component_score >= comp_cut
    ):
        return "Unsecured"
    return "Secured"


def _sanitize_sheet_cell(value: Any) -> Any:
    """Prevent spreadsheet formula injection in untrusted or LLM-generated strings."""
    if isinstance(value, str) and value.startswith(FORMULA_PREFIXES):
        return f"'{value}"
    return value


def _get_label_id(ds: Any, label_name: str, email: str) -> str | None:
    """Direct O(1) Datastore key lookup for a user's Gmail label ID."""
    entity = ds.get(ds.key(label_name, email))
    return entity.get("labelId") if entity else None


def _load_user_credentials(ds: Any, email: str) -> Any:
    from google.oauth2.credentials import Credentials

    entity = ds.get(ds.key("OAuthToken", email))
    if not entity or "token_json" not in entity:
        raise ValueError(f"No stored OAuth credentials found for {email}")
    return Credentials.from_authorized_user_info(json.loads(entity["token_json"]))


VERDICT_LABELS = ("Secured", "Unsecured")
SHEET_CLAIM_SECONDS = 120


class SheetRowLeaseHeldError(RuntimeError):
    """Another delivery is appending this message's Sheets row; retry later."""


def _is_not_found(exc: Exception) -> bool:
    status = getattr(getattr(exc, "resp", None), "status", None)
    return str(status) == "404"


def _apply_gmail_verdict_label(
    gmail_service: Any,
    ds: Any,
    message_id: str,
    email: str,
    verdict_label: str,
) -> None:
    """Apply the verdict label and remove Pending and the opposite verdict label.

    Removing the opposite label keeps the mailbox consistent even if a duplicate
    analysis ever reached this stage with a different verdict.
    """
    target_label_id = _get_label_id(ds, verdict_label, email)
    remove_ids = [
        label_id
        for label_id in (
            _get_label_id(ds, name, email)
            for name in ("Pending", *VERDICT_LABELS)
            if name != verdict_label
        )
        if label_id
    ]

    body: dict[str, list[str]] = {}
    if target_label_id:
        body["addLabelIds"] = [target_label_id]
    if remove_ids:
        body["removeLabelIds"] = remove_ids

    if not body:
        return
    try:
        gmail_service.users().messages().modify(
            userId="me",
            id=message_id,
            body=body,
        ).execute()
    except Exception as exc:
        if not _is_not_found(exc):
            raise
        logger.info("Message %s no longer exists; nothing to label.", message_id)


def _record_datastore_audit(
    ds: Any,
    outcome_event: dict[str, Any],
    verdict: str,
) -> Any:
    """Persist the explainability audit record, first writer wins.

    Pub/Sub is at-least-once and Gemini is not deterministic, so a duplicate
    analysis could disagree with the first. The first recorded verdict is kept and
    returned, so the Gmail label, the audit entity and the Sheets row always agree.
    """
    from google.cloud import datastore

    message_id = outcome_event.get("messageID") or f"unknown-{int(time.time())}"
    key = ds.key("EmailAuditLog", message_id)
    with ds.transaction():
        existing = ds.get(key)
        if existing is not None and existing.get("verdict"):
            if existing["verdict"] != verdict:
                logger.warning(
                    "Duplicate outcome for %s disagrees (%s vs recorded %s); keeping "
                    "the recorded verdict.",
                    message_id,
                    verdict,
                    existing["verdict"],
                )
            return existing

        entity = datastore.Entity(
            key=key, exclude_from_indexes=("reasoning", "geminiAnalysisJson")
        )
        gemini_data = outcome_event.get("geminiAnalysis", {})
        usage = outcome_event.get("geminiUsage") or {}
        entity.update(
            {
                "messageID": message_id,
                "emailAddress": outcome_event.get("emailAddress", ""),
                "senderEmailAddress": outcome_event.get("senderEmailAddress", ""),
                "subject": outcome_event.get("subject", ""),
                "category": outcome_event.get("category", ""),
                "total": float(outcome_event.get("total", 0.0)),
                "maxScore": int(outcome_event.get("maxScore", 3)),
                "threshold": float(outcome_event.get("threshold", 1.90)),
                "verdict": verdict,
                "domainSafeBrowsingHit": bool(
                    outcome_event.get("domainSafeBrowsingHit", False)
                ),
                "linksSafeBrowsingHit": bool(
                    outcome_event.get("linksSafeBrowsingHit", False)
                ),
                "reputationStatus": outcome_event.get("reputationStatus", ""),
                "geminiModels": ",".join(outcome_event.get("geminiModels") or []),
                "geminiBlocked": outcome_event.get("geminiBlocked") or "",
                "geminiEscalationError": outcome_event.get("geminiEscalationError") or "",
                "promptTokens": int(usage.get("promptTokens", 0)),
                "outputTokens": int(usage.get("outputTokens", 0)),
                "thinkingTokens": int(usage.get("thinkingTokens", 0)),
                "reasoning": gemini_data.get("reasoning", ""),
                "geminiAnalysisJson": json.dumps(gemini_data),
                "recordedAt": int(time.time()),
                "sheetAppended": False,
                "sheetClaimUntil": 0,
            }
        )
        ds.put(entity)
        return entity


def _claim_sheet_row(ds: Any, message_id: str, now: int | None = None) -> bool:
    """Atomically claim the right to append this message's Sheets row.

    Returns False if the row was already appended. Raises SheetRowLeaseHeldError if
    another delivery holds an unexpired claim, so Pub/Sub retries and the row is still
    written if that delivery crashed.
    """
    now = int(time.time()) if now is None else now
    key = ds.key("EmailAuditLog", message_id)
    with ds.transaction():
        entity = ds.get(key)
        if entity is None or entity.get("sheetAppended"):
            return False
        if int(entity.get("sheetClaimUntil", 0)) > now:
            raise SheetRowLeaseHeldError(f"Sheets row for {message_id} is being appended")
        entity["sheetClaimUntil"] = now + SHEET_CLAIM_SECONDS
        ds.put(entity)
        return True


def _mark_sheet_appended(ds: Any, message_id: str) -> None:
    key = ds.key("EmailAuditLog", message_id)
    with ds.transaction():
        entity = ds.get(key)
        if entity is not None:
            entity["sheetAppended"] = True
            ds.put(entity)


def _model_cell(models: str, escalation_error: str = "") -> str:
    """Describe which model produced the verdict, e.g. 'gemini-3.8-flash → gemini-4-argon'.

    `models` is the audit log's comma-separated list of models whose result was produced;
    the last one decided. A failed escalation is shown so the row explains why the
    first-pass model decided a borderline email.
    """
    cell = " → ".join(m for m in models.split(",") if m)
    if escalation_error:
        cell += f" (escalation failed: {escalation_error})"
    return cell


# Sheet columns, in order. Add them as a header row in Sheet1!A1:H1.
# "Phishing probability" is the deciding model's overall_confidence (0 to 1); emails whose
# first pass fell between 0.20 and 0.88 were escalated.
SHEET_COLUMNS = (
    "Message ID", "Category", "Score", "Verdict", "Model", "Phishing probability", "Signals", "Reasoning",
)


def _append_to_google_sheet(
    creds: Any,
    message_id: str,
    category: str,
    total_score: float,
    verdict: str,
    reasoning: str,
    propositions: dict[str, bool] | None = None,
    model: str = "",
    phishing_probability: float | None = None,
) -> None:
    from googleapiclient.discovery import build

    sheet_id = os.environ.get("GOOGLE_SHEET_ID", "")
    if not sheet_id or sheet_id == "your-google-sheet-id":
        return

    active_props = (
        ", ".join(k for k, v in propositions.items() if v)
        if propositions
        else "None"
    )
    row = [
        _sanitize_sheet_cell(message_id),
        _sanitize_sheet_cell(category),
        float(total_score),
        _sanitize_sheet_cell(verdict),
        _sanitize_sheet_cell(model),
        round(float(phishing_probability), 2) if phishing_probability is not None else "",
        _sanitize_sheet_cell(active_props),
        _sanitize_sheet_cell(reasoning),
    ]

    sheets_service = build("sheets", "v4", credentials=creds)
    sheets_service.spreadsheets().values().append(
        spreadsheetId=sheet_id,
        range="Sheet1!A1:H1",
        valueInputOption="RAW",
        body={
            "majorDimension": "ROWS",
            "values": [row],
        },
    ).execute()


@functions_framework.cloud_event
def email_outcome(cloud_event: Any) -> None:
    """Cloud Run Function entry point triggered by `email-outcome` Pub/Sub topic."""
    pubsub_data = base64.b64decode(cloud_event.data["message"]["data"]).decode("utf-8")
    outcome_event = json.loads(pubsub_data)

    message_id = outcome_event.get("messageID", "")
    email = outcome_event.get("emailAddress", "")
    total = outcome_event.get("total")
    if total is None:
        logger.warning("Missing `total` score in outcome event for %s", message_id)
        return

    max_score = int(outcome_event.get("maxScore", 3))
    category = outcome_event.get("category", "No attachment and no links")
    gemini_data = outcome_event.get("geminiAnalysis", {})
    reasoning = gemini_data.get("reasoning", "")
    propositions = gemini_data.get("propositions", {})
    domain_sb = bool(outcome_event.get("domainSafeBrowsingHit", False))
    links_sb = bool(outcome_event.get("linksSafeBrowsingHit", False))
    max_comp = float(outcome_event.get("maxComponentScore", 0.0))

    verdict = determine_verdict_label(
        total_score=float(total),
        maximum_score=max_score,
        gemini_is_phishing=bool(gemini_data.get("is_phishing", False)),
        gemini_confidence=float(gemini_data.get("overall_confidence", 0.0)),
        domain_sb_malicious=domain_sb,
        links_sb_malicious=links_sb,
        max_component_score=max_comp,
    )

    reputation_status = outcome_event.get("reputationStatus", "")
    if reputation_status in ("disabled", "unavailable", "error"):
        logger.warning(
            "Message %s was scored WITHOUT a reputation check (status=%s).",
            message_id,
            reputation_status,
        )

    active_props = [k for k, v in propositions.items() if v]
    log_reasoning = (
        os.environ.get("LOG_FULL_REASONING", "false").lower() == "true"
    )
    logger.info(
        "Verdict for message %s (%s): %s [total=%.2f / %d, sb_hit=%s, props=%s]%s",
        message_id,
        category,
        verdict,
        float(total),
        max_score,
        domain_sb or links_sb,
        ",".join(active_props) or "none",
        f" — {reasoning}" if log_reasoning else "",
    )

    if outcome_event.get("simulated"):
        return

    from googleapiclient.discovery import build

    ds = _get_datastore_client()
    audit = _record_datastore_audit(ds, outcome_event, verdict)
    final_verdict = audit["verdict"]

    creds = _load_user_credentials(ds, email)
    gmail_service = build("gmail", "v1", credentials=creds)

    # Label swap is idempotent (same add/remove sets), so a retry is safe.
    _apply_gmail_verdict_label(gmail_service, ds, message_id, email, final_verdict)

    if _claim_sheet_row(ds, audit.key.name):
        recorded = json.loads(audit.get("geminiAnalysisJson") or "{}")
        _append_to_google_sheet(
            creds,
            audit.key.name,
            audit.get("category", category),
            float(audit.get("total", total)),
            final_verdict,
            audit.get("reasoning", reasoning),
            propositions=recorded.get("propositions", propositions),
            model=_model_cell(audit.get("geminiModels") or "", audit.get("geminiEscalationError") or ""),
            phishing_probability=recorded.get("overall_confidence"),
        )
        _mark_sheet_appended(ds, audit.key.name)
