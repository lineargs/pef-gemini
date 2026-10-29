#!/usr/bin/env python3
"""CLI simulator for the PEF v2 pipeline.

Allows running sample or custom emails through the 3-stage pipeline:
  1. Local Live Gemini Mode (--mode local): Calls Gemini 3.8 Flash directly (escalating borderline emails to
     GEMINI_ESCALATION_MODEL when set) & runs the full pipeline in-process.
  2. Offline Heuristic Stub (--mode offline): Deterministic CI fallback when running without network access or credentials.
  3. Cloud Pub/Sub Mode (--mode pubsub): Publishes test emails to the `email-watch` topic on GCP.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import sys
import time
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from functions.email_analyze.main import (  # noqa: E402
    PhishingAnalysisResult,
    PhishingPropositions,
    analyze_with_gemini_detailed,
    check_safe_browsing_batch,
    compute_composite_score,
)
from functions.email_ingest.main import build_analysis_payload  # noqa: E402
from functions.email_outcome.main import determine_verdict_label  # noqa: E402

SAMPLE_EMAILS_PATH = Path(__file__).resolve().parent / "sample_emails.json"

ANSI_GREEN = "\033[92m"
ANSI_RED = "\033[91m"
ANSI_YELLOW = "\033[93m"
ANSI_CYAN = "\033[96m"
ANSI_BOLD = "\033[1m"
ANSI_RESET = "\033[0m"


def _offline_heuristic_analysis(payload: dict[str, Any]) -> PhishingAnalysisResult:
    """Deterministic keyword stub for offline CI smoke tests and runs without credentials.

    NOTE: This function is a deterministic stub for verifying pipeline routing and
    scoring math offline. Use `--mode local` to invoke live `gemini-3.8-flash`.
    """
    text = f"{payload.get('subject', '')}\n{payload.get('body', '')}\n{payload.get('attachmentContent') or ''}".lower()
    sender = payload.get("senderEmailAddress", "").lower()
    urls = payload.get("urls", [])

    urgency = any(
        w in text
        for w in (
            "urgent",
            "within 2 hours",
            "within 24 hours",
            "valid 12 hours",
            "immediate",
            "suspended",
            "temporarily restricted",
        )
    )
    authority = any(
        w in text or w in sender
        for w in (
            "microsoft",
            "security",
            "chief executive",
            "ceo",
            "dhl",
            "customs",
            "hr rewards",
            "paypal",
            "american express",
        )
    )
    suspicious_urls = any(
        any(
            bad in u.lower()
            for bad in (
                "m1crosoft",
                "verify",
                "-uk.info",
                "session=",
                "dghjdgf.com",
                "printakid.com",
                "webscrcmd=",
            )
        )
        for u in urls
    )
    unsolicited = any(
        w in text
        for w in (
            "unauthorized login",
            "unpaid customs",
            "randomly selected",
            "confidential wire",
            "unusual activity",
            "selected to receive",
        )
    )
    deals = any(
        w in text
        for w in (
            "$5,000",
            "loyalty grant",
            "congratulations",
            "winner!!",
            "£900",
            "prize reward",
        )
    )
    fin_req = any(
        w in text
        for w in (
            "verify your credentials",
            "verify your account",
            "verify your identity",
            "wire transfer",
            "routing number",
            "one-time passcode",
            "credit card payment",
            "sort code",
        )
    )

    triggered = sum(
        [urgency, authority, suspicious_urls, unsolicited, deals, fin_req]
    )
    is_phish = triggered >= 2

    domain_score = 0.98 if is_phish else 0.02
    body_score = 0.99 if is_phish else 0.03
    links_score = (0.98 if is_phish else 0.04) if payload.get("links") else 0.0
    att_score = (0.97 if is_phish else 0.02) if payload.get("attachment") else 0.0

    active_props = [
        name
        for name, val in [
            ("urgency", urgency),
            ("authority", authority),
            ("suspicious_long_urls", suspicious_urls),
            ("unsolicited_context", unsolicited),
            ("incredible_deals", deals),
            ("personal_or_financial_request", fin_req),
        ]
        if val
    ]
    reasoning = (
        f"[Offline Stub] Flagged phishing indicators: {', '.join(active_props)}."
        if is_phish
        else "[Offline Stub] No phishing heuristics triggered; structure appears benign."
    )

    return PhishingAnalysisResult(
        domain_phishing_score=domain_score,
        links_phishing_score=links_score,
        body_phishing_score=body_score,
        attachment_phishing_score=att_score,
        overall_confidence=0.98 if is_phish else 0.03,
        is_phishing=is_phish,
        propositions=PhishingPropositions(
            urgency=urgency,
            authority=authority,
            suspicious_long_urls=suspicious_urls,
            unsolicited_context=unsolicited,
            incredible_deals=deals,
            personal_or_financial_request=fin_req,
        ),
        reasoning=reasoning,
    )


def format_badge(label: str) -> str:
    if label == "Pending":
        return f"{ANSI_YELLOW}{ANSI_BOLD}[Pending]{ANSI_RESET}"
    if label == "Secured":
        return f"{ANSI_GREEN}{ANSI_BOLD}[Secured]{ANSI_RESET}"
    return f"{ANSI_RED}{ANSI_BOLD}[Unsecured]{ANSI_RESET}"


def run_single_email(raw_email: dict[str, Any], mode: str) -> dict[str, Any]:
    """Execute the 3-stage pipeline on a single email and print live stage transitions."""
    t0 = time.perf_counter()

    # Stage 1: Ingestion
    ingested = build_analysis_payload({**raw_email, "simulated": True})
    print(f"\n{ANSI_CYAN}{'━' * 78}{ANSI_RESET}")
    print(
        f"{ANSI_BOLD}Email ID:{ANSI_RESET} {ingested['messageID']}  |  "
        f"Initial Gmail Label: {format_badge('Pending')}"
    )
    print(
        f"{ANSI_BOLD}From:{ANSI_RESET}     {ingested['senderEmailAddress']} ({ingested['senderDomain']})"
    )
    print(f"{ANSI_BOLD}Subject:{ANSI_RESET}  {ingested['subject']}")

    if mode == "pubsub":
        from google.cloud import pubsub_v1
        import os

        project_id = os.environ["GOOGLE_CLOUD_PROJECT"]
        topic_name = os.environ.get("TOPIC_EMAIL_WATCH", "email-watch")
        publisher = pubsub_v1.PublisherClient()
        topic_path = publisher.topic_path(project_id, topic_name)
        msg_id = publisher.publish(
            topic_path, json.dumps({**raw_email, "simulated": True}).encode("utf-8")
        ).result(timeout=10)
        print(f"Published to GCP Pub/Sub `{topic_path}` (message_id={msg_id})")
        return {"messageID": ingested["messageID"], "pubsubMessageId": msg_id}

    # Stage 2: Gemini 3.8 Flash (+ escalation) + Safe Browsing Analysis
    models_used = ["offline-stub"]
    if mode == "local":
        run = analyze_with_gemini_detailed(ingested)
        analysis = run.result
        models_used = [
            f"{c['model']} (failed: {c['error']})" if c.get("error") else c["model"] for c in run.calls
        ]
        domain_sb, links_sb = check_safe_browsing_batch(
            ingested["senderDomain"], ingested["urls"]
        )
    else:
        analysis = _offline_heuristic_analysis(ingested)
        domain_sb = False
        links_sb = False

    outcome = compute_composite_score(
        payload=ingested,
        analysis=analysis,
        domain_sb_malicious=domain_sb,
        links_sb_malicious=links_sb,
    )

    # Stage 3: Outcome Evaluation
    verdict = determine_verdict_label(
        total_score=outcome["total"],
        maximum_score=outcome["maxScore"],
        gemini_is_phishing=analysis.is_phishing,
        gemini_confidence=analysis.overall_confidence,
        domain_sb_malicious=domain_sb,
        links_sb_malicious=links_sb,
        max_component_score=outcome["maxComponentScore"],
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000

    props = analysis.propositions.model_dump()
    active_props = [k for k, v in props.items() if v]

    print(
        f"{ANSI_BOLD}Category:{ANSI_RESET} {outcome['category']} "
        f"(Links={outcome['links']}, Attachment={outcome['attachment']})"
    )
    print(
        f"{ANSI_BOLD}Scores:{ANSI_RESET}   "
        f"Domain={analysis.domain_phishing_score:.2f} | "
        f"Links={analysis.links_phishing_score:.2f} | "
        f"Body={analysis.body_phishing_score:.2f} | "
        f"Attachment={analysis.attachment_phishing_score:.2f}"
    )
    if mode == "local":
        print(f"{ANSI_BOLD}Models:{ANSI_RESET}   {' -> '.join(models_used)}")
    print(
        f"{ANSI_BOLD}Phishing probability:{ANSI_RESET} {analysis.overall_confidence:.2f}  "
        f"(is_phishing={analysis.is_phishing}; 0.20 to 0.88 escalates)"
    )
    print(
        f"{ANSI_BOLD}Propositions Triggered:{ANSI_RESET} "
        f"{', '.join(active_props) if active_props else 'None'}"
    )
    print(
        f"{ANSI_BOLD}Total Score:{ANSI_RESET} {outcome['total']:.2f} / {outcome['maxScore']} "
        f"(Thesis Threshold: {outcome['threshold']:.2f})  |  "
        f"Latency: {elapsed_ms:.0f} ms"
    )
    print(
        f"{ANSI_BOLD}Final Gmail Label:{ANSI_RESET} {format_badge(verdict)}  "
        f"(Expected: {raw_email.get('expectedVerdict', 'N/A')})"
    )
    reasoning_label = (
        "Gemini Reasoning:" if mode == "local" else "Stub Reasoning:  "
    )
    print(f"{ANSI_BOLD}{reasoning_label}{ANSI_RESET}  {analysis.reasoning}")

    return {
        "messageID": ingested["messageID"],
        "verdict": verdict,
        "expected": raw_email.get("expectedVerdict"),
        "total": outcome["total"],
        "threshold": outcome["threshold"],
        "maxScore": outcome["maxScore"],
        "latencyMs": round(elapsed_ms, 1),
    }


def main() -> None:
    # Keep per-request HTTP log lines out of the demo output.
    for noisy in ("httpx", "google_genai", "google_genai.models"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    parser = argparse.ArgumentParser(
        description="PEF v2 pipeline simulator (Cloud Run Functions + Pub/Sub + Gemini 3.8 Flash)"
    )
    parser.add_argument(
        "--mode",
        choices=["local", "offline", "pubsub"],
        default="local",
        help="Execution mode: 'local' calls Gemini 3.8 Flash directly, 'offline' uses deterministic keyword stub, 'pubsub' publishes to GCP Pub/Sub.",
    )
    parser.add_argument(
        "--email-id",
        help="Optional specific email ID from sample_emails.json to run (e.g. msg-phish-002).",
    )
    args = parser.parse_args()

    emails: list[dict[str, Any]] = json.loads(
        SAMPLE_EMAILS_PATH.read_text(encoding="utf-8")
    )
    if args.email_id:
        emails = [e for e in emails if e["id"] == args.email_id]
        if not emails:
            sys.exit(
                f"Email ID '{args.email_id}' not found in {SAMPLE_EMAILS_PATH}"
            )

    mode_banner = (
        "LIVE GEMINI 3.8 FLASH"
        if args.mode == "local"
        else (
            "OFFLINE HEURISTIC STUB (CI Smoke Test)"
            if args.mode == "offline"
            else "CLOUD PUB/SUB INJECTION"
        )
    )
    print(
        f"{ANSI_BOLD}PEF v2 Pipeline Simulator — Mode: {mode_banner} "
        f"({len(emails)} email(s)){ANSI_RESET}"
    )

    results = [run_single_email(email, mode=args.mode) for email in emails]
    if args.mode in ("local", "offline"):
        matches = sum(1 for r in results if r["verdict"] == r["expected"])
        print(f"\n{ANSI_CYAN}{'━' * 78}{ANSI_RESET}")
        print(
            f"{ANSI_BOLD}Summary ({args.mode.upper()}):{ANSI_RESET} {matches}/{len(results)} verdicts matched expected outcome."
        )


if __name__ == "__main__":
    main()
