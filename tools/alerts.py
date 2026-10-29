#!/usr/bin/env python3
"""Create, update or delete PEF's Cloud Monitoring alerts. deploy.sh and destroy.sh call this.

Three alert policies email ALERT_EMAIL, so nobody has to check on the pipeline by hand:

  PEF: email in the dead-letter queue    An email failed every retry and was parked in the
                                         dead-letter subscription. Metric alert on its backlog;
                                         it closes once the subscription is empty again.
  PEF: Gmail sign-in needs renewing      Google rejected the stored sign-in (expired, revoked,
                                         or the Google password changed), or the daily Gmail
                                         watch renewal failed. Without action, new email stops
                                         being scanned within 7 days.
  PEF: email could not be scanned        An email failed PEF_MAX_MESSAGE_ATTEMPTS times and was
                                         parked as `failed`, still labelled Pending.

The two log alerts match markers the functions write (PEF_AUTH_EXPIRED, PEF_WATCH_RENEWAL_FAILED,
PEF_MESSAGE_FAILED). Everything created here carries the label app=pef-gemini; `--delete`
removes exactly that. An existing email channel for the same address is reused, and then left
alone on delete.

  python tools/alerts.py --project P --email you@example.com --onboarding-url URL
  python tools/alerts.py --project P --delete [--dry-run]

Auth: the access token of your gcloud login (`gcloud auth print-access-token`). Needs the
Monitoring API (deploy.sh enables it). Alerting policies are free until at least
1 September 2027, when Google starts charging $0.35 a month per metric condition
(one here; log-match conditions have no per-condition charge).
"""

from __future__ import annotations

import argparse
import json
import ssl
import subprocess
import sys
from typing import Any, Callable
import urllib.error
import urllib.request

API = "https://monitoring.googleapis.com/v3"
APP_LABEL = "pef-gemini"
LABELS = {"app": APP_LABEL, "managed-by": "deploy-sh"}

DLQ_POLICY = "PEF: email in the dead-letter queue"
AUTH_POLICY = "PEF: Gmail sign-in needs renewing"
FAILED_POLICY = "PEF: email could not be scanned"

AUTH_MARKERS = ("PEF_AUTH_EXPIRED", "PEF_WATCH_RENEWAL_FAILED")
FAILED_MARKERS = ("PEF_MESSAGE_FAILED",)


def log_filter(markers: tuple[str, ...]) -> str:
    """Match the markers in Cloud Run function logs, written as plain text or structured JSON."""
    terms = " OR ".join(
        f'textPayload:"{m}" OR jsonPayload.message:"{m}"' for m in markers
    )
    return f'resource.type="cloud_run_revision" AND ({terms})'


def build_policies(project: str, dlq_subscription: str, onboarding_url: str, channel: str) -> list[dict[str, Any]]:
    logs_link = f"https://console.cloud.google.com/logs/query?project={project}"
    pull = (
        f"gcloud pubsub subscriptions pull {dlq_subscription} --project={project} "
        "--limit=10 --auto-ack"
    )
    common = {"combiner": "OR", "enabled": True, "notificationChannels": [channel], "userLabels": LABELS}
    return [
        {
            **common,
            "displayName": DLQ_POLICY,
            "severity": "ERROR",
            "documentation": {
                "mimeType": "text/markdown",
                "subject": "PEF: an email failed every retry",
                "content": (
                    "An event failed all its Pub/Sub retries and was moved to the dead-letter "
                    f"subscription `{dlq_subscription}`.\n\n"
                    f"1. Read (and clear) it: `{pull}`\n"
                    "2. Find the cause in the function logs for the same time: "
                    f"{logs_link}\n\n"
                    "This alert closes on its own once the subscription is empty."
                ),
            },
            "conditions": [
                {
                    "displayName": "Dead-letter subscription has undelivered messages",
                    "conditionThreshold": {
                        "filter": (
                            'resource.type = "pubsub_subscription" AND '
                            f'resource.labels.subscription_id = "{dlq_subscription}" AND '
                            'metric.type = "pubsub.googleapis.com/subscription/num_undelivered_messages"'
                        ),
                        "aggregations": [{"alignmentPeriod": "300s", "perSeriesAligner": "ALIGN_MAX"}],
                        "comparison": "COMPARISON_GT",
                        "thresholdValue": 0,
                        "duration": "0s",
                        "trigger": {"count": 1},
                    },
                }
            ],
            "alertStrategy": {"autoClose": "1800s"},
        },
        {
            **common,
            "displayName": AUTH_POLICY,
            "severity": "CRITICAL",
            "documentation": {
                "mimeType": "text/markdown",
                "subject": "PEF: sign in again so your email keeps being scanned",
                "content": (
                    "Google rejected PEF's stored Gmail sign-in (it expired, was revoked, or the "
                    "Google password changed), or the daily Gmail watch renewal failed. New email "
                    "is not being scanned, or stops within 7 days.\n\n"
                    f"1. Sign in again: {onboarding_url}\n"
                    "2. If this repeats every 7 days, your OAuth app is in Testing mode. In the "
                    "Cloud Console, open Google Auth Platform > Audience and publish the app.\n\n"
                    f"Details: {logs_link} (search for PEF_AUTH_EXPIRED or PEF_WATCH_RENEWAL_FAILED)."
                ),
            },
            "conditions": [
                {
                    "displayName": "Gmail sign-in rejected or watch renewal failed",
                    "conditionMatchedLog": {"filter": log_filter(AUTH_MARKERS)},
                }
            ],
            "alertStrategy": {"notificationRateLimit": {"period": "3600s"}, "autoClose": "1800s"},
        },
        {
            **common,
            "displayName": FAILED_POLICY,
            "severity": "WARNING",
            "documentation": {
                "mimeType": "text/markdown",
                "subject": "PEF: an email could not be scanned",
                "content": (
                    "An email failed every scan attempt and was parked as `failed`. It keeps its "
                    "Pending label in Gmail, meaning it was not scanned: treat it with care.\n\n"
                    f"The log line names the message: {logs_link} (search for PEF_MESSAGE_FAILED)."
                ),
            },
            "conditions": [
                {
                    "displayName": "Email parked after repeated failures",
                    "conditionMatchedLog": {"filter": log_filter(FAILED_MARKERS)},
                }
            ],
            "alertStrategy": {"notificationRateLimit": {"period": "3600s"}, "autoClose": "1800s"},
        },
    ]


def _tls_context() -> ssl.SSLContext:
    """Trust certifi's CA bundle when available (python.org macOS builds lack one)."""
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


class Monitoring:
    def __init__(self, project: str, token: str, opener: Callable[..., Any] | None = None) -> None:
        self.project = project
        self.token = token
        self.opener = opener or (lambda req: urllib.request.urlopen(req, timeout=30, context=_tls_context()))

    def call(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        req = urllib.request.Request(
            f"{API}/projects/{self.project}/{path}",
            method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={
                "Authorization": f"Bearer {self.token}",
                "x-goog-user-project": self.project,
                "Content-Type": "application/json",
            },
        )
        try:
            with self.opener(req) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:600]
            raise SystemExit(f"Monitoring API {method} {path} failed ({exc.code}): {detail}") from None
        return json.loads(raw) if raw else {}

    def list(self, collection: str) -> list[dict[str, Any]]:
        items, token = [], ""
        while True:
            page = self.call("GET", f"{collection}?pageSize=1000" + (f"&pageToken={token}" if token else ""))
            items += page.get(collection, [])
            token = page.get("nextPageToken", "")
            if not token:
                return items


def _relative(name: str) -> str:
    """projects/<id or number>/alertPolicies/123 -> alertPolicies/123"""
    return name.split("/", 2)[2]


def ours(item: dict[str, Any]) -> bool:
    return (item.get("userLabels") or {}).get("app") == APP_LABEL


def ensure_channel(api: Monitoring, email: str, dry_run: bool) -> str:
    for channel in api.list("notificationChannels"):
        if channel.get("type") == "email" and (channel.get("labels") or {}).get("email_address") == email:
            print(f"    Email channel for {email}: reusing {channel['name']}")
            return channel["name"]
    if dry_run:
        print(f"    Would create an email channel for {email}")
        return f"projects/{api.project}/notificationChannels/NEW"
    created = api.call(
        "POST",
        "notificationChannels",
        {"type": "email", "displayName": f"PEF alerts ({email})", "labels": {"email_address": email}, "userLabels": LABELS},
    )
    print(f"    Email channel for {email}: created {created['name']}")
    return created["name"]


def apply(api: Monitoring, policies: list[dict[str, Any]], dry_run: bool) -> None:
    existing = {p.get("displayName"): p for p in api.list("alertPolicies") if ours(p)}
    for policy in policies:
        current = existing.get(policy["displayName"])
        if dry_run:
            print(f"    Would {'update' if current else 'create'} alert: {policy['displayName']}")
        elif current:
            # No update mask: the supplied policy replaces the existing one.
            api.call("PATCH", _relative(current["name"]), policy)
            print(f"    Updated alert: {policy['displayName']}")
        else:
            api.call("POST", "alertPolicies", policy)
            print(f"    Created alert: {policy['displayName']}")


def delete(api: Monitoring, dry_run: bool) -> None:
    targets = [p for p in api.list("alertPolicies") if ours(p)]
    targets += [c for c in api.list("notificationChannels") if ours(c)]
    if not targets:
        print("      (none)")
    for item in targets:
        if dry_run:
            print(f"      {item.get('displayName')}")
        else:
            path = _relative(item["name"])
            api.call("DELETE", path + ("?force=true" if "notificationChannels/" in path else ""))
            print(f"    Deleted: {item.get('displayName')}")


def access_token() -> str:
    try:
        out = subprocess.run(["gcloud", "auth", "print-access-token"], check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"Could not get an access token from gcloud: {exc}") from None
    return out.stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--project", required=True)
    parser.add_argument("--email", help="Where the alerts go.")
    parser.add_argument("--onboarding-url", default="(see the OAuth Onboarding URL that deploy.sh prints)")
    parser.add_argument("--dlq-subscription", default="email-dlq-inspect")
    parser.add_argument("--delete", action="store_true", help="Remove the alerts and the channel this created.")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    api = Monitoring(args.project, access_token())
    if args.delete:
        delete(api, args.dry_run)
        return
    if not args.email:
        parser.error("--email is required unless --delete is given")
    channel = ensure_channel(api, args.email, args.dry_run)
    apply(api, build_policies(args.project, args.dlq_subscription, args.onboarding_url, channel), args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
