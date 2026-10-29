#!/usr/bin/env python3
"""Revoke stored Gmail access and delete PEF's Datastore records (used by destroy.sh).

Every onboarded mailbox has an `OAuthToken` entity whose `token_json` holds a Gmail
refresh token together with the OAuth client ID and secret. Deleting the Cloud
resources does not invalidate it, so for each stored token this script:

  1. stops the mailbox's Gmail push watch (users.stop),
  2. revokes the token at Google (https://oauth2.googleapis.com/revoke),
  3. deletes the pipeline's per-user Datastore records.

`EmailAuditLog` (verdicts, reasoning, token usage) is kept unless --purge-audit is
given. Run with Application Default Credentials that can read and write Datastore:

  python tools/teardown_datastore.py --project PROJECT_ID [--dry-run] [--purge-audit]
"""

from __future__ import annotations

import argparse
import json
import ssl
import sys
from typing import Any, Callable
import urllib.error
import urllib.parse
import urllib.request

REVOKE_URL = "https://oauth2.googleapis.com/revoke"
# Kinds written by the pipeline (see functions/*/main.py). Label kinds are keyed by email.
STATE_KINDS = ("OAuthToken", "OAuthState", "MailboxWatchState", "emailNotifications", "Pending", "Secured", "Unsecured")
AUDIT_KIND = "EmailAuditLog"


def _urlopen(req: urllib.request.Request, timeout: float) -> Any:
    """urlopen that trusts certifi's CA bundle when available (python.org macOS builds lack one)."""
    try:
        import certifi

        context = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        context = ssl.create_default_context()
    return urllib.request.urlopen(req, timeout=timeout, context=context)


def revoke_token(token: str, opener: Callable[..., Any] = _urlopen) -> bool:
    """Revoke a refresh or access token. Returns True if Google accepted it or it was already invalid."""
    data = urllib.parse.urlencode({"token": token}).encode()
    req = urllib.request.Request(REVOKE_URL, data=data, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with opener(req, timeout=10):
            return True
    except urllib.error.HTTPError as exc:
        # 400 invalid_token: already revoked or expired, which is the outcome we want.
        return exc.code == 400


def stop_watch(token_json: str, build: Callable[..., Any] | None = None) -> bool:
    """Stop the Gmail push watch for the mailbox that owns this token. Best effort."""
    try:
        from google.oauth2.credentials import Credentials

        if build is None:
            from googleapiclient.discovery import build as _build

            build = _build
        creds = Credentials.from_authorized_user_info(json.loads(token_json))
        build("gmail", "v1", credentials=creds, cache_discovery=False).users().stop(userId="me").execute()
        return True
    except Exception as exc:  # noqa: BLE001 - expired or revoked tokens can't stop a watch
        print(f"      could not stop Gmail watch: {type(exc).__name__}", file=sys.stderr)
        return False


def teardown(ds: Any, dry_run: bool, purge_audit: bool,
             revoke: Callable[[str], bool] = revoke_token,
             stop: Callable[[str], bool] = stop_watch) -> dict[str, int]:
    """Revoke every stored token, then delete the pipeline's records. Returns counts."""
    counts = {"tokens": 0, "revoked": 0, "watches_stopped": 0, "deleted": 0}
    for entity in ds.query(kind="OAuthToken").fetch():
        counts["tokens"] += 1
        email = entity.get("email") or entity.key.name
        print(f"    {email}: {'would revoke' if dry_run else 'revoking'} stored Gmail access")
        if dry_run:
            continue
        token_json = entity.get("token_json") or "{}"
        if stop(token_json):
            counts["watches_stopped"] += 1
        info = json.loads(token_json)
        token = info.get("refresh_token") or info.get("token")
        if token and revoke(token):
            counts["revoked"] += 1
        else:
            print(f"      WARNING: could not revoke the token for {email}; remove access at "
                  "https://myaccount.google.com/permissions", file=sys.stderr)

    kinds = STATE_KINDS + ((AUDIT_KIND,) if purge_audit else ())
    for kind in kinds:
        query = ds.query(kind=kind)
        query.keys_only()
        keys = [e.key for e in query.fetch()]
        if not keys:
            continue
        print(f"    {kind}: {'would delete' if dry_run else 'deleting'} {len(keys)} entit{'y' if len(keys) == 1 else 'ies'}")
        if not dry_run:
            for i in range(0, len(keys), 500):  # Datastore batch limit
                ds.delete_multi(keys[i:i + 500])
            counts["deleted"] += len(keys)
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--project", required=True)
    parser.add_argument("--dry-run", action="store_true", help="List what would happen; change nothing.")
    parser.add_argument("--purge-audit", action="store_true", help=f"Also delete {AUDIT_KIND} (verdict history).")
    args = parser.parse_args()

    try:
        from google.cloud import datastore
    except ImportError:
        sys.exit("google-cloud-datastore is not installed: run `pip install -r requirements.txt` first.")

    ds = datastore.Client(project=args.project)
    counts = teardown(ds, args.dry_run, args.purge_audit)
    if not args.dry_run:
        print(f"    Revoked {counts['revoked']}/{counts['tokens']} stored tokens, stopped "
              f"{counts['watches_stopped']} Gmail watches, deleted {counts['deleted']} entities.")
    if counts["tokens"] and counts["revoked"] < counts["tokens"] and not args.dry_run:
        sys.exit(1)


if __name__ == "__main__":
    main()
