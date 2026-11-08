#!/usr/bin/env python3
"""Live check that the Safe Browsing v5 reputation lookup works with your key.

Runs the same code path as the deployed `email_analyze` function (`check_reputation`)
against Google's Safe Browsing test pages, which are always listed, plus a clean URL.

    python tools/check_safe_browsing.py          # add --raw to see the API's raw response

The key is read from SAFE_BROWSING_API_KEY, then from .env, then (when the key lives in
Secret Manager) from the SAFE_BROWSING_API_KEY secret in GOOGLE_CLOUD_PROJECT via gcloud.
The key is never printed. Exits 0 when the lookup works and finds the test threats.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import functions.email_analyze.main as analyze_main  # noqa: E402

PHISHING_TEST_URL = "http://testsafebrowsing.appspot.com/s/phishing.html"
MALWARE_TEST_URL = "http://testsafebrowsing.appspot.com/s/malware.html"
CLEAN_URL = "https://www.google.com/"
CLEAN_DOMAIN = "google.com"


def _dotenv_value(name: str) -> str:
    env_file = ROOT_DIR / ".env"
    if not env_file.exists():
        return ""
    for line in env_file.read_text().splitlines():
        if line.strip().startswith(f"{name}="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return ""


def _load_key() -> tuple[str, str]:
    key = os.environ.get("SAFE_BROWSING_API_KEY", "")
    if key and not key.startswith("your-"):
        return key, "environment"
    key = _dotenv_value("SAFE_BROWSING_API_KEY")
    if key and not key.startswith("your-"):
        return key, ".env"
    project = os.environ.get("GOOGLE_CLOUD_PROJECT") or _dotenv_value("GOOGLE_CLOUD_PROJECT")
    if project:
        try:
            out = subprocess.run(
                ["gcloud", "secrets", "versions", "access", "latest",
                 "--secret=SAFE_BROWSING_API_KEY", f"--project={project}", "--quiet"],
                capture_output=True, text=True, timeout=30, check=True,
            )
            if out.stdout.strip():
                return out.stdout.strip(), f"Secret Manager ({project})"
        except (OSError, subprocess.SubprocessError):
            pass
    return "", ""


def _print_raw_response(key: str) -> None:
    """Show what the API returned for the phishing test page (the key is not printed)."""
    import urllib.parse
    import urllib.request

    query = urllib.parse.urlencode([("key", key), ("urls", PHISHING_TEST_URL)])
    req = urllib.request.Request(
        f"{analyze_main.SAFE_BROWSING_ENDPOINT}?{query}",
        headers={"User-Agent": analyze_main.SAFE_BROWSING_USER_AGENT},
    )
    try:
        with urllib.request.urlopen(req, timeout=10, context=analyze_main._tls_context()) as resp:
            raw = resp.read()
            print(f"Raw response: HTTP {resp.status}, {resp.headers.get('Content-Type')}, {len(raw)} bytes")
    except Exception as exc:  # noqa: BLE001 - diagnostics only
        print(f"Raw response: request failed: {exc}")
        return
    print(f"  hex: {raw[:200].hex()}")
    try:
        print(f"  parsed: {analyze_main._parse_search_urls_response(raw)}")
    except Exception as exc:  # noqa: BLE001
        print(f"  parse error: {exc}")


def main() -> int:
    key, source = _load_key()
    if not key:
        print("No Safe Browsing API key found (environment, .env or Secret Manager).")
        print("Set SAFE_BROWSING_API_KEY or run ./setup.sh first.")
        return 1
    os.environ["SAFE_BROWSING_API_KEY"] = key
    os.environ["SAFE_BROWSING_FAIL_CLOSED"] = "true"  # surface errors instead of hiding them
    print(f"Key from {source}. Endpoint: {analyze_main.SAFE_BROWSING_ENDPOINT}")

    try:
        matched, status = analyze_main._query_safe_browsing_matches(
            [CLEAN_DOMAIN, PHISHING_TEST_URL, MALWARE_TEST_URL, CLEAN_URL]
        )
        rep = analyze_main.check_reputation(
            CLEAN_DOMAIN, [PHISHING_TEST_URL, MALWARE_TEST_URL, CLEAN_URL]
        )
    except analyze_main.SafeBrowsingUnavailableError as exc:
        print(f"FAIL: lookup failed (network, server or response error): {exc.__cause__ or exc}")
        _print_raw_response(key)
        return 1

    for url in (CLEAN_DOMAIN, PHISHING_TEST_URL, MALWARE_TEST_URL, CLEAN_URL):
        types = ", ".join(sorted(matched.get(url, set()))) or "no match"
        print(f"  {url:55} {types}")
    print(f"status={rep.status} domain_hit={rep.domain_hit} links_hit={rep.links_hit} "
          f"threat_types={rep.threat_types}")

    problems = []
    if rep.status != analyze_main.REPUTATION_OK:
        problems.append(f"status is {rep.status!r}, expected 'ok' (check the key and that the "
                        "Safe Browsing API is enabled)")
    if "SOCIAL_ENGINEERING" not in matched.get(PHISHING_TEST_URL, set()):
        problems.append("the phishing test page was not reported as SOCIAL_ENGINEERING")
    if "MALWARE" not in matched.get(MALWARE_TEST_URL, set()):
        print("NOTE: the malware test page was not reported as MALWARE (not required).")
    if rep.domain_hit or CLEAN_URL in matched:
        problems.append("a clean URL or domain was reported as a threat")
    for problem in problems:
        print(f"FAIL: {problem}")
    if problems or "--raw" in sys.argv:
        _print_raw_response(key)
    if not problems:
        print("PASS: Safe Browsing v5 lookup works.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
