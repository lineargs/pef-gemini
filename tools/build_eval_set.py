#!/usr/bin/env python3
"""Build a labelled evaluation set from public phishing and legitimate-email corpora.

Reads two CSV files from the "Phishing Email Curated Datasets" (Champa, Rabbi and
Zibran, 2024; https://zenodo.org/records/8339691, CC BY 4.0), which you download
yourself into evals/data/ (git-ignored):

  Nazario.csv        phishing emails collected by Jose Nazario (label 1)
  SpamAssasin.csv    the SpamAssassin public corpus; only its legitimate emails
                     (label 0) are used, because its spam is not phishing

and writes a balanced, reproducible sample in the format of tools/sample_emails.json:

  python tools/build_eval_set.py                       # 200 phishing + 200 legitimate
  python tools/build_eval_set.py --per-class 50        # a cheaper first run
  python tools/evaluate.py --mode local --dataset evals/data/eval_set.json --sweep --workers 8

Each class is split evenly between emails with and without a URL in the body (as the
pipeline's own URL extraction sees them), so a model can't score well just by
noticing links. The sample is fixed by --seed. The receiver address is dropped, the
source CSV and row are kept for traceability, and a manifest records the source
files' SHA-256, the seed and the counts.

Caveats to state with any result: the phishing emails date from 2015 to 2022 and the
legitimate ones from 2002, so neither is today's mail; both corpora are public and may
be in a model's training data; the curated CSVs carry no attachments, so only the two
"no attachment" categories are covered; and many Nazario bodies lost their link URLs
during curation ("click HERE" with no address), so those count as emails without links.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import random
import re
import statistics
import sys
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from functions.email_ingest.main import extract_urls  # noqa: E402

DATA_DIR = ROOT_DIR / "evals" / "data"
SOURCE_URL = "https://zenodo.org/records/8339691"
CITATION = "Champa, Rabbi and Zibran (2024), Phishing Email Curated Datasets, Zenodo, CC BY 4.0"
MIN_BODY_CHARS = 40
# mbox bookkeeping messages that are not emails at all
ARTEFACT_MARKERS = ("internal format of your mail folder",)


def find_file(explicit: Path | None, *names: str) -> Path:
    if explicit:
        return explicit
    for name in names:
        candidate = DATA_DIR / name
        if candidate.exists():
            return candidate
    sys.exit(
        f"Could not find {' or '.join(names)} in {DATA_DIR}.\n"
        f"Download it from {SOURCE_URL} and save it there, or pass the path explicitly."
    )


def read_rows(path: Path) -> list[dict[str, str]]:
    csv.field_size_limit(sys.maxsize)
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        missing = {"sender", "subject", "body", "label"} - set(reader.fieldnames or [])
        if missing:
            sys.exit(f"{path.name} is missing columns {sorted(missing)}; is it from {SOURCE_URL}?")
        return [{**row, "_row": str(i)} for i, row in enumerate(reader, start=2)]  # line 1 is the header


def clean(rows: list[dict[str, str]], label: str) -> tuple[list[dict[str, str]], dict[str, int]]:
    """Keep rows with the wanted label, a real body, no mbox artefacts and no duplicates."""
    kept, seen = [], set()
    dropped = {"other_label": 0, "short_body": 0, "artefact": 0, "duplicate": 0}
    for row in rows:
        body = (row.get("body") or "").strip()
        if (row.get("label") or "").strip() != label:
            dropped["other_label"] += 1
        elif len(body) < MIN_BODY_CHARS:
            dropped["short_body"] += 1
        elif any(marker in body.lower() for marker in ARTEFACT_MARKERS):
            dropped["artefact"] += 1
        else:
            key = ((row.get("subject") or "").strip().lower(), re.sub(r"\s+", " ", body)[:500])
            if key in seen:
                dropped["duplicate"] += 1
                continue
            seen.add(key)
            kept.append(row)
    return kept, dropped


def stratified_sample(rows: list[dict[str, str]], n: int, rng: random.Random) -> tuple[list[dict[str, str]], dict[str, int]]:
    """Half with URLs, half without; if one side is short, the other fills the gap."""
    with_urls = [r for r in rows if extract_urls(r.get("body") or "")]
    without = [r for r in rows if not extract_urls(r.get("body") or "")]
    rng.shuffle(with_urls)
    rng.shuffle(without)
    take_with = min(len(with_urls), n // 2)
    take_without = min(len(without), n - take_with)
    take_with = min(len(with_urls), n - take_without)
    sample = with_urls[:take_with] + without[:take_without]
    if len(sample) < n:
        print(f"  note: only {len(sample)} usable emails for a class (asked for {n})", file=sys.stderr)
    rng.shuffle(sample)
    return sample, {"with_urls": take_with, "without_urls": take_without, "available_with_urls": len(with_urls), "available_without_urls": len(without)}


def to_item(row: dict[str, str], source: str, prefix: str, expected: str) -> dict[str, Any]:
    return {
        "id": f"{prefix}-{int(row['_row']):05d}",
        "expectedVerdict": expected,
        "source": source,
        "sourceRow": int(row["_row"]),
        "from": (row.get("sender") or "").strip(),
        "subject": (row.get("subject") or "").strip(),
        "date": (row.get("date") or "").strip(),
        "body": (row.get("body") or "").strip(),
        "attachmentFilename": None,
        "attachmentContent": None,
    }


def year_of(item: dict[str, Any]) -> str | None:
    match = re.search(r"\b(19|20)\d{2}\b", item.get("date") or "")
    return match.group(0) if match else None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--nazario", type=Path, help="Path to Nazario.csv (default: evals/data/Nazario.csv).")
    parser.add_argument("--spamassassin", type=Path, help="Path to SpamAssasin.csv (default: evals/data/).")
    parser.add_argument("--per-class", type=int, default=200, help="Emails per class (default 200).")
    parser.add_argument("--seed", type=int, default=2026, help="Random seed; the same seed gives the same sample.")
    parser.add_argument("--out", type=Path, default=DATA_DIR / "eval_set.json")
    args = parser.parse_args()

    nazario = find_file(args.nazario, "Nazario.csv")
    spamassassin = find_file(args.spamassassin, "SpamAssasin.csv", "SpamAssassin.csv")
    rng = random.Random(args.seed)

    phish, phish_dropped = clean(read_rows(nazario), "1")
    ham, ham_dropped = clean(read_rows(spamassassin), "0")
    phish_sample, phish_strata = stratified_sample(phish, args.per_class, rng)
    ham_sample, ham_strata = stratified_sample(ham, args.per_class, rng)

    items = [to_item(r, "Nazario", "nazario", "Unsecured") for r in phish_sample]
    items += [to_item(r, "SpamAssassin ham", "spamassassin", "Secured") for r in ham_sample]
    rng.shuffle(items)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(items, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")

    def years(xs: list[dict[str, Any]]) -> str:
        found = sorted(y for y in (year_of(x) for x in xs) if y)
        if not found:
            return "unknown"
        return found[0] if found[0] == found[-1] else f"{found[0]}–{found[-1]}"

    phish_items = [i for i in items if i["expectedVerdict"] == "Unsecured"]
    ham_items = [i for i in items if i["expectedVerdict"] == "Secured"]
    chars = [len(i["body"][:32_000]) + len(i["subject"]) for i in items]
    # Rough planning figure only: ~4 characters per token plus ~650 tokens of system
    # instruction, ~500 output and thinking tokens, Gemini 3.8 Flash promotional prices.
    est_flash = sum((c / 4 + 650) * 0.75 + 500 * 3.75 for c in chars) / 1e6

    manifest = {
        "citation": CITATION,
        "source_url": SOURCE_URL,
        "files": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (nazario, spamassassin)
        },
        "seed": args.seed,
        "per_class": args.per_class,
        "phishing": {"n": len(phish_items), "dropped": phish_dropped, **phish_strata, "years": years(phish_items)},
        "legitimate": {"n": len(ham_items), "dropped": ham_dropped, **ham_strata, "years": years(ham_items)},
        "output": str(args.out.relative_to(ROOT_DIR) if args.out.is_relative_to(ROOT_DIR) else args.out),
        "output_sha256": hashlib.sha256(args.out.read_bytes()).hexdigest(),
    }
    manifest_path = args.out.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"Wrote {len(items)} emails to {manifest['output']} (manifest: {manifest_path.name})")
    print(f"  phishing:   {len(phish_items)} from {nazario.name} ({phish_strata['with_urls']} with URLs, "
          f"{phish_strata['without_urls']} without; years {manifest['phishing']['years']})")
    print(f"  legitimate: {len(ham_items)} from {spamassassin.name} ({ham_strata['with_urls']} with URLs, "
          f"{ham_strata['without_urls']} without; years {manifest['legitimate']['years']})")
    print(f"  median body length: {statistics.median(chars):,.0f} characters")
    print(f"  rough cost on Gemini 3.8 Flash alone: about ${est_flash:.2f} (escalations to Argon add to this)")
    print(f"Next: python tools/evaluate.py --mode local --dataset {manifest['output']} --sweep --workers 8")


if __name__ == "__main__":
    main()
