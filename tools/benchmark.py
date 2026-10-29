#!/usr/bin/env python3
"""Benchmark & Cost Comparison: 2021 AutoML Thesis Baseline vs. 2026 Gemini 3.8 Flash (PEF v2).

Prints the architecture and token-economics comparison tables between PEF v1 and PEF v2.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from tools.simulator import SAMPLE_EMAILS_PATH, run_single_email  # noqa: E402

THESIS_2021_STATS = {
    # Confirmed against the 2021 code, the SREday London 2026 slides and the author.
    # Full details: datasets/thesis_2021_slice.json
    "url_model": {
        "name": "PEFURLs (AutoML NL Single-Label)",
        "dataset": "PhishStorm (Marchal et al., 2014) — 95,895 URLs",
        "confidence_threshold": 0.95,
        "precision_pct": 99.58,
        "recall_pct": 95.09,
    },
    "messages_model": {
        "name": "PEFMessages (AutoML NL Single-Label)",
        "dataset": "52,162 emails (20,643 phishing)",
        "confidence_threshold": 0.95,
        "precision_pct": 99.41,
        "recall_pct": 98.45,
    },
    "training_hours_total": 12,
    "live_inbox_trial": {
        "total_emails": 298,
        "period": "February to May 2021",
        "categories": [
            {
                "name": "No attachments and no URLs",
                "n": 67,
                "pct": 22.5,
                "phishing": 33,
                "legit": 34,
            },
            {
                "name": "URLs, but no attachments",
                "n": 223,
                "pct": 74.8,
                "phishing": 135,
                "legit": 88,
            },
            {
                "name": "Attachments, but no URLs",
                "n": 3,
                "pct": 1.0,
                "phishing": 0,
                "legit": 3,
            },
            {
                "name": "Attachments and URLs",
                "n": 5,
                "pct": 1.7,
                "phishing": 0,
                "legit": 5,
            },
        ],
    },
}


def print_architecture_and_cost_comparison() -> None:
    print("\n" + "=" * 92)
    print(
        "  PEF v1 (2021 MSc Thesis: AutoML NL) vs. PEF v2 (2026: Gemini 3.8 Flash on Agent Platform)"
    )
    print("=" * 92)
    rows = [
        ("Dimension", "2021 Thesis (PEF v1)", "2026 Modernized (PEF v2)"),
        ("-" * 26, "-" * 28, "-" * 32),
        (
            "AI / ML Engine",
            "2 Custom AutoML NL Models",
            "Gemini 3.8 Flash (+ 4 Argon if unsure)",
        ),
        (
            "Dataset Prep & Training",
            "148,057 rows + 12 hrs train",
            "Zero-shot Structured Outputs (0 hrs)",
        ),
        (
            "Cloud Run / Functions",
            "8 Functions (Node.js 8 and 10)",
            "3 Pipeline Functions + Auth Setup (Python 3.12)",
        ),
        (
            "Pub/Sub Hops per Email",
            "5 sequential topics",
            "2 decoupled hops (ingest -> analyze -> outcome)",
        ),
        (
            "BEC & Executive Spoofing",
            "Not measured (no ground truth)",
            "Semantic intent + propositions (measure: tools/evaluate.py)",
        ),
        (
            "Attachment Inspection",
            "One attachment, scored as text",
            "Text attachments (.txt/.csv/.html/.eml) + MIME metadata",
        ),
        (
            "Explainability",
            "Opaque float [0, 6] only",
            "6 Proposition flags + PII-free reasoning summary",
        ),
        (
            "Pricing model",
            "Per AutoML prediction (<=4/email)",
            "Per Gemini token; $0 compute at idle",
        ),
        (
            "Token / Inference Cost",
            "Not recorded",
            "Pay-per-token; measured per run by tools/evaluate.py",
        ),
    ]
    for col1, col2, col3 in rows:
        print(f"  {col1:<26} | {col2:<28} | {col3}")
    print("=" * 92)


def print_thesis_trial_summary() -> None:
    trial = THESIS_2021_STATS["live_inbox_trial"]
    print(
        f"\n2021 live inbox trial (N={trial['total_emails']}, {trial['period']}): the framework's verdicts"
    )
    print(
        f"  {'Category':<30} | {'N':>5} | {'Share':>7} | {'Flagged':>10} | {'Not flagged':>11}"
    )
    print("  " + "-" * 74)
    for cat in trial["categories"]:
        print(
            f"  {cat['name']:<30} | {cat['n']:>5} | {cat['pct']:>6.1f}% | "
            f"{cat['phishing']:>10} | {cat['legit']:>11}"
        )
    print(
        "  Verdicts, not ground truth: which were correct was not recorded, so the 2021\n"
        "  trial has no accuracy figure."
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PEF v1 vs. v2 Benchmark & Cost Analyzer"
    )
    parser.add_argument(
        "--mode",
        choices=["offline", "local"],
        default="offline",
        help="Run using 'local' (live Gemini 3.8 Flash API) or 'offline' (deterministic pipeline smoke-test stub).",
    )
    args = parser.parse_args()

    print_architecture_and_cost_comparison()
    print_thesis_trial_summary()

    emails = json.loads(SAMPLE_EMAILS_PATH.read_text(encoding="utf-8"))
    t0 = time.perf_counter()
    results = [run_single_email(e, mode=args.mode) for e in emails]
    total_ms = (time.perf_counter() - t0) * 1000

    tp = sum(
        1
        for r in results
        if r["verdict"] == "Unsecured" and r["expected"] == "Unsecured"
    )
    tn = sum(
        1
        for r in results
        if r["verdict"] == "Secured" and r["expected"] == "Secured"
    )
    fp = sum(
        1
        for r in results
        if r["verdict"] == "Unsecured" and r["expected"] == "Secured"
    )
    fn = sum(
        1
        for r in results
        if r["verdict"] == "Secured" and r["expected"] == "Unsecured"
    )

    precision = (tp / (tp + fp)) * 100 if (tp + fp) else 0.0
    recall = (tp / (tp + fn)) * 100 if (tp + fn) else 0.0
    avg_latency = total_ms / len(results)

    eval_label = (
        "Live Gemini 3.8 Flash Evaluation"
        if args.mode == "local"
        else "Pipeline Smoke-Test Verification (Deterministic Offline Stub)"
    )
    print("\n" + "=" * 92)
    print(f"  {eval_label} (N={len(results)} across all 4 categories):")
    print(
        f"  TP={tp} | TN={tn} | FP={fp} | FN={fn}  -->  "
        f"Precision={precision:.2f}% | Recall={recall:.2f}% | Avg Latency={avg_latency:.0f} ms"
    )
    print(
        f"  N={len(results)} is a small sample set, not a benchmark. For quotable accuracy, tokens and cost\n"
        "  (with 95% confidence intervals), run: python tools/evaluate.py --mode local --sweep"
    )
    print("=" * 92)


if __name__ == "__main__":
    main()
