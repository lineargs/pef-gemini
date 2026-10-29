#!/usr/bin/env python3
"""Live evaluation harness for PEF v2: measured accuracy, tokens and cost.

Runs a labelled email set through the real pipeline functions (ingest normalisation,
Gemini analysis, optional reputation check, composite score, verdict) and records
every result, so the numbers you publish come from a saved run rather than
from estimates.

Outputs (in --out, default `evals/results/`):
  <run_id>.jsonl       one line per email: verdict, scores, propositions, tokens, cost
  <run_id>.summary.md  confusion matrix with Wilson 95% intervals, token and cost
                       per 1,000 emails, and (with --sweep) a cut-off sweep

Examples:
  # Live run against Gemini on Agent Platform (needs ADC + GOOGLE_CLOUD_PROJECT)
  python tools/evaluate.py --mode local --sweep

  # Your own labelled set (JSON list or JSONL; each item needs expectedVerdict
  # "Secured"/"Unsecured", or label "phishing"/"legitimate")
  python tools/evaluate.py --mode local --dataset path/to/emails.jsonl --sweep

  # Recompute the summary and sweep from a saved run without calling Gemini
  python tools/evaluate.py --replay evals/results/<run_id>.jsonl --sweep

  # CI smoke test of the harness itself (keyword stub, NOT a model evaluation)
  python tools/evaluate.py --mode offline
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import time
from typing import Any, Iterable

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from functions.email_analyze.main import (  # noqa: E402
    DEFAULT_MODEL,
    GeminiRun,
    analyze_with_gemini_detailed,
    check_reputation,
    compute_composite_score,
)
from functions.email_ingest.main import build_analysis_payload  # noqa: E402
from functions.email_outcome.main import (  # noqa: E402
    THRESHOLDS_BY_MAX_SCORE,
    component_cutoff,
    confidence_cutoff,
    determine_verdict_label,
)
from tools.simulator import SAMPLE_EMAILS_PATH, _offline_heuristic_analysis  # noqa: E402

# USD per 1M tokens, Gemini API paid tier. Output price applies to output AND thinking
# tokens. Gemini 3.8 Flash rates are promotional until 31 Dec 2026 and double on
# 1 Jan 2027 (1.50 / 7.50). Gemini 4 Argon rates are introductory until 30 Nov 2026 and
# double on 1 Dec 2026 (4.00 / 20.00). Override with --prices '{"model": {"input": x, "output": y}}'.
# Source: https://ai.google.dev/gemini-api/docs/pricing (checked October 2026).
DEFAULT_PRICES: dict[str, dict[str, float]] = {
    "gemini-3.8-flash": {"input": 0.75, "output": 3.75},
    "gemini-4-argon": {"input": 2.00, "output": 10.00},
    "gemini-3.5-flash-lite": {"input": 0.30, "output": 2.50},
}

SMALL_SAMPLE_WARNING = 100
SWEEP_GRID = (0.70, 0.80, 0.85, 0.90, 0.95)


# --------------------------------------------------------------------------- data


def load_dataset(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".jsonl":
        items = [json.loads(line) for line in text.splitlines() if line.strip()]
    else:
        items = json.loads(text)
    emails = []
    for i, item in enumerate(items):
        expected = item.get("expectedVerdict")
        if expected is None and "label" in item:
            expected = (
                "Unsecured"
                if str(item["label"]).lower() in ("phishing", "phish", "spam", "1", "true")
                else "Secured"
            )
        if expected not in ("Secured", "Unsecured"):
            raise ValueError(f"Item {i} has no usable expectedVerdict/label: {item.get('id')}")
        emails.append({**item, "expectedVerdict": expected, "id": item.get("id") or f"item-{i}"})
    return emails


# ------------------------------------------------------------------------ metrics


def wilson_interval(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval; behaves sensibly for small n and 0%/100%."""
    if n == 0:
        return (float("nan"), float("nan"))
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def confusion(rows: Iterable[dict[str, Any]], verdict_key: str = "verdict") -> dict[str, int]:
    c = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    for r in rows:
        pred_pos = r[verdict_key] == "Unsecured"
        true_pos = r["expected"] == "Unsecured"
        c[("t" if pred_pos == true_pos else "f") + ("p" if pred_pos else "n")] += 1
    return c


def rates(c: dict[str, int]) -> dict[str, Any]:
    tp, tn, fp, fn = c["tp"], c["tn"], c["fp"], c["fn"]
    precision = tp / (tp + fp) if tp + fp else float("nan")
    recall = tp / (tp + fn) if tp + fn else float("nan")
    fpr = fp / (fp + tn) if fp + tn else float("nan")
    f1 = (
        2 * precision * recall / (precision + recall)
        if tp and not math.isnan(precision) and not math.isnan(recall)
        else 0.0
    )
    return {
        "precision": precision,
        "precision_ci": wilson_interval(tp, tp + fp),
        "recall": recall,
        "recall_ci": wilson_interval(tp, tp + fn),
        "fpr": fpr,
        "fpr_ci": wilson_interval(fp, fp + tn),
        "f1": f1,
    }


def call_cost_usd(call: dict[str, Any], prices: dict[str, dict[str, float]]) -> float | None:
    price = prices.get(call.get("model", ""))
    if price is None:
        return None
    billed_output = int(call.get("outputTokens") or 0) + int(call.get("thinkingTokens") or 0)
    return (
        int(call.get("promptTokens") or 0) * price["input"] + billed_output * price["output"]
    ) / 1_000_000


# -------------------------------------------------------------------------- run


def evaluate_email(
    raw_email: dict[str, Any],
    mode: str,
    with_reputation: bool,
    prices: dict[str, dict[str, float]],
) -> dict[str, Any]:
    payload = build_analysis_payload({**raw_email, "simulated": True})
    started = time.perf_counter()

    reputation_status = "not_checked"
    domain_hit = links_hit = False
    if with_reputation and mode == "local":
        rep = check_reputation(payload["senderDomain"], payload["urls"])
        domain_hit, links_hit, reputation_status = rep.domain_hit, rep.links_hit, rep.status

    if mode == "local":
        run = analyze_with_gemini_detailed(payload)
    else:
        run = GeminiRun(result=_offline_heuristic_analysis(payload), calls=[])
    latency_ms = (time.perf_counter() - started) * 1000
    analysis = run.result

    outcome = compute_composite_score(payload, analysis, domain_hit, links_hit)
    verdict = determine_verdict_label(
        total_score=outcome["total"],
        maximum_score=outcome["maxScore"],
        gemini_is_phishing=analysis.is_phishing,
        gemini_confidence=analysis.overall_confidence,
        domain_sb_malicious=domain_hit,
        links_sb_malicious=links_hit,
        max_component_score=outcome["maxComponentScore"],
    )
    costs = [call_cost_usd(c, prices) for c in run.calls]
    return {
        "id": raw_email["id"],
        "expected": raw_email["expectedVerdict"],
        "verdict": verdict,
        "category": outcome["category"],
        "total": outcome["total"],
        "maxScore": outcome["maxScore"],
        "maxComponentScore": outcome["maxComponentScore"],
        "isPhishing": analysis.is_phishing,
        "overallConfidence": analysis.overall_confidence,
        "domainHit": domain_hit,
        "linksHit": links_hit,
        "reputationStatus": reputation_status,
        "analysis": analysis.model_dump(),
        "calls": run.calls,
        "costUsd": None if any(c is None for c in costs) else sum(costs),
        "latencyMs": round(latency_ms, 1),
    }


def verdict_with_cutoffs(r: dict[str, Any], conf_cut: float | None, comp_cut: float | None) -> str:
    """Re-derive a verdict from a saved row; None/None means thesis threshold only."""
    if r["domainHit"] or r["linksHit"]:
        return "Unsecured"
    if conf_cut is None and comp_cut is None:
        threshold = THRESHOLDS_BY_MAX_SCORE.get(r["maxScore"], 1.90)
        return "Unsecured" if r["total"] >= threshold else "Secured"
    return determine_verdict_label(
        total_score=r["total"],
        maximum_score=r["maxScore"],
        gemini_is_phishing=r["isPhishing"],
        gemini_confidence=r["overallConfidence"],
        max_component_score=r["maxComponentScore"],
        confidence_threshold=conf_cut,
        component_threshold=comp_cut,
    )


# ---------------------------------------------------------------------- report


def _pct(x: float) -> str:
    return "n/a" if math.isnan(x) else f"{x * 100:.1f}%"


def _ci(ci: tuple[float, float]) -> str:
    lo, hi = ci
    return "n/a" if math.isnan(lo) else f"{lo * 100:.1f}–{hi * 100:.1f}%"


def build_summary(all_rows: list[dict[str, Any]], meta: dict[str, Any], sweep: bool) -> str:
    errors = [row for row in all_rows if row.get("error")]
    rows = [row for row in all_rows if not row.get("error")]
    n = len(rows)
    c = confusion(rows)
    r = rates(c)
    lines = [f"# PEF v2 evaluation — {meta['run_id']}", ""]
    if meta["mode"] != "local":
        lines += [
            "> **Offline keyword stub — this is a smoke test of the harness, not an evaluation "
            "of Gemini. Do not quote these numbers.**",
            "",
        ]
    lines += [
        f"- Mode: `{meta['mode']}` · Models: `{', '.join(meta.get('models') or ['n/a'])}` · "
        f"Thinking: `{meta.get('thinking_level')}` · Escalation: `{meta.get('escalation_model') or 'off'}`",
        f"- Dataset: `{meta['dataset']}` (sha256 `{meta['dataset_sha256'][:12]}`), N = {n}",
        f"- Reputation check: `{meta.get('with_reputation')}` · Cut-offs: confidence "
        f"{meta['confidence_cutoff']}, component {meta['component_cutoff']}",
        f"- Recorded: {meta['recorded_at']} · google-genai {meta.get('sdk_version', 'n/a')}",
        "",
    ]
    blocked = [row for row in rows if any(c.get("blocked") for c in row["calls"])]
    if errors or blocked:
        lines += [
            f"> {len(errors)} email(s) failed with an error and are excluded from the metrics "
            f"below; {len(blocked)} were declined by the model and scored fail-closed "
            "(Unsecured). See the `.jsonl` for details.",
            "",
        ]
        for row in errors[:10]:
            lines.append(f"- `{row['id']}`: {row['error'][:200]}")
        if errors:
            lines.append("")
    if n < SMALL_SAMPLE_WARNING:
        lines += [
            f"> N = {n} is too small for accuracy claims; the intervals below show how wide "
            f"the uncertainty is. Use a labelled set of at least {SMALL_SAMPLE_WARNING} emails "
            "(ideally several hundred, both classes) before quoting precision/recall.",
            "",
        ]
    lines += [
        "## Accuracy (positive class = Unsecured)",
        "",
        "| TP | TN | FP | FN | Precision (95% CI) | Recall (95% CI) | False-positive rate (95% CI) | F1 |",
        "|---:|---:|---:|---:|---|---|---|---:|",
        f"| {c['tp']} | {c['tn']} | {c['fp']} | {c['fn']} | "
        f"{_pct(r['precision'])} ({_ci(r['precision_ci'])}) | "
        f"{_pct(r['recall'])} ({_ci(r['recall_ci'])}) | "
        f"{_pct(r['fpr'])} ({_ci(r['fpr_ci'])}) | {r['f1']:.3f} |",
        "",
        "### By category",
        "",
        "| Category | N | Correct |",
        "|---|---:|---:|",
    ]
    for cat in sorted({row["category"] for row in rows}):
        sub = [row for row in rows if row["category"] == cat]
        ok = sum(1 for row in sub if row["verdict"] == row["expected"])
        lines.append(f"| {cat} | {len(sub)} | {ok} |")

    calls = [call for row in rows for call in row["calls"]]
    if calls:

        def avg(key: str) -> float:
            return sum(int(call.get(key) or 0) for call in calls) / n

        costs = [row["costUsd"] for row in rows if row["costUsd"] is not None]
        escalated = sum(1 for row in rows if len(row["calls"]) > 1)
        escalation_failed = sum(1 for row in rows if any(c.get("error") for c in row["calls"]))
        lat = sorted(row["latencyMs"] for row in rows)
        p50 = lat[len(lat) // 2]
        p95 = lat[min(len(lat) - 1, math.ceil(0.95 * len(lat)) - 1)]
        lines += [
            "",
            "## Tokens, cost and latency (measured)",
            "",
            "| Avg prompt tokens / email | Avg output tokens | Avg thinking tokens | "
            "Cost per 1,000 emails | Escalated | Latency p50 / p95 |",
            "|---:|---:|---:|---:|---:|---|",
            f"| {avg('promptTokens'):.0f} | {avg('outputTokens'):.0f} | "
            f"{avg('thinkingTokens'):.0f} | "
            + (f"${sum(costs) / len(costs) * 1000:.2f}" if costs else "n/a (unknown model price)")
            + f" | {escalated}/{n}"
            + (f" ({escalation_failed} failed)" if escalation_failed else "")
            + f" | {p50:.0f} / {p95:.0f} ms |",
            "",
            f"Prices used (USD per 1M tokens, output includes thinking): `{json.dumps(meta['prices'])}`. "
            "Gemini 3.8 Flash promotional rates double on 1 January 2027; "
            "Gemini 4 Argon introductory rates double on 1 December 2026.",
        ]

    if sweep:
        lines += [
            "",
            "## Cut-off sweep",
            "",
            "Verdict rule: reputation hit OR thesis threshold OR (`is_phishing` AND "
            "(confidence ≥ c OR max component ≥ k)). Choose cut-offs on a labelled set that "
            "is separate from the one you report results on.",
            "",
            "| Rule | Precision | Recall | FPR | F1 |",
            "|---|---:|---:|---:|---:|",
        ]
        candidates: list[tuple[str, float | None, float | None]] = [
            ("Thesis threshold only (k × 0.95)", None, None)
        ]
        candidates += [(f"c = {cc:.2f}, k = {kk:.2f}", cc, kk) for cc in SWEEP_GRID for kk in SWEEP_GRID]
        for label, cc, kk in candidates:
            swept = [{**row, "swept": verdict_with_cutoffs(row, cc, kk)} for row in rows]
            sr = rates(confusion(swept, "swept"))
            marker = (
                " ← current"
                if cc == meta["confidence_cutoff"] and kk == meta["component_cutoff"]
                else ""
            )
            lines.append(
                f"| {label}{marker} | {_pct(sr['precision'])} | {_pct(sr['recall'])} | "
                f"{_pct(sr['fpr'])} | {sr['f1']:.3f} |"
            )
    lines.append("")
    return "\n".join(lines)


# ------------------------------------------------------------------------- main


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=["local", "offline"], default="local")
    parser.add_argument("--dataset", type=Path, default=SAMPLE_EMAILS_PATH)
    parser.add_argument("--out", type=Path, default=ROOT_DIR / "evals" / "results")
    parser.add_argument("--with-reputation", action="store_true", help="Also call Safe Browsing (needs SAFE_BROWSING_API_KEY).")
    parser.add_argument("--sweep", action="store_true", help="Add a cut-off sweep to the summary.")
    parser.add_argument("--limit", type=int, default=0, help="Only evaluate the first N emails.")
    parser.add_argument("--prices", help="JSON price overrides, e.g. '{\"gemini-3.8-flash\": {\"input\": 1.5, \"output\": 7.5}}'.")
    parser.add_argument("--replay", type=Path, help="Recompute the summary from a saved .jsonl run.")
    args = parser.parse_args()

    prices = {**DEFAULT_PRICES, **(json.loads(args.prices) if args.prices else {})}
    args.out.mkdir(parents=True, exist_ok=True)

    if args.replay:
        lines = args.replay.read_text(encoding="utf-8").splitlines()
        meta = {**json.loads(lines[0])["meta"], "prices": prices}
        rows = [json.loads(line) for line in lines[1:] if line.strip()]
        for row in rows:  # Re-price in case --prices changed.
            costs = [call_cost_usd(c, prices) for c in row["calls"]]
            row["costUsd"] = None if any(c is None for c in costs) else sum(costs)
        summary = build_summary(rows, meta, args.sweep)
        print(summary)
        return

    emails = load_dataset(args.dataset)
    if args.limit:
        emails = emails[: args.limit]

    try:
        from importlib.metadata import version

        sdk_version = version("google-genai")
    except Exception:
        sdk_version = "not installed"

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{stamp}_{args.mode}"
    meta = {
        "run_id": run_id,
        "mode": args.mode,
        "dataset": str(args.dataset.relative_to(ROOT_DIR) if args.dataset.is_relative_to(ROOT_DIR) else args.dataset),
        "dataset_sha256": hashlib.sha256(args.dataset.read_bytes()).hexdigest(),
        "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "thinking_level": os.environ.get("GEMINI_THINKING_LEVEL", "LOW") if args.mode == "local" else None,
        "escalation_model": (os.environ.get("GEMINI_ESCALATION_MODEL", "").strip() or None) if args.mode == "local" else None,
        "with_reputation": bool(args.with_reputation and args.mode == "local"),
        "confidence_cutoff": confidence_cutoff(),
        "component_cutoff": component_cutoff(),
        "sdk_version": sdk_version,
        "prices": prices,
    }

    if args.mode == "local":
        meta["models"] = [os.environ.get("GEMINI_MODEL", DEFAULT_MODEL)]
        if meta["escalation_model"]:
            meta["models"].append(meta["escalation_model"])
    else:
        meta["models"] = ["offline-stub"]

    # Rows are written as they complete, so an interrupted or failing run keeps
    # every result already paid for. Per-email errors are recorded, not fatal.
    rows = []
    jsonl_path = args.out / f"{run_id}.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps({"meta": meta}) + "\n")
        fh.flush()
        for i, email in enumerate(emails, start=1):
            try:
                row = evaluate_email(email, args.mode, args.with_reputation, prices)
                mark = "ok " if row["verdict"] == row["expected"] else "MISS"
            except Exception as exc:  # noqa: BLE001 - record and continue
                row = {
                    "id": email["id"],
                    "expected": email["expectedVerdict"],
                    "verdict": "Error",
                    "error": f"{type(exc).__name__}: {exc}",
                    "calls": [],
                    "costUsd": None,
                }
                mark = "ERR "
            rows.append(row)
            fh.write(json.dumps(row) + "\n")
            fh.flush()
            print(f"[{i}/{len(emails)}] {mark} {row['id']}: {row['verdict']} (expected {row['expected']})", file=sys.stderr)

    summary = build_summary(rows, meta, args.sweep)
    summary_path = args.out / f"{run_id}.summary.md"
    summary_path.write_text(summary, encoding="utf-8")
    print(summary)
    print(f"\nSaved {jsonl_path} and {summary_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
