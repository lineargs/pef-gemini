#!/usr/bin/env python3
"""The 2021 framework (PEF v1) in numbers, plus a replay of 2021-style emails on PEF v2.

Prints the confirmed facts about the 2021 MSc framework from
`datasets/thesis_2021_slice.json` (its two AutoML models, pipeline and live-trial
verdicts), then runs four synthetic emails written in the style of 2021 lures
through the PEF v2 pipeline. The 2021 emails themselves were a private inbox and
are not in this repository.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from tools.simulator import run_single_email  # noqa: E402

SLICE_PATH = ROOT_DIR / "datasets" / "thesis_2021_slice.json"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Show the 2021 framework's facts and replay 2021-style emails on PEF v2"
    )
    parser.add_argument(
        "--mode",
        choices=["offline", "local"],
        default="offline",
        help="'offline' (deterministic keyword stub) or 'local' (live Gemini 3.8 Flash).",
    )
    args = parser.parse_args()

    data = json.loads(SLICE_PATH.read_text(encoding="utf-8"))
    meta = data["metadata"]

    print("\n" + "=" * 84)
    print("  PEF v1 (2021 MSc framework): confirmed facts")
    print("=" * 84)
    for model in meta["models"]:
        print(f"\n  {model['name']} ({model['api']})")
        print(f"      Used by: {', '.join(model['used_by'])}")
        if model.get("dataset"):
            print(f"      Dataset: {model['dataset']}")
        print(
            f"      Training rows: {model['training_rows']:,} "
            f"({model['legitimate_rows']:,} legitimate, {model['phishing_rows']:,} phishing)"
        )
        print(
            f"      Held-out precision / recall at 0.95: "
            f"{model['held_out_precision_pct_at_095']}% / {model['held_out_recall_pct_at_095']}%"
        )
    print(f"\n  Training time, both models: {meta['training_hours_total']} hours")
    pipe = meta["pipeline"]
    runtimes = ", ".join(f"{n} on {rt}" for rt, n in pipe["runtimes"].items())
    print(f"  Cloud Functions: {pipe['cloud_functions']} ({runtimes})")
    print(f"  Email topics in sequence: {' -> '.join(pipe['email_topics_in_sequence'])}")

    trial = meta["live_trial"]
    print(
        f"\n  Live trial ({trial['period']}): {trial['emails']} emails, {trial['flagged_phishing']} flagged as phishing, "
        f"{trial['not_flagged']} not flagged."
    )
    print(f"  {trial['note']}")

    print("\n" + "=" * 84)
    print(f"  Replaying synthetic 2021-style emails through PEF v2 ({args.mode.upper()} mode)")
    print("=" * 84)
    for email_item in data["replay_emails"]:
        print(f"\n  [{email_item['sourceDataset']}]")
        run_single_email(email_item, mode=args.mode)


if __name__ == "__main__":
    main()
