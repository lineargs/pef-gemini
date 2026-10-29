"""Tests for tools/build_eval_set.py: cleaning, balance and reproducibility."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from tools import build_eval_set as bes  # noqa: E402

FIELDS = ["sender", "receiver", "date", "subject", "body", "urls", "label"]


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def _row(i: int, label: str, link: bool, **extra: str) -> dict[str, str]:
    body = f"Message number {i} with enough words to count as a real body of an email."
    if link:
        body += f" See https://example.org/page/{i}"
    return {"sender": f"Sender {i} <s{i}@example.org>", "receiver": "someone@example.com",
            "date": "Thu, 22 Aug 2002 18:26:25 +0700", "subject": f"Subject {i}",
            "body": body, "urls": "1" if link else "0", "label": label, **extra}


class TestBuildEvalSet(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        phish = [_row(i, "1", link=i % 3 == 0) for i in range(60)]
        phish.append({**_row(999, "1", False), "body": "This text is part of the internal format of your mail folder, and is not a real message."})
        phish.append({**_row(998, "1", False), "body": "too short"})
        phish.append(dict(phish[0]))  # exact duplicate
        ham = [_row(i, "0", link=i % 2 == 0) for i in range(100, 160)] + [_row(i, "1", True) for i in range(200, 210)]
        _write_csv(self.tmp / "Nazario.csv", phish)
        _write_csv(self.tmp / "SpamAssasin.csv", ham)

    def _run(self, *args: str) -> list[dict]:
        out = self.tmp / "eval_set.json"
        argv = ["build_eval_set.py", "--nazario", str(self.tmp / "Nazario.csv"),
                "--spamassassin", str(self.tmp / "SpamAssasin.csv"), "--out", str(out), *args]
        with mock.patch.object(sys, "argv", argv), mock.patch("sys.stdout", io.StringIO()):
            bes.main()
        return json.loads(out.read_text(encoding="utf-8"))

    def test_balanced_cleaned_and_labelled(self) -> None:
        items = self._run("--per-class", "20")
        phish = [i for i in items if i["expectedVerdict"] == "Unsecured"]
        ham = [i for i in items if i["expectedVerdict"] == "Secured"]
        self.assertEqual((len(phish), len(ham)), (20, 20))
        self.assertTrue(all(i["source"] == "Nazario" for i in phish))
        self.assertTrue(all(i["source"] == "SpamAssassin ham" for i in ham))  # label-1 rows excluded
        for group in (phish, ham):  # half with a URL in the body, half without
            self.assertEqual(sum("https://" in i["body"] for i in group), 10)
        bodies = [i["body"] for i in items]
        self.assertFalse(any("internal format of your mail folder" in b or b == "too short" for b in bodies))
        self.assertEqual(len(set(i["id"] for i in items)), len(items))
        self.assertNotIn("receiver", items[0])  # the recipient address is dropped

    def test_same_seed_same_sample_and_manifest(self) -> None:
        first = self._run("--per-class", "15")
        second = self._run("--per-class", "15")
        self.assertEqual(first, second)
        self.assertNotEqual(first, self._run("--per-class", "15", "--seed", "7"))
        manifest = json.loads((self.tmp / "eval_set.manifest.json").read_text())
        self.assertEqual(manifest["phishing"]["dropped"], {"other_label": 0, "short_body": 1, "artefact": 1, "duplicate": 1})

    def test_short_stratum_is_filled_from_the_other(self) -> None:
        items = self._run("--per-class", "50")  # only 20 phishing emails have links
        phish = [i for i in items if i["expectedVerdict"] == "Unsecured"]
        self.assertEqual(len(phish), 50)
        self.assertEqual(sum("https://" in i["body"] for i in phish), 20)

    def test_evaluate_loads_the_output(self) -> None:
        from tools.evaluate import load_dataset

        self._run("--per-class", "5")
        emails = load_dataset(self.tmp / "eval_set.json")
        self.assertEqual(len(emails), 10)


if __name__ == "__main__":
    unittest.main(verbosity=2)
