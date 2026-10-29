"""Tests for tools/alerts.py: the policies it builds and its create/update/delete calls."""

from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from tools import alerts  # noqa: E402

CHANNEL = "projects/p/notificationChannels/1"


class FakeApi:
    """Records Monitoring API calls and answers from an in-memory project."""

    def __init__(self, policies=(), channels=()) -> None:
        self.state = {"alertPolicies": list(policies), "notificationChannels": list(channels)}
        self.calls: list[tuple[str, str, dict | None]] = []
        self.next_id = 100

    def __call__(self, req):
        path = req.full_url.split("/v3/projects/p/", 1)[1]
        body = json.loads(req.data) if req.data else None
        self.calls.append((req.get_method(), path, body))
        assert req.headers["X-goog-user-project"] == "p"
        collection = path.split("?", 1)[0].split("/", 1)[0]
        if req.get_method() == "GET":
            result = {collection: self.state[collection]}
        elif req.get_method() == "POST":
            self.next_id += 1
            result = {**body, "name": f"projects/123/{collection}/{self.next_id}"}
            self.state[collection].append(result)
        else:
            result = {}
        return io.BytesIO(json.dumps(result).encode())


def _api(fake: FakeApi) -> alerts.Monitoring:
    return alerts.Monitoring("p", "token", opener=fake)


class TestAlerts(unittest.TestCase):
    def test_policies(self) -> None:
        policies = alerts.build_policies("p", "email-dlq-inspect", "https://onboard.example", CHANNEL)
        self.assertEqual([p["displayName"] for p in policies],
                         [alerts.DLQ_POLICY, alerts.AUTH_POLICY, alerts.FAILED_POLICY])
        for policy in policies:
            self.assertEqual(policy["notificationChannels"], [CHANNEL])
            self.assertEqual(policy["userLabels"]["app"], "pef-gemini")
            self.assertEqual(len(policy["conditions"]), 1)
            self.assertLessEqual(len(policy["documentation"]["subject"]), 255)
        dlq = policies[0]["conditions"][0]["conditionThreshold"]
        self.assertIn('subscription_id = "email-dlq-inspect"', dlq["filter"])
        self.assertIn("https://onboard.example", policies[1]["documentation"]["content"])
        for policy in policies[1:]:  # log-match alerts need a rate limit
            self.assertIn("notificationRateLimit", policy["alertStrategy"])
        self.assertIn('jsonPayload.message:"PEF_AUTH_EXPIRED"', policies[1]["conditions"][0]["conditionMatchedLog"]["filter"])
        self.assertIn('textPayload:"PEF_MESSAGE_FAILED"', policies[2]["conditions"][0]["conditionMatchedLog"]["filter"])

    def test_first_run_creates_channel_and_policies(self) -> None:
        fake = FakeApi()
        api = _api(fake)
        channel = alerts.ensure_channel(api, "me@example.com", dry_run=False)
        alerts.apply(api, alerts.build_policies("p", "dlq", "u", channel), dry_run=False)
        posts = [(path, body) for method, path, body in fake.calls if method == "POST"]
        self.assertEqual([p for p, _ in posts], ["notificationChannels"] + ["alertPolicies"] * 3)
        self.assertEqual(posts[0][1]["labels"], {"email_address": "me@example.com"})
        self.assertEqual(posts[1][1]["notificationChannels"], [channel])

    def test_rerun_reuses_channel_and_replaces_policies(self) -> None:
        existing = [{"name": "projects/123/alertPolicies/7", "displayName": alerts.AUTH_POLICY,
                     "userLabels": {"app": "pef-gemini"}},
                    {"name": "projects/123/alertPolicies/8", "displayName": alerts.DLQ_POLICY,
                     "userLabels": {"app": "something-else"}}]
        channels = [{"name": "projects/123/notificationChannels/5", "type": "email",
                     "labels": {"email_address": "me@example.com"}}]
        fake = FakeApi(existing, channels)
        api = _api(fake)
        channel = alerts.ensure_channel(api, "me@example.com", dry_run=False)
        self.assertEqual(channel, "projects/123/notificationChannels/5")
        alerts.apply(api, alerts.build_policies("p", "dlq", "u", channel), dry_run=False)
        writes = [(m, path) for m, path, _ in fake.calls if m != "GET"]
        # Only our own policy is updated; a same-named policy without our label is left alone.
        self.assertEqual(writes, [("POST", "alertPolicies"), ("PATCH", "alertPolicies/7"), ("POST", "alertPolicies")])

    def test_delete_removes_only_labelled_items(self) -> None:
        fake = FakeApi(
            [{"name": "projects/123/alertPolicies/7", "displayName": "a", "userLabels": {"app": "pef-gemini"}},
             {"name": "projects/123/alertPolicies/9", "displayName": "theirs"}],
            [{"name": "projects/123/notificationChannels/5", "displayName": "c", "userLabels": {"app": "pef-gemini"}},
             {"name": "projects/123/notificationChannels/6", "displayName": "reused"}],
        )
        alerts.delete(_api(fake), dry_run=True)
        self.assertFalse([c for c in fake.calls if c[0] == "DELETE"])
        alerts.delete(_api(fake), dry_run=False)
        self.assertEqual([path for m, path, _ in fake.calls if m == "DELETE"],
                         ["alertPolicies/7", "notificationChannels/5?force=true"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
