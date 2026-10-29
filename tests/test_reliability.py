"""Reliability tests: retry safety, cursor handling, idempotent outcomes, metering.

These use a small in-memory Datastore fake built on the real `google.cloud.datastore`
Key/Entity classes, so transaction/claim logic is exercised without a cloud project.
"""

from __future__ import annotations

import base64
import contextlib
import json
import logging
import os
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock

try:
    from google.cloud import datastore
except ImportError:
    class _StubKey:
        def __init__(self, kind: str, name: str, project: str = "test-project") -> None:
            self.kind = kind
            self.name = name
            self.project = project
            self.flat_path = (kind, name)

    class _StubEntity(dict):
        def __init__(self, key: _StubKey | None = None, exclude_from_indexes: tuple = ()) -> None:
            super().__init__()
            self.key = key
            self.exclude_from_indexes = set(exclude_from_indexes)

    datastore = ModuleType("google.cloud.datastore")  # type: ignore[assignment]
    datastore.Key = _StubKey  # type: ignore[attr-defined]
    datastore.Entity = _StubEntity  # type: ignore[attr-defined]
    google_mod = sys.modules.setdefault("google", ModuleType("google"))
    cloud_mod = sys.modules.setdefault("google.cloud", ModuleType("google.cloud"))
    google_mod.cloud = cloud_mod  # type: ignore[attr-defined]
    cloud_mod.datastore = datastore  # type: ignore[attr-defined]
    sys.modules["google.cloud.datastore"] = datastore

try:
    import googleapiclient.discovery  # noqa: F401
except ImportError:
    gapi_mod = sys.modules.setdefault("googleapiclient", ModuleType("googleapiclient"))
    disc_mod = sys.modules.setdefault("googleapiclient.discovery", ModuleType("googleapiclient.discovery"))
    disc_mod.build = lambda *a, **kw: None  # type: ignore[attr-defined]
    gapi_mod.discovery = disc_mod  # type: ignore[attr-defined]

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import functions.auth_setup.main as auth_main  # noqa: E402
import functions.email_analyze.main as analyze_main  # noqa: E402
import functions.email_ingest.main as ingest_main  # noqa: E402
import functions.email_outcome.main as outcome_main  # noqa: E402
from functions.email_analyze.main import (  # noqa: E402
    PhishingAnalysisResult,
    PhishingPropositions,
)


class FakeDatastore:
    """Minimal in-memory stand-in for `datastore.Client` (single process)."""

    def __init__(self) -> None:
        self.store: dict[tuple, datastore.Entity] = {}

    def key(self, kind: str, name: str) -> datastore.Key:
        return datastore.Key(kind, name, project="test-project")

    def get(self, key: datastore.Key):
        return self.store.get(key.flat_path)

    def put(self, entity: datastore.Entity) -> None:
        self.store[entity.key.flat_path] = entity

    def delete(self, key: datastore.Key) -> None:
        self.store.pop(key.flat_path, None)

    @contextlib.contextmanager
    def transaction(self):
        yield self


class HttpError404(Exception):
    resp = SimpleNamespace(status=404)


def _phish_result(confidence: float = 0.97) -> PhishingAnalysisResult:
    return PhishingAnalysisResult(
        domain_phishing_score=0.9,
        links_phishing_score=0.0,
        body_phishing_score=0.95,
        attachment_phishing_score=0.0,
        overall_confidence=confidence,
        is_phishing=True,
        propositions=PhishingPropositions(
            urgency=True,
            authority=True,
            suspicious_long_urls=False,
            unsolicited_context=True,
            incredible_deals=False,
            personal_or_financial_request=True,
        ),
        reasoning="test",
    )


def _gmail_notification_event(email: str, history_id: str) -> SimpleNamespace:
    data = json.dumps({"emailAddress": email, "historyId": history_id}).encode()
    return SimpleNamespace(data={"message": {"data": base64.b64encode(data).decode()}})


def _fake_gmail(message_ids: list[str], history_id: str = "200") -> mock.MagicMock:
    gmail = mock.MagicMock()
    users = gmail.users.return_value
    users.history.return_value.list.return_value.execute.return_value = {
        "history": [{"messagesAdded": [{"message": {"id": m}} for m in message_ids]}],
        "historyId": history_id,
    }

    def _get(userId: str, id: str):  # noqa: A002 - mirrors Gmail API kwarg
        msg = {
            "id": id,
            "payload": {
                "mimeType": "text/plain",
                "headers": [
                    {"name": "From", "value": "x@phish.test"},
                    {"name": "Subject", "value": "Hi"},
                ],
                "body": {"data": base64.urlsafe_b64encode(b"body").decode()},
            },
        }
        return SimpleNamespace(execute=lambda: msg)

    users.messages.return_value.get.side_effect = _get
    return gmail


class TestIngestRetrySafety(unittest.TestCase):
    def setUp(self) -> None:
        self.ds = FakeDatastore()
        state = datastore.Entity(key=self.ds.key("MailboxWatchState", "u@example.com"))
        state.update({"email": "u@example.com", "lastHistoryId": "100"})
        self.ds.put(state)
        patches = [
            mock.patch.object(ingest_main, "_get_datastore_client", return_value=self.ds),
            mock.patch.object(ingest_main, "_load_user_credentials", return_value=object()),
            mock.patch.dict(os.environ, {"ALLOW_SIMULATED_PAYLOADS": "false"}),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def _run(self, gmail: mock.MagicMock, publish: mock.MagicMock) -> None:
        with mock.patch("googleapiclient.discovery.build", return_value=gmail), mock.patch.object(
            ingest_main, "_publish_to_analyze", publish
        ):
            ingest_main.email_ingest(_gmail_notification_event("u@example.com", "200"))

    def _status(self, msg_id: str):
        entity = self.ds.get(self.ds.key("emailNotifications", msg_id))
        return entity.get("status") if entity else None

    def _cursor(self) -> str:
        return self.ds.get(self.ds.key("MailboxWatchState", "u@example.com"))["lastHistoryId"]

    def test_failed_publish_is_retried_not_stranded(self) -> None:
        gmail = _fake_gmail(["m1", "m2"])
        publish = mock.MagicMock(side_effect=["ok-1", RuntimeError("pubsub down")])

        with self.assertRaises(RuntimeError):
            self._run(gmail, publish)

        # m1 published; m2 released (lease cleared, attempt counted, not marked
        # published); cursor NOT advanced.
        self.assertEqual(self._status("m1"), "published")
        m2 = self.ds.get(self.ds.key("emailNotifications", "m2"))
        self.assertEqual((m2["status"], m2["leaseUntil"], m2["attempts"]), ("processing", 0, 1))
        self.assertEqual(self._cursor(), "100")

        # Pub/Sub redelivers: only m2 is published this time, then the cursor moves.
        publish_retry = mock.MagicMock(return_value="ok-2")
        self._run(gmail, publish_retry)
        self.assertEqual(publish_retry.call_count, 1)
        self.assertEqual(publish_retry.call_args.args[0]["messageID"], "m2")
        self.assertEqual(self._status("m2"), "published")
        self.assertEqual(self._cursor(), "200")

    def test_active_lease_blocks_concurrent_duplicate(self) -> None:
        self.assertTrue(ingest_main._claim_message(self.ds, "m1", now=1000))
        self.assertFalse(ingest_main._claim_message(self.ds, "m1", now=1001))
        # A crashed worker's lease expires and the message can be taken over.
        expired = 1000 + ingest_main.CLAIM_LEASE_SECONDS + 1
        self.assertTrue(ingest_main._claim_message(self.ds, "m1", now=expired))
        ingest_main._mark_message(self.ds, "m1", ingest_main.STATUS_PUBLISHED)
        self.assertFalse(ingest_main._claim_message(self.ds, "m1", now=expired + 10_000))

    def test_cursor_held_while_another_worker_owns_a_message(self) -> None:
        # Another invocation is mid-way through m1 (unexpired lease).
        self.assertTrue(ingest_main._claim_message(self.ds, "m1"))
        gmail = _fake_gmail(["m1", "m2"])
        publish = mock.MagicMock(return_value="ok")
        # The notification is NOT acknowledged: Pub/Sub retries after backoff, so m1
        # is picked up even if the worker holding its lease crashed.
        with self.assertRaises(ingest_main.LeaseHeldError):
            self._run(gmail, publish)
        # m2 is processed, and the cursor stays put so m1 can still be found.
        self.assertEqual(publish.call_count, 1)
        self.assertEqual(self._status("m2"), "published")
        self.assertEqual(self._cursor(), "100")

    def test_crashed_worker_lease_is_taken_over_on_retry(self) -> None:
        # A worker claimed m1 and died without releasing (timeout/OOM).
        self.assertTrue(ingest_main._claim_message(self.ds, "m1", now=1_000))
        gmail = _fake_gmail(["m1"])
        publish = mock.MagicMock(return_value="ok")
        with mock.patch.object(ingest_main.time, "time", return_value=1_010):
            with self.assertRaises(ingest_main.LeaseHeldError):
                self._run(gmail, publish)
        # Pub/Sub backoff redelivers after the lease has expired.
        later = 1_000 + ingest_main.CLAIM_LEASE_SECONDS + 1
        with mock.patch.object(ingest_main.time, "time", return_value=later):
            self._run(gmail, publish)
        publish.assert_called_once()
        self.assertEqual(self._status("m1"), "published")
        self.assertEqual(self._cursor(), "200")

    def test_poison_message_is_parked_and_does_not_block_mailbox(self) -> None:
        gmail = _fake_gmail(["poison", "m2"])

        def _publish(payload):
            if payload["messageID"] == "poison":
                raise RuntimeError("always fails")
            return "ok"

        publish = mock.MagicMock(side_effect=_publish)
        for _ in range(ingest_main.MAX_MESSAGE_ATTEMPTS):
            with self.assertRaises(RuntimeError):
                self._run(gmail, publish)
            self.assertEqual(self._cursor(), "100")  # blocked while retrying
        # Next delivery parks the poison message and processes the rest.
        self._run(gmail, publish)
        self.assertEqual(self._status("poison"), "failed")
        self.assertEqual(self._status("m2"), "published")
        self.assertEqual(self._cursor(), "200")

    def test_published_payload_is_bounded_but_keeps_all_urls(self) -> None:
        huge_body = ("x" * 100_000) + " https://late-link.example/phish"
        payload = ingest_main.build_analysis_payload(
            {"messageId": "big", "from": "a@b.c", "body": huge_body, "attachmentContent": "y" * 90_000}
        )
        self.assertEqual(len(payload["body"]), ingest_main.MAX_TEXT_CHARS)
        self.assertEqual(len(payload["attachmentContent"]), ingest_main.MAX_TEXT_CHARS)
        self.assertIn("https://late-link.example/phish", payload["urls"])
        self.assertTrue(payload["links"])

    def test_legacy_processed_entities_are_respected(self) -> None:
        legacy = datastore.Entity(key=self.ds.key("emailNotifications", "old"))
        legacy.update({"processed": True})
        self.ds.put(legacy)
        self.assertFalse(ingest_main._claim_message(self.ds, "old"))

    def test_deleted_message_is_skipped_not_retried_forever(self) -> None:
        gmail = _fake_gmail(["gone"])
        gmail.users.return_value.messages.return_value.get.side_effect = HttpError404()
        publish = mock.MagicMock()
        self._run(gmail, publish)
        publish.assert_not_called()
        self.assertEqual(self._status("gone"), "skipped")
        self.assertEqual(self._cursor(), "200")

    def test_label_change_notification_does_no_fallback_scan(self) -> None:
        gmail = _fake_gmail([])
        gmail.users.return_value.history.return_value.list.return_value.execute.return_value = {
            "historyId": "200"
        }
        publish = mock.MagicMock()
        self._run(gmail, publish)
        gmail.users.return_value.messages.return_value.list.assert_not_called()
        publish.assert_not_called()

    def test_expired_cursor_falls_back_but_transient_errors_raise(self) -> None:
        gmail = _fake_gmail([])
        history_exec = gmail.users.return_value.history.return_value.list.return_value.execute
        history_exec.side_effect = HttpError404()
        gmail.users.return_value.messages.return_value.list.return_value.execute.return_value = {
            "messages": [{"id": "recent-1"}]
        }
        ids, cursor = ingest_main._collect_inbox_message_ids(gmail, self.ds, "u@example.com", "200")
        self.assertEqual(ids, ["recent-1"])
        self.assertEqual(cursor, "200")

        history_exec.side_effect = TimeoutError("transient")
        with self.assertRaises(TimeoutError):
            ingest_main._collect_inbox_message_ids(gmail, self.ds, "u@example.com", "200")

    def test_cursor_never_moves_backwards(self) -> None:
        ingest_main._save_last_history_id(self.ds, "u@example.com", "90")
        self.assertEqual(self._cursor(), "100")
        ingest_main._save_last_history_id(self.ds, "u@example.com", "150")
        self.assertEqual(self._cursor(), "150")


class TestWatchRenewalKeepsCursor(unittest.TestCase):
    def test_renewal_does_not_overwrite_ingest_cursor(self) -> None:
        ds = FakeDatastore()
        with mock.patch.object(auth_main, "_get_datastore_client", return_value=ds):
            auth_main._save_watch_state("u@example.com", {"historyId": "100", "expiration": "1"})
            entity = ds.get(ds.key("MailboxWatchState", "u@example.com"))
            self.assertEqual(entity["lastHistoryId"], "100")

            entity["lastHistoryId"] = "120"  # ingest has processed up to 120
            ds.put(entity)
            auth_main._save_watch_state("u@example.com", {"historyId": "999", "expiration": "2"})
            entity = ds.get(ds.key("MailboxWatchState", "u@example.com"))
            self.assertEqual(entity["lastHistoryId"], "120")
            self.assertEqual(entity["expiration"], "2")


class TestAnalyzeStage(unittest.TestCase):
    def test_reputation_outage_raises_before_spending_gemini_tokens(self) -> None:
        payload = {"messageID": "m", "senderDomain": "https://x.org", "urls": ["https://x.org/a"]}
        event = SimpleNamespace(
            data={"message": {"data": base64.b64encode(json.dumps(payload).encode()).decode()}}
        )
        with mock.patch.dict(
            os.environ, {"SAFE_BROWSING_API_KEY": "k", "SAFE_BROWSING_FAIL_CLOSED": "true"}
        ), mock.patch("urllib.request.urlopen", side_effect=TimeoutError("down")), mock.patch.object(
            analyze_main, "analyze_with_gemini_detailed"
        ) as gemini:
            with self.assertRaises(analyze_main.SafeBrowsingUnavailableError):
                analyze_main.email_analyze(event)
            gemini.assert_not_called()

    def test_token_usage_is_recorded_per_call(self) -> None:
        result = _phish_result()
        response = SimpleNamespace(
            parsed=result,
            text=json.dumps(result.model_dump()),
            usage_metadata=SimpleNamespace(
                prompt_token_count=812,
                candidates_token_count=164,
                thoughts_token_count=233,
                total_token_count=1209,
            ),
        )
        client = mock.MagicMock()
        client.models.generate_content.return_value = response
        run = analyze_main.analyze_with_gemini_detailed(
            {"senderEmailAddress": "a@b.c", "body": "hi"}, client=client
        )
        self.assertEqual(run.models, ["gemini-3.8-flash"])
        self.assertEqual(
            run.token_totals(),
            {"promptTokens": 812, "outputTokens": 164, "thinkingTokens": 233, "totalTokens": 1209},
        )

    def test_evaluate_retries_transient_errors_only(self) -> None:
        from tools import evaluate as ev

        class ServerError(Exception):
            code = 504

        self.assertTrue(ev.is_transient(ServerError("504 DEADLINE_EXCEEDED")))
        self.assertTrue(ev.is_transient(TimeoutError()))
        bad_request = ValueError("400 INVALID_ARGUMENT")
        self.assertFalse(ev.is_transient(bad_request))

    def test_genai_client_has_a_request_timeout(self) -> None:
        try:
            from google.genai import types  # noqa: F401
        except ImportError:
            self.skipTest("google-genai not installed")
        with mock.patch("google.genai.Client") as client_cls, mock.patch.object(analyze_main, "_genai_client", None), \
                mock.patch.dict(os.environ, {"GEMINI_TIMEOUT_SECONDS": "30"}):
            analyze_main._get_genai_client()
        http_options = client_cls.call_args.kwargs["http_options"]
        self.assertEqual(http_options.timeout, 30_000)

    def test_escalation_thinking_level_defaults_to_low(self) -> None:
        client = mock.MagicMock()
        client.models.generate_content.side_effect = [
            SimpleNamespace(parsed=_phish_result(0.50), text="{}"),
            SimpleNamespace(parsed=_phish_result(0.97), text="{}"),
        ]
        with mock.patch.dict(os.environ, {"GEMINI_ESCALATION_MODEL": "gemini-4-argon"}):
            run = analyze_main.analyze_with_gemini_detailed({"body": "x"}, client=client)
        self.assertEqual(run.models, ["gemini-3.8-flash", "gemini-4-argon"])
        self.assertEqual(run.calls[1]["thinkingLevel"], "LOW")
        self.assertEqual(run.result.overall_confidence, 0.97)  # the escalation result is used
        config = client.models.generate_content.call_args.kwargs["config"]
        thinking_cfg = config["thinking_config"] if isinstance(config, dict) else config.thinking_config
        thinking_lvl = thinking_cfg["thinking_level"] if isinstance(thinking_cfg, dict) else getattr(thinking_cfg.thinking_level, "value", thinking_cfg.thinking_level)
        self.assertEqual(str(thinking_lvl), "LOW")

    def test_confident_first_pass_does_not_escalate(self) -> None:
        for confidence in (0.03, 0.97):
            client = mock.MagicMock()
            client.models.generate_content.return_value = SimpleNamespace(
                parsed=_phish_result(confidence), text="{}"
            )
            with mock.patch.dict(os.environ, {"GEMINI_ESCALATION_MODEL": "gemini-4-argon"}):
                run = analyze_main.analyze_with_gemini_detailed({"body": "x"}, client=client)
            self.assertEqual(run.models, ["gemini-3.8-flash"], confidence)

    def test_no_escalation_model_means_one_call(self) -> None:
        client = mock.MagicMock()
        client.models.generate_content.return_value = SimpleNamespace(
            parsed=_phish_result(0.50), text="{}"
        )
        env = {k: v for k, v in os.environ.items() if k != "GEMINI_ESCALATION_MODEL"}
        with mock.patch.dict(os.environ, env, clear=True):
            analyze_main.analyze_with_gemini_detailed({"body": "x"}, client=client)
        self.assertEqual(client.models.generate_content.call_count, 1)

    def test_transient_escalation_failure_is_retried_once(self) -> None:
        class ServerError(Exception):
            code = 503

        client = mock.MagicMock()
        client.models.generate_content.side_effect = [
            SimpleNamespace(parsed=_phish_result(0.50), text="{}"),
            ServerError("503 UNAVAILABLE"),
            SimpleNamespace(parsed=_phish_result(0.96), text="{}"),
        ]
        with mock.patch.dict(os.environ, {"GEMINI_ESCALATION_MODEL": "gemini-4-argon"}), \
                mock.patch.object(analyze_main, "ESCALATION_RETRY_DELAY_S", 0):
            run = analyze_main.analyze_with_gemini_detailed({"body": "x"}, client=client)
        self.assertEqual(run.result.overall_confidence, 0.96)  # the retried escalation decided
        self.assertEqual(run.models, ["gemini-3.8-flash", "gemini-4-argon"])
        self.assertEqual(run.calls[1]["attempts"], 2)

    def test_escalation_retry_skipped_when_it_would_not_fit_the_budget(self) -> None:
        class ServerError(Exception):
            code = 504

        client = mock.MagicMock()
        client.models.generate_content.side_effect = [
            SimpleNamespace(parsed=_phish_result(0.50), text="{}"),
            ServerError("504 DEADLINE_EXCEEDED"),
        ]
        env = {"GEMINI_ESCALATION_MODEL": "gemini-4-argon", "PEF_ANALYSIS_BUDGET_SECONDS": "30"}
        with mock.patch.dict(os.environ, env), mock.patch.object(analyze_main, "ESCALATION_RETRY_DELAY_S", 0), \
                self.assertLogs(analyze_main.logger, level="WARNING"):
            run = analyze_main.analyze_with_gemini_detailed({"body": "x"}, client=client)
        self.assertEqual(client.models.generate_content.call_count, 2)  # no second escalation
        self.assertEqual(run.result.overall_confidence, 0.50)

    def test_failed_escalation_keeps_first_pass_result(self) -> None:
        client = mock.MagicMock()
        client.models.generate_content.side_effect = [
            SimpleNamespace(parsed=_phish_result(0.50), text="{}"),
            RuntimeError("404 model not found"),
        ]
        with mock.patch.dict(os.environ, {"GEMINI_ESCALATION_MODEL": "gemini-4-argon"}), \
                self.assertLogs(analyze_main.logger, level="WARNING"):
            run = analyze_main.analyze_with_gemini_detailed({"body": "x"}, client=client)
        self.assertEqual(run.result.overall_confidence, 0.50)
        self.assertEqual(run.models, ["gemini-3.8-flash"])
        self.assertEqual(run.escalation_error, "gemini-4-argon: RuntimeError")
        self.assertEqual(run.calls[1], {"model": "gemini-4-argon", "thinkingLevel": "LOW", "error": "RuntimeError"})

    def test_policy_block_fails_closed_without_retry_loop(self) -> None:
        try:
            from google.genai import types
            safety_reason = types.FinishReason.SAFETY
            prohibited_reason = types.BlockedReason.PROHIBITED_CONTENT
        except ImportError:
            safety_reason = SimpleNamespace(name="SAFETY", value="SAFETY")
            prohibited_reason = SimpleNamespace(name="PROHIBITED_CONTENT", value="PROHIBITED_CONTENT")

        client = mock.MagicMock()
        client.models.generate_content.return_value = SimpleNamespace(
            parsed=None,
            text=None,
            prompt_feedback=None,
            candidates=[SimpleNamespace(finish_reason=safety_reason)],
        )
        run = analyze_main.analyze_with_gemini_detailed({"body": "x"}, client=client)
        self.assertTrue(run.result.is_phishing)
        self.assertEqual(run.blocked_reason, "SAFETY")
        self.assertIn("declined", run.result.reasoning)
        verdict = outcome_main.determine_verdict_label(
            total_score=0.0,
            maximum_score=3,
            gemini_is_phishing=run.result.is_phishing,
            gemini_confidence=run.result.overall_confidence,
        )
        self.assertEqual(verdict, "Unsecured")

        # A blocked *prompt* is reported via prompt_feedback.block_reason.
        client.models.generate_content.return_value = SimpleNamespace(
            parsed=None,
            text=None,
            prompt_feedback=SimpleNamespace(block_reason=prohibited_reason),
            candidates=[],
        )
        run = analyze_main.analyze_with_gemini_detailed({"body": "x"}, client=client)
        self.assertEqual(run.blocked_reason, "PROHIBITED_CONTENT")

    def test_other_empty_response_raises_for_retry(self) -> None:
        client = mock.MagicMock()
        client.models.generate_content.return_value = SimpleNamespace(
            parsed=None, text=None, prompt_feedback=None,
            candidates=[SimpleNamespace(finish_reason="MAX_TOKENS")],
        )
        with self.assertRaisesRegex(ValueError, "finish_reason=MAX_TOKENS"):
            analyze_main.analyze_with_gemini({"body": "x"}, client=client)

    def test_safe_browsing_permanent_errors_batching_and_rate_limits(self) -> None:
        import urllib.error

        def _http_error(code: int):
            return urllib.error.HTTPError("https://sb", code, "err", {}, None)

        env = {"SAFE_BROWSING_API_KEY": "k", "SAFE_BROWSING_FAIL_CLOSED": "true"}
        with mock.patch.dict(os.environ, env):
            # Invalid key / API disabled: permanent, recorded, not retried.
            with mock.patch("urllib.request.urlopen", side_effect=_http_error(403)):
                rep = analyze_main.check_reputation("https://x.org", ["https://x.org/a"])
                self.assertEqual(rep.status, "error")
            # Rate limited: transient, so fail closed (retry).
            with mock.patch("urllib.request.urlopen", side_effect=_http_error(429)):
                with self.assertRaises(analyze_main.SafeBrowsingUnavailableError):
                    analyze_main.check_reputation("https://x.org", ["https://x.org/a"])
            # More than 500 URLs are split into Lookup API-sized batches.
            ok = mock.MagicMock()
            ok.read.return_value = b"{}"
            ok.__enter__.return_value = ok
            urls = [f"https://x.org/{i}" for i in range(1_200)]
            with mock.patch("urllib.request.urlopen", return_value=ok) as urlopen:
                rep = analyze_main.check_reputation("https://x.org", urls)
            self.assertEqual(rep.status, "ok")
            self.assertEqual(urlopen.call_count, 3)
            sizes = [
                len(json.loads(c.args[0].data)["threatInfo"]["threatEntries"])
                for c in urlopen.call_args_list
            ]
            self.assertEqual(sizes, [500, 500, 201])


class TestOutcomeStage(unittest.TestCase):
    def _event(self) -> SimpleNamespace:
        outcome = {
            "messageID": "m1",
            "emailAddress": "u@example.com",
            "total": 2.9,
            "maxScore": 5,
            "category": "Links, but no attachment",
            "maxComponentScore": 0.95,
            "geminiAnalysis": {**_phish_result().model_dump()},
            "reputationStatus": "ok",
            "geminiModels": ["gemini-3.8-flash", "gemini-4-argon"],
            "geminiUsage": {"promptTokens": 800, "outputTokens": 150, "thinkingTokens": 200},
        }
        return SimpleNamespace(
            data={"message": {"data": base64.b64encode(json.dumps(outcome).encode()).decode()}}
        )

    def test_redelivery_does_not_duplicate_sheet_rows(self) -> None:
        ds = FakeDatastore()
        sheet = mock.MagicMock()
        with mock.patch.object(outcome_main, "_get_datastore_client", return_value=ds), mock.patch.object(
            outcome_main, "_load_user_credentials", return_value=object()
        ), mock.patch.object(outcome_main, "_apply_gmail_verdict_label") as label, mock.patch.object(
            outcome_main, "_append_to_google_sheet", sheet
        ), mock.patch("googleapiclient.discovery.build"):
            outcome_main.email_outcome(self._event())
            outcome_main.email_outcome(self._event())  # Pub/Sub redelivery
        self.assertEqual(sheet.call_count, 1)
        self.assertEqual(label.call_count, 2)  # idempotent label swap is re-applied
        audit = ds.get(ds.key("EmailAuditLog", "m1"))
        self.assertTrue(audit["sheetAppended"])
        self.assertEqual(audit["thinkingTokens"], 200)
        self.assertEqual(audit["reputationStatus"], "ok")
        self.assertEqual(audit["geminiModels"], "gemini-3.8-flash,gemini-4-argon")
        self.assertEqual(sheet.call_args.kwargs["model"], "gemini-3.8-flash → gemini-4-argon")
        self.assertEqual(sheet.call_args.kwargs["phishing_probability"], 0.97)

    def test_sheet_row_names_the_deciding_model(self) -> None:
        self.assertEqual(outcome_main._model_cell("gemini-3.8-flash"), "gemini-3.8-flash")
        self.assertEqual(
            outcome_main._model_cell("gemini-3.8-flash", "gemini-4-argon: ResourceExhausted"),
            "gemini-3.8-flash (escalation failed: gemini-4-argon: ResourceExhausted)",
        )
        service = mock.MagicMock()
        with mock.patch.dict(os.environ, {"GOOGLE_SHEET_ID": "sheet-1"}), \
                mock.patch("googleapiclient.discovery.build", return_value=service):
            outcome_main._append_to_google_sheet(
                object(), "m1", "Links, but no attachment", 2.9, "Unsecured", "Lookalike domain.",
                propositions={"urgency": True, "authority": False},
                model="gemini-3.8-flash → gemini-4-argon",
                phishing_probability=0.9666,
            )
        kwargs = service.spreadsheets().values().append.call_args.kwargs
        self.assertEqual(kwargs["range"], "Sheet1!A1:H1")
        row = kwargs["body"]["values"][0]
        self.assertEqual(len(row), len(outcome_main.SHEET_COLUMNS))
        self.assertEqual(dict(zip(outcome_main.SHEET_COLUMNS, row))["Model"], "gemini-3.8-flash → gemini-4-argon")
        self.assertEqual(dict(zip(outcome_main.SHEET_COLUMNS, row))["Signals"], "urgency")
        self.assertEqual(dict(zip(outcome_main.SHEET_COLUMNS, row))["Phishing probability"], 0.97)

    def test_function_loggers_emit_info_on_cloud_run(self) -> None:
        # functions-framework sets the root logger to WARNING before loading the module,
        # so each function must set its own logger to INFO or its INFO lines are dropped.
        for module in (auth_main, ingest_main, analyze_main, outcome_main):
            self.assertEqual(module.logger.level, logging.INFO, module.__name__)

    def test_disagreeing_duplicate_keeps_first_verdict(self) -> None:
        ds = FakeDatastore()
        first = json.loads(base64.b64decode(self._event().data["message"]["data"]))
        second = {**first, "total": 0.1, "maxComponentScore": 0.1,
                  "geminiAnalysis": {**first["geminiAnalysis"], "is_phishing": False,
                                     "overall_confidence": 0.05}}
        events = [
            SimpleNamespace(data={"message": {"data": base64.b64encode(json.dumps(e).encode()).decode()}})
            for e in (first, second)
        ]
        with mock.patch.object(outcome_main, "_get_datastore_client", return_value=ds), mock.patch.object(
            outcome_main, "_load_user_credentials", return_value=object()
        ), mock.patch.object(outcome_main, "_apply_gmail_verdict_label") as label, mock.patch.object(
            outcome_main, "_append_to_google_sheet"
        ) as sheet, mock.patch("googleapiclient.discovery.build"):
            for event in events:
                outcome_main.email_outcome(event)
        self.assertEqual([c.args[4] for c in label.call_args_list], ["Unsecured", "Unsecured"])
        self.assertEqual(sheet.call_args.args[4], "Unsecured")
        self.assertEqual(ds.get(ds.key("EmailAuditLog", "m1"))["verdict"], "Unsecured")

    def test_label_swap_removes_pending_and_opposite_verdict_and_tolerates_404(self) -> None:
        ds = FakeDatastore()
        for name, label_id in (("Pending", "L_P"), ("Secured", "L_S"), ("Unsecured", "L_U")):
            e = datastore.Entity(key=ds.key(name, "u@example.com"))
            e["labelId"] = label_id
            ds.put(e)
        gmail = mock.MagicMock()
        outcome_main._apply_gmail_verdict_label(gmail, ds, "m1", "u@example.com", "Unsecured")
        body = gmail.users.return_value.messages.return_value.modify.call_args.kwargs["body"]
        self.assertEqual(body["addLabelIds"], ["L_U"])
        self.assertEqual(sorted(body["removeLabelIds"]), ["L_P", "L_S"])

        gmail.users.return_value.messages.return_value.modify.return_value.execute.side_effect = HttpError404()
        outcome_main._apply_gmail_verdict_label(gmail, ds, "gone", "u@example.com", "Secured")

    def test_concurrent_sheet_append_is_claimed_once(self) -> None:
        ds = FakeDatastore()
        audit = datastore.Entity(key=ds.key("EmailAuditLog", "m1"))
        audit.update({"verdict": "Secured", "sheetAppended": False, "sheetClaimUntil": 0})
        ds.put(audit)
        self.assertTrue(outcome_main._claim_sheet_row(ds, "m1", now=1_000))
        with self.assertRaises(outcome_main.SheetRowLeaseHeldError):
            outcome_main._claim_sheet_row(ds, "m1", now=1_001)
        outcome_main._mark_sheet_appended(ds, "m1")
        self.assertFalse(outcome_main._claim_sheet_row(ds, "m1", now=5_000))

    def test_heuristic_cutoffs_are_configurable(self) -> None:
        kwargs = dict(
            total_score=1.0,
            maximum_score=3,
            gemini_is_phishing=True,
            gemini_confidence=0.80,
            max_component_score=0.80,
        )
        self.assertEqual(outcome_main.determine_verdict_label(**kwargs), "Secured")
        with mock.patch.dict(os.environ, {"PEF_CONFIDENCE_CUTOFF": "0.75"}):
            self.assertEqual(outcome_main.determine_verdict_label(**kwargs), "Unsecured")
        self.assertEqual(
            outcome_main.determine_verdict_label(**kwargs, component_threshold=0.8),
            "Unsecured",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
