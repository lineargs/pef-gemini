"""Tests for tools/teardown_datastore.py: stored Gmail access is revoked before deletion."""

from __future__ import annotations

import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock
import urllib.error

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from tools import teardown_datastore as td  # noqa: E402


class _Query:
    def __init__(self, ds: "FakeDatastore", kind: str) -> None:
        self.ds, self.kind = ds, kind

    def keys_only(self) -> None:
        pass

    def fetch(self):
        return list(self.ds.kinds.get(self.kind, []))


class FakeDatastore:
    """Just enough of datastore.Client: query(kind).fetch(), delete_multi(keys)."""

    def __init__(self, kinds: dict[str, list]) -> None:
        self.kinds = kinds
        self.deleted: list = []

    def query(self, kind: str) -> _Query:
        return _Query(self, kind)

    def delete_multi(self, keys) -> None:
        self.deleted.extend(keys)
        for kind, entities in self.kinds.items():
            self.kinds[kind] = [e for e in entities if e.key not in keys]


class _Entity(dict):
    def __init__(self, kind: str, name: str, **fields) -> None:
        super().__init__(fields)
        self.key = SimpleNamespace(kind=kind, name=name)


def _store(with_audit: bool = True) -> FakeDatastore:
    token = json.dumps({"refresh_token": "1//refresh-abc", "token": "ya29.access", "client_id": "id", "client_secret": "s"})
    kinds = {
        "OAuthToken": [_Entity("OAuthToken", "u@example.com", email="u@example.com", token_json=token)],
        "MailboxWatchState": [_Entity("MailboxWatchState", "u@example.com")],
        "Pending": [_Entity("Pending", "u@example.com")],
        "emailNotifications": [_Entity("emailNotifications", f"m{i}") for i in range(3)],
    }
    if with_audit:
        kinds["EmailAuditLog"] = [_Entity("EmailAuditLog", "m0")]
    return FakeDatastore(kinds)


class TestTeardown(unittest.TestCase):
    def test_revokes_refresh_token_then_deletes_state_but_keeps_audit(self) -> None:
        ds = _store()
        revoked, stopped = [], []
        with mock.patch("sys.stdout", io.StringIO()):
            counts = td.teardown(ds, dry_run=False, purge_audit=False,
                                 revoke=lambda t: revoked.append(t) or True,
                                 stop=lambda tj: stopped.append(tj) or True)
        self.assertEqual(revoked, ["1//refresh-abc"])  # the refresh token, not the access token
        self.assertEqual(len(stopped), 1)
        self.assertEqual(counts, {"tokens": 1, "revoked": 1, "watches_stopped": 1, "deleted": 6})
        self.assertEqual(ds.kinds["OAuthToken"], [])
        self.assertEqual(len(ds.kinds["EmailAuditLog"]), 1)  # verdict history kept by default

    def test_purge_audit_also_deletes_verdict_history(self) -> None:
        ds = _store()
        with mock.patch("sys.stdout", io.StringIO()):
            td.teardown(ds, dry_run=False, purge_audit=True, revoke=lambda t: True, stop=lambda tj: True)
        self.assertEqual(ds.kinds["EmailAuditLog"], [])

    def test_dry_run_changes_nothing(self) -> None:
        ds = _store()
        revoke = mock.MagicMock()
        with mock.patch("sys.stdout", io.StringIO()) as out:
            td.teardown(ds, dry_run=True, purge_audit=True, revoke=revoke, stop=mock.MagicMock())
        revoke.assert_not_called()
        self.assertEqual(ds.deleted, [])
        self.assertIn("would revoke", out.getvalue())

    def test_revoke_treats_already_invalid_token_as_done(self) -> None:
        def already_revoked(req, timeout):
            raise urllib.error.HTTPError(req.full_url, 400, "invalid_token", {}, None)

        def server_error(req, timeout):
            raise urllib.error.HTTPError(req.full_url, 503, "unavailable", {}, None)

        self.assertTrue(td.revoke_token("t", opener=already_revoked))
        self.assertFalse(td.revoke_token("t", opener=server_error))

    def test_revoke_posts_the_token_to_google(self) -> None:
        seen = {}

        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def opener(req, timeout):
            seen["url"], seen["data"], seen["method"] = req.full_url, req.data, req.get_method()
            return _Resp()

        self.assertTrue(td.revoke_token("1//refresh-abc", opener=opener))
        self.assertEqual(seen["url"], "https://oauth2.googleapis.com/revoke")
        self.assertEqual(seen["method"], "POST")
        self.assertEqual(seen["data"], b"token=1%2F%2Frefresh-abc")


if __name__ == "__main__":
    unittest.main(verbosity=2)
