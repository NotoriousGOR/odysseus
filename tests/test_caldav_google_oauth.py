"""#4908 — Google CalDAV rejects app passwords, so Google-linked CalDAV
accounts authenticate with the linked email account's OAuth bearer token."""
import types

import core.database as database
import routes.email_helpers as email_helpers
from routes.calendar_routes import FALLBACK_OWNER
from src import caldav_sync


class _FakeDb:
    def __init__(self, row):
        self.row = row

    def get(self, _model, _id):
        return self.row

    def close(self):
        pass


def _row(owner="", provider="google"):
    return types.SimpleNamespace(owner=owner, oauth_provider=provider, imap_user="me@gmail.com",
                                 from_address="", oauth_access_token="enc", oauth_token_expiry="0")


def _token_for(monkeypatch, row, owner):
    monkeypatch.setattr(database, "SessionLocal", lambda: _FakeDb(row))
    monkeypatch.setattr(email_helpers, "_get_valid_google_token", lambda _id, _cfg: "tok")
    return caldav_sync._google_access_token("acc1", owner)


def test_google_token_requires_owned_google_account(monkeypatch):
    assert _token_for(monkeypatch, _row(owner="alice"), "alice") == "tok"
    assert _token_for(monkeypatch, _row(owner="alice"), "bob") == ""
    assert _token_for(monkeypatch, _row(provider=""), "alice") == ""
    # Single-user: calendar uses FALLBACK_OWNER, email rows have no owner.
    assert _token_for(monkeypatch, _row(owner=""), FALLBACK_OWNER) == "tok"


def test_caldav_credentials_uses_bearer_only_for_google_links(monkeypatch):
    monkeypatch.setattr(caldav_sync, "_google_access_token", lambda gid, owner: f"tok-{gid}")
    acc = {"url": " https://x/ ", "username": "me", "google_account_id": "g1"}
    assert caldav_sync.caldav_credentials(acc, "alice") == ("https://x/", "me", "tok-g1", "bearer")
    plain = {"url": "https://x/", "username": "me", "password": ""}
    assert caldav_sync.caldav_credentials(plain, "alice")[3] is None
