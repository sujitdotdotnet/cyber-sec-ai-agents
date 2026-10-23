"""Limits and identities: per-user and per-guest allowances, rate limit, downloads, persistence, allow-lists."""

from dataclasses import replace

import pytest

from secagents import identity
from secagents.config import settings
from secagents.db import Db
from secagents.limits import GLOBAL, Allowance, Usage, allowance_for, today


@pytest.fixture
def usage(tmp_path):
    return Usage(Db(tmp_path / "u.db"))


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def allowance(usage, who, **kw):
    base = dict(session_cap=None, daily_cap=1000, global_cap=10_000, rate_per_minute=100, download_cap=2, clock=Clock())
    return Allowance(usage, who, **{**base, **kw})


def test_usage_counters_add_up_per_owner_day_and_kind(usage):
    usage.add("a", "tokens", 10)
    usage.add("a", "tokens", 5)
    usage.add("a", "downloads", 1)
    usage.add("b", "tokens", 7)
    usage.add("a", "tokens", 99, day="2000-01-01")
    assert (usage.get("a", "tokens"), usage.get("a", "downloads"), usage.get("b", "tokens")) == (15, 1, 7)
    assert usage.get("a", "tokens", day="2000-01-01") == 99 and usage.get("nobody", "tokens") == 0
    usage.prune(keep_days=7)
    assert usage.get("a", "tokens", day="2000-01-01") == 0 and usage.get("a", "tokens") == 15


def test_counters_survive_a_restart(tmp_path):
    first = Usage(Db(tmp_path / "u.db"))
    first.add("u-1", "tokens", 400)
    assert Usage(Db(tmp_path / "u.db")).get("u-1", "tokens") == 400  # a new process opening the same database


def test_a_users_daily_cap_applies_to_that_user_only(usage):
    a, b = allowance(usage, identity.user("a", "a@x.com"), daily_cap=100), allowance(usage, identity.user("b", "b@x.com"), daily_cap=100)
    a.spend(120)
    assert "daily allowance" in a.blocked() and b.blocked() is None
    a2 = allowance(usage, identity.user("a", "a@x.com"), daily_cap=100)  # same user, new session or device
    assert "daily allowance" in a2.blocked()


def test_guests_are_limited_per_session_and_per_client_not_per_tab(usage):
    client = identity.guest(client="abc")
    one, two = allowance(usage, client, session_cap=50, daily_cap=100), allowance(usage, identity.guest(client="abc"), session_cap=50, daily_cap=100)
    one.spend(60)
    assert "guest session" in one.blocked()
    assert two.blocked() is None  # a fresh session starts its own session allowance...
    two.spend(45)
    assert "guest allowance" in two.blocked()  # ...but the client's daily total (60 + 45) is already over 100
    other = allowance(usage, identity.guest(client="zzz"), session_cap=50, daily_cap=100)
    assert other.blocked() is None


def test_everyone_together_have_a_global_cap(usage):
    a, b = allowance(usage, identity.user("a", "a"), global_cap=150), allowance(usage, identity.user("b", "b"), global_cap=150)
    a.spend(100)
    assert b.blocked() is None
    b.spend(60)
    assert "all visitors" in a.blocked() and usage.get(GLOBAL, "tokens") == 160


def test_rate_limit_is_per_minute_and_recovers(usage):
    clock = Clock()
    a = allowance(usage, identity.user("a", "a"), rate_per_minute=3, clock=clock)
    for _ in range(3):
        a.spend(1)
    assert "Too many requests" in a.blocked()
    clock.t += 61
    assert a.blocked() is None


def test_downloads_are_limited_and_repeats_are_free(usage):
    a = allowance(usage, identity.guest(client="c"), download_cap=2)
    assert a.download("https://github.com/o/r") is None and a.download("https://github.com/o/r") is None  # same link: counted once
    assert a.download("https://github.com/o/r2") is None
    assert "Download limit" in a.download("https://github.com/o/r3")
    assert usage.get(a.identity.limit_key, "downloads") == 2


def test_allowance_for_uses_guest_and_user_settings(usage, monkeypatch):
    cfg = replace(settings, session_token_cap=11, guest_daily_token_cap=22, user_daily_token_cap=33, guest_daily_downloads=1, user_daily_downloads=5)
    monkeypatch.setattr("secagents.limits.settings", cfg)
    g, u = allowance_for(identity.guest(), usage), allowance_for(identity.user("s", "s"), usage)
    assert (g.session_cap, g.daily_cap, g.download_cap) == (11, 22, 1)
    assert (u.session_cap, u.daily_cap, u.download_cap) == (None, 33, 5)


def test_the_day_key_is_utc_and_dated():
    assert len(today()) == 10 and today().count("-") == 2


# ---- identities -----------------------------------------------------------------------------------------
def test_user_ids_are_stable_private_and_case_insensitive():
    a, b = identity.user("Sub-1", "me@x.com"), identity.user("sub-1", "other label")
    assert a.id == b.id and a.id.startswith("u-") and "sub-1" not in a.id.lower() and a.limit_key == a.id and not a.is_guest


def test_guest_identity_limits_by_client_when_known():
    assert identity.guest(client="h").limit_key == "guest-h"
    solo = identity.guest()
    assert solo.limit_key == solo.id and solo.is_guest


def test_client_hash_trusts_only_the_rightmost_forwarded_address():
    assert identity.client_hash("1.1.1.1, 2.2.2.2") == identity.client_hash("9.9.9.9, 2.2.2.2")  # the forged left part is ignored
    assert identity.client_hash("1.1.1.1") != identity.client_hash("2.2.2.2")
    assert identity.client_hash(None) is None and identity.client_hash(" , ") is None
    assert "1.1.1.1" not in (identity.client_hash("1.1.1.1") or "")  # only a hash is kept


def test_access_list(monkeypatch):
    open_site = replace(settings, allowed_emails=(), allowed_email_domains=())
    monkeypatch.setattr(identity, "settings", open_site)
    assert identity.check_allowed("anyone@x.com") is None
    assert "not verified" in identity.check_allowed("a@x.com", verified=False)
    monkeypatch.setattr(identity, "settings", replace(settings, allowed_emails=("boss@x.com",), allowed_email_domains=("corp.com",)))
    assert identity.check_allowed("Boss@x.com") is None and identity.check_allowed("dev@corp.com") is None
    assert "access list" in identity.check_allowed("stranger@evil.com") and "access list" in identity.check_allowed("")
