"""Tests for sign-in location tracking (approximate, privacy-preserving)."""
import pytest

import geo
from audit import AuditLog


@pytest.mark.parametrize("raw, expected", [
    ("49.36.12.7", "49.36.12.7"),
    ("49.36.12.7, 10.0.0.1", "49.36.12.7"),          # first hop of X-Forwarded-For
    ("10.0.0.5", None), ("127.0.0.1", None),          # private / loopback ignored
    ("not-an-ip", None), ("", None), (None, None),
    ("<script>alert(1)</script>", None),              # injection attempt
])
def test_ip_parsing(raw, expected):
    assert geo.parse_ip(raw) == expected


def test_ip_is_masked():
    assert geo.mask_ip("49.36.12.7") == "49.36.12.x"
    assert geo.mask_ip("2405:201:abcd:1234::1").endswith(":x")
    assert geo.mask_ip(None) == "hidden"


def test_lookup_failure_gives_unknown(monkeypatch):
    def boom(*a, **k):
        raise TimeoutError
    monkeypatch.setattr(geo.requests, "get", boom)
    geo.lookup.cache_clear()
    assert geo.lookup("8.8.4.4") == geo.UNKNOWN
    assert geo.lookup(None) == geo.UNKNOWN


def test_lookup_cleans_provider_text(monkeypatch):
    class Resp:
        ok = True
        def json(self):
            return {"city": "Pune;loc=Evil", "region": "Maharashtra", "country_name": "India"}
    monkeypatch.setattr(geo.requests, "get", lambda *a, **k: Resp())
    geo.lookup.cache_clear()
    text = geo.lookup("1.1.1.1")
    assert text.startswith("Pune") and ";" not in text and "=" not in text
    geo.lookup.cache_clear()


def test_last_location_from_audit_log(tmp_path):
    log = AuditLog(str(tmp_path / "a.db"))
    assert log.last_location("admin") is None
    log.record("admin", "login_success", "role admin; loc=Pune, India; ip=1.2.3.x")
    log.record("admin", "login_success", "role admin; loc=Delhi, India; ip=5.6.7.x")
    assert log.last_location("admin") == "Delhi, India"
    assert len(log.login_history()) == 2
    assert log.verify() == (True, None)
