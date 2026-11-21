"""Tests for the advanced security features: two-factor login, encryption at
rest, tamper-evident audit log, model signing, differential privacy, anomaly
detection, rate limiting and CAPTCHA."""
import base64
import sqlite3

import numpy as np
import pandas as pd
import pytest

import mfa
from anomaly import InputAnomalyDetector
from audit import AuditLog
from auth import (hash_password, load_users, authenticate, verify_second_factor,
                  LoginThrottle)
from database import Database
from guards import RateLimiter, new_captcha, captcha_ok
from models import Student
from privacy import dp_mean, dp_histogram
from secure_crypto import check_keys

SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
PW = "Test-Admin-Pass-1"


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


# ---------------- Keys ----------------
def test_all_security_keys_are_configured():
    assert check_keys() == []


def test_missing_key_is_detected(monkeypatch):
    monkeypatch.delenv("SPP_SECURITY_AUDIT_KEY")
    assert "audit_key" in check_keys()


# ---------------- Two-factor login (TOTP, RFC 6238) ----------------
def test_totp_matches_rfc6238_test_vector():
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert mfa.totp_at(secret, 59 // 30, digits=8) == "94287082"
    assert mfa.totp_at(secret, 1111111109 // 30, digits=8) == "07081804"


def test_correct_code_is_accepted_and_cannot_be_replayed():
    verifier = mfa.TOTPVerifier()
    now = 1_700_000_000
    code = mfa.totp_at(SECRET, mfa.current_step(now))
    assert verifier.verify("admin", SECRET, code, now=now)
    assert not verifier.verify("admin", SECRET, code, now=now)   # replay refused


@pytest.mark.parametrize("code", ["000000", "12345", "abcdef", "", None, "1234567"])
def test_wrong_or_malformed_codes_are_refused(code):
    assert not mfa.TOTPVerifier().verify("admin", SECRET, code, now=1_700_000_000)


def test_old_code_outside_window_is_refused():
    now = 1_700_000_000
    old = mfa.totp_at(SECRET, mfa.current_step(now) - 5)
    assert not mfa.TOTPVerifier().verify("admin", SECRET, old, now=now)


def test_admin_without_two_factor_is_not_loaded():
    users = load_users({"boss": {"password_hash": hash_password(PW), "role": "admin"}})
    assert users == {}


def test_two_factor_failures_count_towards_lockout():
    users = load_users({"admin": {"password_hash": hash_password(PW),
                                  "role": "admin", "totp_secret": SECRET}})
    assert authenticate("admin", PW, users)[0] == "admin"
    throttle = LoginThrottle(clock=FakeClock())
    for _ in range(5):
        ok, _ = verify_second_factor("admin", "000000", users,
                                     mfa.TOTPVerifier(), throttle)
        assert not ok
    ok, message = verify_second_factor("admin", "000000", users,
                                       mfa.TOTPVerifier(), throttle)
    assert not ok and message.startswith("Too many")


# ---------------- Encryption at rest ----------------
def test_names_are_encrypted_in_the_database(tmp_path):
    db = Database(str(tmp_path / "enc.db"))
    db.add_student(Student("Anu Sharma", 6, 85, 22, 25, 17, 78))
    raw = sqlite3.connect(db.db_name).execute("SELECT name FROM students").fetchone()[0]
    assert "Anu" not in raw and raw.startswith("gAAAA")       # Fernet token
    assert db.get_all().loc[0, "name"] == "Anu Sharma"


def test_wrong_key_cannot_read_names(tmp_path):
    from cryptography.fernet import Fernet
    path = str(tmp_path / "enc.db")
    Database(path).add_student(Student("Anu", 6, 85, 22, 25, 17, 78))
    stranger = Database(path, cipher=Fernet(Fernet.generate_key()))
    assert stranger.get_all().loc[0, "name"] == "[unreadable]"


# ---------------- Tamper-evident audit log ----------------
def test_untouched_audit_chain_verifies(tmp_path):
    log = AuditLog(str(tmp_path / "audit.db"))
    for action in ["login_success", "prediction", "logout"]:
        log.record("admin", action)
    assert log.verify() == (True, None)


def test_edited_audit_entry_is_detected(tmp_path):
    log = AuditLog(str(tmp_path / "audit.db"))
    for action in ["login_success", "prediction", "logout"]:
        log.record("admin", action)
    conn = sqlite3.connect(log.db_name)
    with conn:
        conn.execute("UPDATE audit_log SET actor = 'someone' WHERE id = 2")
    assert log.verify() == (False, 2)


def test_deleted_audit_entry_is_detected(tmp_path):
    log = AuditLog(str(tmp_path / "audit.db"))
    for action in ["a", "b", "c"]:
        log.record("admin", action)
    conn = sqlite3.connect(log.db_name)
    with conn:
        conn.execute("DELETE FROM audit_log WHERE id = 2")
    assert log.verify()[0] is False


def test_simulated_tampering_is_caught(tmp_path):
    log = AuditLog(str(tmp_path / "audit.db"))
    log.record("admin", "login_success")
    log.simulate_tampering()
    assert log.verify() == (False, 1)


# ---------------- Model integrity ----------------
def test_tampered_model_is_detected_and_replaced(workdir):
    import predictor
    predictor.train_model()
    assert predictor.model_status() == "verified"
    with open(predictor.MODEL_PATH, "ab") as f:
        f.write(b"malicious-bytes")
    assert predictor.model_status() == "tampered"
    events = []
    predictor.on_tamper = lambda *a: events.append(a)
    try:
        score = predictor.predict_score(6, 85, 22, 25, 17)
    finally:
        predictor.on_tamper = None
    assert 0 <= score <= 100
    assert predictor.model_status() == "verified"
    assert events and events[0][1] == "model_tampered"


def test_unsigned_model_is_never_loaded(workdir):
    import predictor
    predictor.train_model()
    import os
    os.remove(predictor.SIG_PATH)
    assert predictor.model_status() == "missing"
    predictor.predict_score(6, 85, 22, 25, 17)       # retrains and re-signs
    assert predictor.model_status() == "verified"


def test_explanation_and_model_comparison(workdir):
    import predictor
    contributions, base = predictor.explain(6, 85, 22, 25, 17)
    assert set(contributions) == set(predictor.FEATURES)
    total = base + sum(contributions.values())
    assert abs(total - predictor.predict_score(6, 85, 22, 25, 17)) < 1.0
    table = predictor.compare_models()
    assert list(table["Model"]) == ["Linear Regression", "Random Forest"]


# ---------------- Differential privacy ----------------
def test_dp_mean_is_close_but_noisy():
    rng = np.random.default_rng(0)
    values = rng.uniform(40, 100, 300)
    noisy = [dp_mean(values, 0, 100, 1.0, np.random.default_rng(i)) for i in range(50)]
    assert abs(np.mean(noisy) - values.mean()) < 1.0
    assert len(set(round(v, 6) for v in noisy)) > 1           # noise is really added


def test_dp_histogram_has_no_negative_counts():
    counts, _ = dp_histogram([50, 60, 70], bins=10, epsilon=0.1,
                             rng=np.random.default_rng(1))
    assert (counts >= 0).all()


# ---------------- Anomaly detection ----------------
def test_unusual_inputs_are_flagged(workdir):
    from analysis import load_data
    detector = InputAnomalyDetector(load_data(), ["study_hours", "attendance",
                                                  "internal1", "internal2",
                                                  "assignment"])
    normal = {"study_hours": 5.5, "attendance": 75, "internal1": 19,
              "internal2": 19, "assignment": 14}
    weird = {"study_hours": 24, "attendance": 2, "internal1": 30,
             "internal2": 0, "assignment": 0}
    assert detector.check(normal)[0] is False
    assert detector.check(weird)[0] is True


# ---------------- Rate limiting and CAPTCHA ----------------
def test_rate_limiter_blocks_flooding_then_recovers():
    clock = FakeClock()
    limiter = RateLimiter(max_events=3, window_seconds=60, clock=clock)
    assert all(limiter.allow("s1") for _ in range(3))
    assert not limiter.allow("s1")
    assert limiter.allow("s2")                     # other sessions unaffected
    clock.now += 61
    assert limiter.allow("s1")


def test_captcha():
    question, answer = new_captcha()
    assert "+" in question and captcha_ok(answer, answer)
    assert not captcha_ok("999", answer)
