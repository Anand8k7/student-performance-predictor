"""Automated security tests for the Student Performance Predictor.

Run with:  python -m pytest -v
All tests use fake passwords and temporary databases only.
"""
import logging
import os
import sqlite3

import pytest

from models import Student
from database import Database
from auth import (hash_password, verify_password, validate_password_strength,
                  authenticate, load_users, LoginThrottle, GENERIC_FAILURE)

ADMIN_PW = "Test-Admin-Pass-1"
USER_PW = "Test-User-Pass-2"
HEADER = "name,study_hours,attendance,internal1,internal2,assignment,semester_score\n"


@pytest.fixture(scope="module")
def users():
    return load_users({
        "admin": {"password_hash": hash_password(ADMIN_PW), "role": "admin"},
        "student1": {"password_hash": hash_password(USER_PW), "role": "user"},
    })


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


# ---------------- Input validation ----------------
def test_valid_student_is_accepted():
    s = Student("Test User", 6, 85, 22, 25, 17, 78)
    assert s.name == "Test User"


@pytest.mark.parametrize("args, message", [
    (("", 5, 80, 15, 15, 10), "Name cannot be empty"),
    (("A" * 51, 5, 80, 15, 15, 10), "Name must be at most 50 characters"),
    (("Robert'); DROP TABLE students;--", 5, 80, 15, 15, 10), "Name can only contain"),
    ((123, 5, 80, 15, 15, 10), "Name must be text"),
    (("Test", -1, 80, 15, 15, 10), "Study hours must be between 0 and 24"),
    (("Test", 30, 80, 15, 15, 10), "Study hours must be between 0 and 24"),
    (("Test", 5, 101, 15, 15, 10), "Attendance must be between 0 and 100"),
    (("Test", 5, 80, 45, 15, 10), "Internal 1 must be between 0 and 30"),
    (("Test", 5, 80, 15, -2, 10), "Internal 2 must be between 0 and 30"),
    (("Test", 5, 80, 15, 15, 25), "Assignment must be between 0 and 20"),
    (("Test", 5, 80, "abc", 15, 10), "Internal 1 must be a number"),
    (("Test", float("nan"), 80, 15, 15, 10), "Study hours must be a real number"),
    (("Test", 5, True, 15, 15, 10), "Attendance must be a number"),
])
def test_invalid_input_is_rejected(args, message):
    with pytest.raises(ValueError, match=message.replace("(", r"\(").replace(")", r"\)")):
        Student(*args)


# ---------------- Database and SQL injection ----------------
def test_sql_injection_text_is_stored_as_plain_text(tmp_path):
    db = Database(str(tmp_path / "test.db"))
    attack = "Robert'); DROP TABLE students;--"
    conn = sqlite3.connect(db.db_name)
    with conn:
        conn.execute("INSERT INTO students (name) VALUES (?)", (attack,))
    conn.close()
    df = db.get_all()
    assert len(df) == 1 and df.loc[0, "name"] == attack   # table still exists


def test_csv_with_one_bad_row_saves_nothing(tmp_path):
    db = Database(str(tmp_path / "test.db"))
    csv = tmp_path / "bad.csv"
    csv.write_text(HEADER + "Anu,6,85,22,25,17,78\nBad,6,85,45,25,17,78\n")
    with pytest.raises(ValueError, match="Row 3: Internal 1"):
        db.load_csv(str(csv))
    assert len(db.get_all()) == 0


def test_csv_with_attack_name_is_rejected(tmp_path):
    db = Database(str(tmp_path / "test.db"))
    csv = tmp_path / "attack.csv"
    csv.write_text(HEADER + "x' OR '1'='1,6,85,22,25,17,78\n")
    with pytest.raises(ValueError, match="Name can only contain"):
        db.load_csv(str(csv))


def test_real_sample_data_loads(workdir):
    db = Database("test.db")
    db.load_csv("data/students.csv")
    assert len(db.get_all()) == 300


# ---------------- Prediction ----------------
def test_prediction_rejects_bad_input(workdir):
    import predictor
    with pytest.raises(ValueError, match="Internal 1 must be between 0 and 30"):
        predictor.predict_score(6, 85, 45, 25, 17)


def test_prediction_works_for_valid_input(workdir):
    import predictor
    score = predictor.predict_score(6, 85, 22, 25, 17)
    assert 0 <= score <= 100


# ---------------- Password hashing ----------------
def test_password_is_hashed_with_argon2id():
    h = hash_password(ADMIN_PW)
    assert h.startswith("$argon2id$") and ADMIN_PW not in h


def test_same_password_gives_different_hashes():
    assert hash_password(ADMIN_PW) != hash_password(ADMIN_PW)


def test_correct_and_wrong_passwords():
    h = hash_password(ADMIN_PW)
    assert verify_password(ADMIN_PW, h)
    assert not verify_password("wrong-password-1", h)
    assert verify_password(ADMIN_PW, "not-a-hash") is False


@pytest.mark.parametrize("weak", ["Ab1", "OnlyLettersHere", "12345678901234", "A1" * 70])
def test_weak_passwords_are_rejected(weak):
    with pytest.raises(ValueError):
        validate_password_strength(weak)


# ---------------- Login ----------------
def test_login_returns_correct_roles(users):
    assert authenticate("admin", ADMIN_PW, users)[0] == "admin"
    assert authenticate("student1", USER_PW, users)[0] == "user"


def test_wrong_password_and_unknown_user_get_same_message(users):
    wrong = authenticate("admin", "wrong-password-1", users)
    unknown = authenticate("nobody", "wrong-password-1", users)
    assert wrong == unknown == (None, GENERIC_FAILURE)


@pytest.mark.parametrize("username, password", [
    ("", ""), (None, None), ("admin' OR '1'='1", "x' OR '1'='1"),
])
def test_bad_login_input_is_refused(users, username, password):
    assert authenticate(username, password, users)[0] is None


def test_lockout_after_five_failures(users):
    clock = FakeClock()
    throttle = LoginThrottle(max_attempts=5, lockout_seconds=60, clock=clock)
    for _ in range(5):
        authenticate("admin", "wrong-password-1", users, throttle)
    role, message = authenticate("admin", ADMIN_PW, users, throttle)
    assert role is None and message.startswith("Too many failed attempts")
    assert authenticate("student1", USER_PW, users, throttle)[0] == "user"
    clock.now += 61
    assert authenticate("admin", ADMIN_PW, users, throttle)[0] == "admin"


# ---------------- Authorization configuration (fail closed) ----------------
def test_bad_account_settings_are_ignored():
    good = hash_password(USER_PW)
    users = load_users({
        "admin2": {"password_hash": good, "role": "superuser"},   # unknown role
        "weak": {"password_hash": "plain-text", "role": "user"},  # not a hash
        "ok1": {"password_hash": good, "role": "user"},
    })
    assert list(users) == ["ok1"]
    assert load_users({}) == {} and load_users(None) == {}


# ---------------- Logging ----------------
def test_log_has_no_passwords_hashes_or_unknown_usernames(users):
    authenticate("admin", "Secret-Typed-Pass-9", users)
    authenticate("someone-typed-this", ADMIN_PW, users)
    authenticate("admin", ADMIN_PW, users)
    for handler in logging.getLogger("auth").handlers:
        handler.flush()
    path = logging.getLogger("auth").handlers[0].baseFilename
    with open(path) as f:
        log = f.read()
    assert "Secret-Typed-Pass-9" not in log and ADMIN_PW not in log
    assert "$argon2" not in log
    assert "someone-typed-this" not in log
    assert "Failed login" in log and "Login success" in log
