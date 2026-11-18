import math
import re
import threading
import time

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from logger_config import get_logger

logger = get_logger("auth")

ROLE_ADMIN = "admin"
ROLE_USER = "user"
ROLES = (ROLE_ADMIN, ROLE_USER)

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{3,30}$")
PASSWORD_MIN_LENGTH = 10
PASSWORD_MAX_LENGTH = 128

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 60
MAX_TRACKED_USERNAMES = 1000
FORGET_AFTER_SECONDS = 900

# One message for every kind of login failure, so attackers learn nothing.
GENERIC_FAILURE = "Incorrect username or password."

_hasher = PasswordHasher()  # Argon2id with safe default settings
_DUMMY_HASH = _hasher.hash("dummy-password-used-for-timing-1")


def validate_password_strength(password):
    if not isinstance(password, str):
        raise ValueError("Password must be text")
    if len(password) < PASSWORD_MIN_LENGTH:
        raise ValueError(
            f"Password must be at least {PASSWORD_MIN_LENGTH} characters"
        )
    if len(password) > PASSWORD_MAX_LENGTH:
        raise ValueError(
            f"Password must be at most {PASSWORD_MAX_LENGTH} characters"
        )
    has_letter = any(c.isalpha() for c in password)
    has_digit = any(c.isdigit() for c in password)
    if not (has_letter and has_digit):
        raise ValueError("Password must contain at least one letter and one number")
    return password


def hash_password(password):
    validate_password_strength(password)
    return _hasher.hash(password)


def verify_password(password, stored_hash):
    if not isinstance(password, str) or not isinstance(stored_hash, str):
        return False
    if len(password) > PASSWORD_MAX_LENGTH:
        return False
    try:
        return _hasher.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def normalize_username(username):
    if not isinstance(username, str):
        return ""
    return username.strip().lower()[:64]


def safe_for_log(text):
    # Keep only printable characters, so typed text cannot fake log lines.
    return "".join(c for c in str(text)[:30] if c.isprintable())


def load_users(raw_users):
    """Turn configured accounts into a safe dictionary.

    Expected shape:
    {"admin": {"password_hash": "$argon2id$...", "role": "admin"}}
    Any account that is not set up correctly is ignored (fail closed).
    """
    users = {}
    if not hasattr(raw_users, "items"):
        return users
    for name, info in raw_users.items():
        name = str(name)
        if not USERNAME_PATTERN.match(name):
            logger.error("Ignored an account with an invalid username")
            continue
        if not hasattr(info, "get"):
            logger.error("Ignored account '%s': settings are not valid",
                         safe_for_log(name))
            continue
        password_hash = info.get("password_hash")
        role = info.get("role")
        if (not isinstance(password_hash, str)
                or not password_hash.startswith("$argon2id$")):
            logger.error("Ignored account '%s': not a valid Argon2id hash",
                         safe_for_log(name))
            continue
        if role not in ROLES:
            logger.error("Ignored account '%s': invalid role",
                         safe_for_log(name))
            continue
        key = name.lower()
        if key in users:
            logger.error("Ignored account '%s': duplicate username",
                         safe_for_log(name))
            continue
        users[key] = {"password_hash": password_hash, "role": role}
    return users


class LoginThrottle:
    """Locks a username for a short time after too many failed logins."""

    def __init__(self, max_attempts=MAX_FAILED_ATTEMPTS,
                 lockout_seconds=LOCKOUT_SECONDS, clock=time.monotonic):
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self._clock = clock
        self._records = {}
        self._lock = threading.Lock()

    def seconds_locked(self, key):
        with self._lock:
            record = self._records.get(key)
            if record is None or record["locked_until"] == 0.0:
                return 0
            remaining = record["locked_until"] - self._clock()
            if remaining > 0:
                return math.ceil(remaining)
            del self._records[key]
            return 0

    def record_failure(self, key):
        with self._lock:
            now = self._clock()
            record = self._records.setdefault(
                key, {"count": 0, "locked_until": 0.0, "last": now}
            )
            record["count"] += 1
            record["last"] = now
            if record["count"] >= self.max_attempts:
                record["locked_until"] = now + self.lockout_seconds
            self._prune(now)

    def record_success(self, key):
        with self._lock:
            self._records.pop(key, None)

    def _prune(self, now):
        if len(self._records) <= MAX_TRACKED_USERNAMES:
            return
        stale = [k for k, r in self._records.items()
                 if r["locked_until"] == 0.0
                 and now - r["last"] > FORGET_AFTER_SECONDS]
        for k in stale:
            del self._records[k]
        while len(self._records) > MAX_TRACKED_USERNAMES:
            oldest = min(self._records, key=lambda k: self._records[k]["last"])
            del self._records[oldest]


def authenticate(username, password, users, throttle=None):
    """Check a login. Returns (role, message). The role is None on failure."""
    key = normalize_username(username)

    if throttle is not None:
        wait = throttle.seconds_locked(key)
        if wait > 0:
            logger.warning("Login blocked for user '%s' (too many failed attempts)",
                           safe_for_log(key))
            return None, (f"Too many failed attempts. "
                          f"Please wait {wait} seconds and try again.")

    account = users.get(key) if key else None
    if account is None:
        # Do the same slow work as a real check, so timing does not
        # reveal whether the username exists.
        verify_password(password, _DUMMY_HASH)
        ok = False
    else:
        ok = verify_password(password, account["password_hash"])

    if ok:
        if throttle is not None:
            throttle.record_success(key)
        logger.info("Login success for user '%s' (role %s)",
                    safe_for_log(key), account["role"])
        return account["role"], "Login successful."

    if throttle is not None:
        throttle.record_failure(key)
    logger.warning("Failed login for user '%s'", safe_for_log(key))
    return None, GENERIC_FAILURE
