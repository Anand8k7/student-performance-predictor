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
    return
