"""Encryption at rest (Fernet = AES-128-CBC + HMAC-SHA256) and HMAC signing."""
import hashlib
import hmac

from cryptography.fernet import Fernet, InvalidToken

from keys import get_secret

MIN_HMAC_KEY_LENGTH = 32


class MissingKeyError(RuntimeError):
    pass


def _require(name):
    value = get_secret("security", name)
    if not value:
        raise MissingKeyError(f"Security key '{name}' is not configured")
    return value


def get_cipher():
    return Fernet(_require("data_key").encode())


def encrypt_text(cipher, text):
    return cipher.encrypt(str(text).encode()).decode()


def decrypt_text(cipher, token):
    try:
        return cipher.decrypt(str(token).encode()).decode()
    except (InvalidToken, ValueError, TypeError):
        return "[unreadable]"


def hmac_sha256(key_name, data):
    key = _require(key_name).encode()
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def hmac_matches(key_name, data, expected):
    # compare_digest takes the same time for every input (no timing leak)
    return hmac.compare_digest(hmac_sha256(key_name, data), str(expected))


def check_keys():
    """Return the names of keys that are missing or too weak (empty = all good)."""
    problems = []
    try:
        get_cipher()
    except Exception:
        problems.append("data_key")
    for name in ("audit_key", "model_key"):
        value = get_secret("security", name)
        if not value or len(value) < MIN_HMAC_KEY_LENGTH:
            problems.append(name)
    return problems
