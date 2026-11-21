"""Two-factor login with time-based one-time passwords (TOTP, RFC 6238).
Works with Google Authenticator, Microsoft Authenticator, Authy, etc."""
import base64
import hashlib
import hmac
import re
import struct
import threading
import time

DIGITS = 6
PERIOD = 30          # seconds per code
WINDOW = 1           # also accept the previous/next code (clock drift)
SECRET_PATTERN = re.compile(r"^[A-Z2-7]{16,64}$")
CODE_PATTERN = re.compile(r"^\d{6}$")


def valid_secret(secret):
    return isinstance(secret, str) and bool(SECRET_PATTERN.match(secret))


def _decode(secret):
    return base64.b32decode(secret + "=" * (-len(secret) % 8))


def totp_at(secret, step, digits=DIGITS):
    digest = hmac.new(_decode(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % (10 ** digits)).zfill(digits)


def current_step(now=None):
    return int((time.time() if now is None else now) // PERIOD)


class TOTPVerifier:
    """Checks 6-digit codes and refuses a code that was already used (replay)."""

    def __init__(self):
        self._last_step = {}
        self._lock = threading.Lock()

    def verify(self, username, secret, code, now=None):
        if not valid_secret(secret):
            return False
        code = str(code or "").replace(" ", "").strip()
        if not CODE_PATTERN.match(code):
            return False
        step = current_step(now)
        for candidate in range(step - WINDOW, step + WINDOW + 1):
            if hmac.compare_digest(totp_at(secret, candidate), code):
                with self._lock:
                    if candidate <= self._last_step.get(username, -1):
                        return False          # replayed code
                    self._last_step[username] = candidate
                return True
        return False


def provisioning_uri(username, secret, issuer="StudentPredictor"):
    return (f"otpauth://totp/{issuer}:{username}?secret={secret}"
            f"&issuer={issuer}&digits={DIGITS}&period={PERIOD}")
