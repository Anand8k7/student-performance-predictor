"""Rate limiting (defends against flooding and model-extraction attacks)
and a simple CAPTCHA shown after repeated failed logins."""
import secrets
import threading
import time
from collections import deque

MAX_TRACKED_KEYS = 1000


class RateLimiter:
    def __init__(self, max_events=20, window_seconds=60, clock=time.monotonic):
        self.max_events = max_events
        self.window = window_seconds
        self._clock = clock
        self._events = {}
        self._lock = threading.Lock()

    def allow(self, key):
        with self._lock:
            now = self._clock()
            queue = self._events.setdefault(key, deque())
            while queue and now - queue[0] > self.window:
                queue.popleft()
            if len(queue) >= self.max_events:
                return False
            queue.append(now)
            if len(self._events) > MAX_TRACKED_KEYS:
                for k in [k for k, q in self._events.items() if not q][:100]:
                    del self._events[k]
            return True


def new_captcha():
    rng = secrets.SystemRandom()
    a, b = rng.randint(2, 9), rng.randint(2, 9)
    return f"Security check: what is {a} + {b}?", str(a + b)


def captcha_ok(answer, expected):
    return secrets.compare_digest(str(answer).strip(), str(expected))
