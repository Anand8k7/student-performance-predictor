"""Tamper-evident audit log: every entry is chained to the previous one with
HMAC-SHA256 (like a blockchain). Changing or deleting any entry breaks the chain."""
import sqlite3
from datetime import datetime, timezone

import pandas as pd

from secure_crypto import hmac_sha256

GENESIS = "0" * 64


def _clean(text, limit=60):
    return "".join(c for c in str(text)[:limit] if c.isprintable())


class AuditLog:
    def __init__(self, db_name="students.db"):
        self.db_name = db_name
        conn = sqlite3.connect(self.db_name)
        try:
            with conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        action TEXT NOT NULL,
                        detail TEXT NOT NULL,
                        prev_hash TEXT NOT NULL,
                        hash TEXT NOT NULL
                    )
                """)
        finally:
            conn.close()

    @staticmethod
    def _seal(prev, ts, actor, action, detail):
        payload = f"{prev}|{ts}|{actor}|{action}|{detail}".encode()
        return hmac_sha256("audit_key", payload)

    def record(self, actor, action, detail=""):
        actor, action, detail = _clean(actor), _clean(action), _clean(detail, 120)
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        conn = sqlite3.connect(self.db_name, isolation_level=None)
        try:
            conn.execute("BEGIN IMMEDIATE")   # one writer at a time keeps one chain
            row = conn.execute(
                "SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev = row[0] if row else GENESIS
            conn.execute(
                "INSERT INTO audit_log (ts, actor, action, detail, prev_hash, hash) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (ts, actor, action, detail, prev,
                 self._seal(prev, ts, actor, action, detail)))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def verify(self):
        """Return (True, None) if intact, else (False, id of the first bad entry)."""
        conn = sqlite3.connect(self.db_name)
        try:
            rows = conn.execute(
                "SELECT id, ts, actor, action, detail, prev_hash, hash "
                "FROM audit_log ORDER BY id").fetchall()
        finally:
            conn.close()
        prev = GENESIS
        expected_id = rows[0][0] if rows else None
        for entry_id, ts, actor, action, detail, prev_hash, stored in rows:
            if entry_id != expected_id or prev_hash != prev:
                return False, entry_id          # an entry was deleted or moved
            if self._seal(prev, ts, actor, action, detail) != stored:
                return False, entry_id          # an entry was edited
            prev = stored
            expected_id += 1
        return True, None

    def entries(self, limit=50):
        conn = sqlite3.connect(self.db_name)
        try:
            return pd.read_sql(
                "SELECT id, ts, actor, action, detail, substr(hash, 1, 12) AS hash "
                "FROM audit_log ORDER BY id DESC LIMIT ?", conn, params=(int(limit),))
        finally:
            conn.close()

    def counts(self):
        conn = sqlite3.connect(self.db_name)
        try:
            return dict(conn.execute(
                "SELECT action, COUNT(*) FROM audit_log GROUP BY action").fetchall())
        finally:
            conn.close()

    def simulate_tampering(self):
        """DEMO ONLY: edits one stored entry the way an attacker with database
        access would, so the dashboard can show the chain catching it."""
        conn = sqlite3.connect(self.db_name)
        try:
            with conn:
                conn.execute(
                    "UPDATE audit_log SET detail = ? WHERE id = "
                    "(SELECT MIN(id) FROM audit_log)", ("edited by attacker",))
        finally:
            conn.close()
