import os
import shutil
import sys

import base64
import secrets

import pytest

# Test-only keys, made fresh for every run (never real secrets).
os.environ.setdefault("SPP_SECURITY_DATA_KEY",
                      base64.urlsafe_b64encode(os.urandom(32)).decode())
os.environ.setdefault("SPP_SECURITY_AUDIT_KEY", secrets.token_hex(32))
os.environ.setdefault("SPP_SECURITY_MODEL_KEY", secrets.token_hex(32))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    """Run a test inside a temporary folder with a copy of the sample data.
    The real database and data files are never touched."""
    os.makedirs(tmp_path / "data")
    shutil.copy(os.path.join(ROOT, "data", "students.csv"), tmp_path / "data")
    monkeypatch.chdir(tmp_path)
    return tmp_path
