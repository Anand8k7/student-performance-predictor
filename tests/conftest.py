import os
import shutil
import sys

import pytest

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
