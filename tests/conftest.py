import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.sqli.lab.lab_server import LabServer  # noqa: E402


@pytest.fixture(scope="session")
def lab_server(tmp_path_factory):
    """Laboratorio SQLi local real (127.0.0.1) con datos ficticios."""
    db = tmp_path_factory.mktemp("lab") / "lab.db"
    lab = LabServer(port=0, db_path=str(db))
    lab.start()
    yield lab
    lab.stop()


@pytest.fixture()
def fresh_db_path(tmp_path):
    return tmp_path / "test.db"
