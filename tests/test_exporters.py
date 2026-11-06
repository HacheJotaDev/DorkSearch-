import csv
import json

from app.models import UrlRecord
from app.storage.database import Database
from app.storage.exporters import export_auto, export_csv, export_json, export_txt


def sample_rows(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    db.add_urls([
        UrlRecord.from_url("https://shop.local/product.php?id=1", dork="d1", timestamp="t1"),
        UrlRecord.from_url("https://shop.local/product.php?id=2", dork="d1", timestamp="t1"),
        UrlRecord.from_url("https://shop.local/about", dork="d2", timestamp="t1"),
    ])
    return db, db.iter_urls()


def test_export_txt(tmp_path):
    db, rows = sample_rows(tmp_path)
    out = tmp_path / "urls.txt"
    n = export_txt(out, rows)
    assert n == 3
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "https://shop.local/product.php?id=1"
    assert len(lines) == 3


def test_export_csv(tmp_path):
    db, rows = sample_rows(tmp_path)
    out = tmp_path / "urls.csv"
    n = export_csv(out, rows)
    assert n == 3
    with open(out, encoding="utf-8") as f:
        r = list(csv.DictReader(f))
    assert len(r) == 3
    assert r[0]["url"].startswith("https://")
    assert "domain" in r[0] and "priority" in r[0]


def test_export_json(tmp_path):
    db, rows = sample_rows(tmp_path)
    out = tmp_path / "urls.json"
    n = export_json(out, rows)
    assert n == 3
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data) == 3
    assert data[0]["url"].startswith("https://")


def test_export_auto_por_extension(tmp_path):
    db, rows = sample_rows(tmp_path)
    assert export_auto(tmp_path / "a.txt", db.iter_urls()) == 3
    assert export_auto(tmp_path / "a.csv", db.iter_urls()) == 3
    assert export_auto(tmp_path / "a.json", db.iter_urls()) == 3
    import pytest
    with pytest.raises(ValueError):
        export_auto(tmp_path / "a.xml", db.iter_urls())
