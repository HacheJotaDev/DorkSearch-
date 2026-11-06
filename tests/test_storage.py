import json

from app.models import Finding, UrlRecord
from app.storage.database import Database, utcnow


def make_db(tmp_path):
    return Database(tmp_path / "test.db")


def test_deduplicacion_por_url(tmp_path):
    db = make_db(tmp_path)
    rec = UrlRecord.from_url("https://shop.local/p.php?id=1", timestamp="t")
    assert db.add_urls([rec]) == 1
    assert db.add_urls([rec]) == 0          # INSERT OR IGNORE: 0 nuevas
    assert db.count() == 1


def test_insercion_por_lotes(tmp_path):
    db = make_db(tmp_path)
    recs = [UrlRecord.from_url(f"https://shop.local/p.php?id={i}", timestamp="t")
            for i in range(1200)]
    assert db.add_urls(recs, batch_size=200) == 1200
    assert db.count() == 1200


def test_iter_keyset_sin_perdidas_ni_duplicados(tmp_path):
    db = make_db(tmp_path)
    recs = [UrlRecord.from_url(f"https://shop.local/p.php?id={i}", timestamp="t")
            for i in range(1050)]
    db.add_urls(recs, batch_size=100)
    got = [r["url"] for r in db.iter_urls(batch=128)]
    assert len(got) == 1050
    assert len(set(got)) == 1050


def test_filtros_iter(tmp_path):
    db = make_db(tmp_path)
    db.add_urls([
        UrlRecord.from_url("https://a.local/p.php?id=1", timestamp="t"),
        UrlRecord.from_url("https://b.local/img.png", timestamp="t"),
        UrlRecord.from_url("https://a.local/p.php?id=2", timestamp="t"),
    ])
    a_rows = list(db.iter_urls(domain="a.local"))
    assert len(a_rows) == 2
    png = list(db.iter_urls(ext="png"))
    assert len(png) == 1
    with_params = list(db.iter_urls(has_params=True))
    assert len(with_params) == 2
    hp = list(db.iter_urls(min_priority=60))
    assert hp == []


def test_dork_tasks_checkpoint(tmp_path):
    db = make_db(tmp_path)
    db.upsert_dork_task("site:a.com inurl:id=", "offline", next_start=1, status="running")
    db.upsert_dork_task("site:a.com inurl:id=", next_start=11, add_results=10)
    t = db.get_dork_tasks()[0]
    assert t["next_start"] == 11 and t["results"] == 10 and t["status"] == "running"
    db.upsert_dork_task("site:a.com inurl:id=", status="done")
    assert db.count_dork_tasks("done") == 1
    assert db.pending_dorks() == []


def test_quota_diaria(tmp_path):
    db = make_db(tmp_path)
    assert db.quota_used_today() == 0
    db.quota_add()
    db.quota_add(3)
    assert db.quota_used_today() == 4
    assert db.quota_key().startswith("quota:")


def test_meta_roundtrip(tmp_path):
    db = make_db(tmp_path)
    db.meta_set("k", "v1")
    db.meta_set("k", "v2")
    assert db.meta_get("k") == "v2"
    assert db.meta_get("no", "def") == "def"


def test_findings_roundtrip(tmp_path):
    db = make_db(tmp_path)
    f = Finding(
        url="https://shop.local/p.php?id=1%27", param="id", technique="error",
        dbms="SQLite", evidence="CONFIRMED", evidence_level=40,
        details="error visible", request_snapshot={"status": 500, "length": 120},
        evidence_snippets=["unrecognized token"], remediation=["usar parametrizadas"],
        timestamp=utcnow(),
    )
    db.add_findings([f])
    rows = db.list_findings()
    assert len(rows) == 1
    r = rows[0]
    assert r["evidence"] == "CONFIRMED" and r["param"] == "id"
    assert r["request_json"]["status"] == 500
    assert r["snippets"] == ["unrecognized token"]


def test_stats(tmp_path):
    db = make_db(tmp_path)
    db.add_urls([UrlRecord.from_url("https://a.local/p.php?id=1", timestamp="t")])
    s = db.stats()
    assert s["total_urls"] == 1 and s["unique_domains"] == 1
    assert "quota_used_today" in s and "top_domains" in s


def test_persistencia_reabrir(tmp_path):
    p = tmp_path / "persist.db"
    db1 = Database(p)
    db1.add_urls([UrlRecord.from_url("https://a.local/x", timestamp="t")])
    db1.close()
    db2 = Database(p)
    assert db2.count() == 1
