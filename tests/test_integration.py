"""Pruebas de integración: motor completo con proveedor offline, filtros,
deduplicación, checkpoints de reanudación, análisis de parámetros y export."""
import asyncio
import json

import pytest

from app.analyzer.param_analyzer import analyze_database
from app.config import AppConfig
from app.search.api_client import OfflineReplayProvider
from app.search.engine import SearchEngine
from app.search.url_filter import UrlFilter, UrlFilterer
from app.storage.database import Database
from app.storage.exporters import export_csv, export_json, export_txt


def make_cfg(tmp_path, domains=("shop.local",)) -> AppConfig:
    cfg = AppConfig()
    cfg.search.provider = "offline"
    cfg.search.authorized_domains = list(domains)
    cfg.search.results_per_page = 10
    cfg.search.max_results_per_dork = 200
    cfg.search.max_api_requests_per_day = 100
    cfg.search.concurrency = 2
    cfg.search.rate_limit_rps = 0  # sin espera en pruebas
    cfg.storage.database = str(tmp_path / "urls.db")
    return cfg


def test_motor_dedup_y_cuota(tmp_path):
    urls = [f"https://shop.local/p.php?id={i}" for i in range(1, 26)]
    urls += [f"https://shop.local/p.php?id={i}" for i in range(11, 36)]  # solapamiento
    db = Database(tmp_path / "urls.db")
    cfg = make_cfg(tmp_path)
    provider = OfflineReplayProvider({"*": urls})
    engine = SearchEngine(cfg, provider, db, UrlFilterer(UrlFilter(allowed_domains={"shop.local"})),
                          batch_size=10)
    stats = asyncio.run(engine.run(["test-dork"]))

    unique = len(set(urls))
    assert db.count() == unique == 35
    assert stats.urls_new == unique
    assert stats.api_requests == 6          # 5 páginas con resultados + 1 que descubre el fin
    assert stats.dorks_completed == 1
    # paginación real del proveedor (la última página vacía marca el final)
    assert provider.calls == [("test-dork", 1), ("test-dork", 11), ("test-dork", 21),
                              ("test-dork", 31), ("test-dork", 41), ("test-dork", 51)]


def test_motor_fuerza_lista_blanca(tmp_path):
    db = Database(tmp_path / "urls.db")
    cfg = make_cfg(tmp_path, domains=())
    cfg.search.allow_unrestricted_search = False
    engine = SearchEngine(cfg, OfflineReplayProvider({}), db, UrlFilterer(UrlFilter()))
    with pytest.raises(RuntimeError):
        asyncio.run(engine.run(["x"]))


def test_motor_filtra_fuera_de_whitelist(tmp_path):
    urls = ["https://shop.local/a?id=1", "https://evil.local/b?id=2",
            "https://shop.local/c?id=3"]
    db = Database(tmp_path / "urls.db")
    cfg = make_cfg(tmp_path)
    engine = SearchEngine(cfg, OfflineReplayProvider({"*": urls}), db,
                          UrlFilterer(UrlFilter(allowed_domains={"shop.local"})))
    asyncio.run(engine.run(["q"]))
    stored = {r["url"] for r in db.iter_urls()}
    assert stored == {"https://shop.local/a?id=1", "https://shop.local/c?id=3"}


def test_reanudacion_desde_checkpoint(tmp_path):
    urls = [f"https://shop.local/p.php?id={i}" for i in range(1, 51)]
    db = Database(tmp_path / "urls.db")
    # checkpoint simulando una interrupción en la página 3
    db.upsert_dork_task("test-dork", "offline", next_start=21, status="running")
    cfg = make_cfg(tmp_path)
    provider = OfflineReplayProvider({"*": urls})
    engine = SearchEngine(cfg, provider, db, UrlFilterer(UrlFilter(allowed_domains={"shop.local"})))
    asyncio.run(engine.run(["test-dork"]))
    assert provider.calls[0] == ("test-dork", 21)          # reanuda donde se quedó
    assert db.count() == 30                                # páginas 3..5
    tasks = db.get_dork_tasks()
    assert tasks[0]["status"] == "done"


def test_pausa_y_parada(tmp_path):
    urls = [f"https://shop.local/p.php?id={i}" for i in range(1, 201)]
    db = Database(tmp_path / "urls.db")
    cfg = make_cfg(tmp_path)

    class SlowProvider(OfflineReplayProvider):
        """Añade latencia para poder detener el motor a mitad de ejecución."""

        async def fetch(self, client, query, start, num):
            await asyncio.sleep(0.03)
            return await super().fetch(client, query, start, num)

    engine = SearchEngine(cfg, SlowProvider({"*": urls}), db,
                          UrlFilterer(UrlFilter(allowed_domains={"shop.local"})))

    async def go():
        task = asyncio.create_task(engine.run(["stop-dork"]))
        await asyncio.sleep(0.10)
        engine.stop()                                       # parada limpia
        return await task

    stats = asyncio.run(go())
    assert stats.api_requests < 20                          # NO recorrió todas las páginas
    assert db.count() < 200
    task_row = db.get_dork_tasks()[0]
    assert task_row["status"] in ("running", "done")        # checkpoint queda guardado


def test_flujo_completo_buscar_analizar_exportar(tmp_path):
    urls = [f"https://shop.local/product.php?id={i}" for i in range(1, 31)]
    db = Database(tmp_path / "urls.db")
    cfg = make_cfg(tmp_path)
    engine = SearchEngine(cfg, OfflineReplayProvider({"*": urls}), db,
                          UrlFilterer(UrlFilter(allowed_domains={"shop.local"})))
    asyncio.run(engine.run(["dork-1"]))

    result = analyze_database(db)
    assert result["analyzed"] == 30
    rows = list(db.iter_urls())
    assert all(r["params_count"] == 1 for r in rows)
    assert all(r["priority"] >= 30 for r in rows)          # id numérico ⇒ prioridad alta
    assert all(r["db_related"] == "id" for r in rows)

    t = export_txt(tmp_path / "u.txt", db.iter_urls())
    c = export_csv(tmp_path / "u.csv", db.iter_urls())
    j = export_json(tmp_path / "u.json", db.iter_urls())
    assert t == c == j == 30
    assert len((tmp_path / "u.txt").read_text().splitlines()) == 30
    data = json.loads((tmp_path / "u.json").read_text())
    assert data[0]["url"].startswith("https://shop.local/product.php?id=")
