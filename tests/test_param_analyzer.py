from app.analyzer.param_analyzer import (
    ParamAnalyzer, analyze_database, priority_label,
)
from app.models import UrlRecord
from app.storage.database import Database


def test_parametro_id_detectado():
    a = ParamAnalyzer().analyze("https://shop.local/product.php?id=42")
    assert "id" in a.db_related
    assert a.category == "parameterized"
    assert a.priority >= 30


def test_parametros_relacionados_bd():
    a = ParamAnalyzer().analyze("https://shop.local/catalogo.php?product=9&category=3")
    assert "product" in a.db_related and "category" in a.db_related
    assert a.priority >= 40


def test_valor_numerico_puntua_mas():
    ana = ParamAnalyzer()
    num = ana.analyze("https://shop.local/p.php?id=42")
    txt = ana.analyze("https://shop.local/p.php?id=abc")
    assert num.priority > txt.priority


def test_ruta_dinamica():
    a = ParamAnalyzer().analyze("https://shop.local/product/123")
    assert a.category == "dynamic_path"
    assert "123" in a.dynamic_path_segments
    assert a.priority > 0


def test_ruta_uuid():
    a = ParamAnalyzer().analyze(
        "https://shop.local/item/550e8400-e29b-41d4-a716-446655440000")
    assert a.category == "dynamic_path"


def test_estatica_cero():
    a = ParamAnalyzer().analyze("https://shop.local/about")
    assert a.category == "static"
    assert a.priority == 0


def test_priorizacion_de_lista():
    ana = ParamAnalyzer()
    urls = [
        "https://shop.local/contacto",
        "https://shop.local/product.php?id=42",
        "https://shop.local/search?q=zapatos",
    ]
    ranked = sorted((ana.analyze(u) for u in urls), key=lambda a: -a.priority)
    assert ranked[0].url.endswith("id=42")
    assert ranked[-1].url.endswith("contacto")


def test_etiquetas_prioridad():
    assert priority_label(70) == "ALTA"
    assert priority_label(40) == "MEDIA"
    assert priority_label(10) == "BAJA"
    assert priority_label(0) == "NULA"


def test_stats_agregadas():
    ana = ParamAnalyzer()
    urls = ["https://s.local/p.php?id=1", "https://s.local/p.php?id=2",
            "https://s.local/about"]
    st = ParamAnalyzer.stats(ana.analyze_batch(urls))
    assert st["total"] == 3
    assert st["parameterized"] == 2
    assert st["static"] == 1
    assert st["top_params"][0][0] == "id"


def test_analyze_database(fresh_db_path):
    db = Database(fresh_db_path)
    db.add_urls([UrlRecord.from_url(u, timestamp="t") for u in [
        "https://shop.local/product.php?id=1",
        "https://shop.local/product.php?id=2",
        "https://shop.local/about",
    ]])
    result = analyze_database(db)
    assert result["analyzed"] == 3
    rows = list(db.iter_urls())
    with_params = [r for r in rows if r["params_count"] > 0]
    assert len(with_params) == 2
    assert all(r["priority"] > 0 for r in with_params)
    assert all(r["analyzed"] == 1 for r in rows)
    # segunda pasada: nada nuevo por analizar
    assert analyze_database(db)["analyzed"] == 0
