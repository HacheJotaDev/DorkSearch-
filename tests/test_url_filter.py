from app.search.url_filter import UrlFilter, UrlFilterer


def make(**kw):
    return UrlFilterer(UrlFilter(**kw))


def test_lista_blanca_obligatoria():
    f = make(allowed_domains={"example.com"})
    ok, reason = f.check("https://sub.example.com/a/product.php?id=1")
    assert ok
    ok, reason = f.check("https://evil.com/product.php?id=1")
    assert not ok and reason == "fuera-de-whitelist"


def test_subdominios_pertenecen_a_la_whitelist():
    f = make(allowed_domains={"example.com"})
    ok, _ = f.check("https://deep.sub.example.com/x")
    assert ok


def test_esquema_no_http_bloqueado():
    f = make(allowed_domains={"example.com"})
    ok, reason = f.check("ftp://example.com/f.txt")
    assert not ok and reason == "esquema-no-http"


def test_dominio_bloqueado():
    f = make(allowed_domains={"example.com"}, blocked_domains={"img.example.com"})
    ok, reason = f.check("https://img.example.com/a.png")
    assert not ok and reason == "dominio-bloqueado"


def test_extension_bloqueada_y_permitida():
    f = make(allowed_domains={"example.com"}, blocked_extensions={"pdf"})
    ok, reason = f.check("https://example.com/doc.pdf")
    assert not ok and reason == "extension-bloqueada"
    f2 = make(allowed_domains={"example.com"}, allowed_extensions={"php"})
    ok, reason = f2.check("https://example.com/p.php?id=1")
    assert ok
    ok, reason = f2.check("https://example.com/p.css")
    assert not ok and reason == "extension-no-permitida"


def test_requiere_parametros():
    f = make(allowed_domains={"example.com"}, require_params=True)
    ok, reason = f.check("https://example.com/about")
    assert not ok and reason == "sin-parametros"
    ok, _ = f.check("https://example.com/p.php?id=1")
    assert ok


def test_parametro_requerido():
    f = make(allowed_domains={"example.com"}, param_name_include=["id", "item"])
    ok, reason = f.check("https://example.com/p.php?ref=9")
    assert not ok and reason == "parametro-requerido-ausente"
    ok, _ = f.check("https://example.com/p.php?id=9")
    assert ok


def test_regex_include_exclude():
    f = make(allowed_domains={"example.com"}, url_regex_include=r"\.php\?")
    ok, _ = f.check("https://example.com/a.php?id=1")
    assert ok
    ok, reason = f.check("https://example.com/a.html")
    assert not ok and reason == "regex-no-incluida"
    f2 = make(allowed_domains={"example.com"}, url_regex_exclude=r"logout")
    ok, reason = f2.check("https://example.com/a.php?id=1&logout=1")
    assert not ok and reason == "regex-excluida"


def test_filtro_por_ruta():
    f = make(allowed_domains={"example.com"}, path_include=["shop"], path_exclude=["admin"])
    ok, reason = f.check("https://example.com/user/profile")
    assert not ok and reason == "ruta-no-incluida"
    ok, reason = f.check("https://example.com/shop/admin")
    assert not ok and reason == "ruta-excluida"
    ok, _ = f.check("https://example.com/shop/item?id=3")
    assert ok


def test_filter_batch():
    f = make(allowed_domains={"example.com"})
    out = f.filter_batch([
        "https://example.com/a?id=1",
        "https://other.com/b?id=2",
        "https://example.com/c",
    ])
    # solo se descarta la URL fuera de la lista blanca
    assert out == ["https://example.com/a?id=1", "https://example.com/c"]
