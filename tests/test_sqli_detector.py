import asyncio

import httpx
import pytest

from app.sqli.detector import SqliDetector
from app.sqli.scope import ScopeGuard, ScopeViolation


def run(coro):
    return asyncio.run(coro)


def detector(lab_server, allowed=("127.0.0.1",), **kw):
    client = httpx.AsyncClient(timeout=10, follow_redirects=True)
    return client, SqliDetector(client, ScopeGuard(list(allowed)), **kw)


def test_detecta_error_en_endpoint_vulnerable(lab_server):
    async def go():
        client, d = detector(lab_server)
        try:
            return await d.audit_url(f"{lab_server.base_url}/vulnerable/product?id=1")
        finally:
            await client.aclose()

    findings = run(go())
    assert findings, "debe detectar el endpoint vulnerable"
    f = findings[0]
    assert f.param == "id"
    assert f.technique == "error"
    assert f.evidence in ("CONFIRMED", "LIKELY")
    assert f.dbms in ("SQLite", "JDBC/ODBC genérico")
    assert f.evidence_snippets
    assert any("parametrizada" in r.lower() for r in f.remediation)
    assert f.request_snapshot["url"]  # reproducibilidad: snapshot guardado


def test_endpoint_corregido_sin_hallazgos(lab_server):
    async def go():
        client, d = detector(lab_server)
        try:
            return await d.audit_url(f"{lab_server.base_url}/fixed/product?id=1")
        finally:
            await client.aclose()

    findings = run(go())
    assert findings == [], "el endpoint parametrizado NO debe marcarse como vulnerable"


def test_endpoint_corregido_search_sin_hallazgos(lab_server):
    async def go():
        client, d = detector(lab_server)
        try:
            return await d.audit_url(f"{lab_server.base_url}/fixed/search?q=teclado")
        finally:
            await client.aclose()

    assert run(go()) == []


def test_scope_violation_bloquea_peticion(lab_server):
    async def go():
        client, d = detector(lab_server, allowed=("example.com",))
        try:
            await d.audit_url(f"{lab_server.base_url}/vulnerable/product?id=1")
        finally:
            await client.aclose()

    with pytest.raises(ScopeViolation):
        run(go())


def test_is_allowed_reglas(lab_server):
    g = ScopeGuard(["127.0.0.1", "lab.local"])
    assert g.is_allowed(f"{lab_server.base_url}/vulnerable/product?id=1")
    assert g.is_allowed("http://sub.lab.local/a")
    assert not g.is_allowed("http://evil.local/a")
    assert not g.is_allowed("ftp://127.0.0.1/a")


def test_limite_de_peticiones(lab_server):
    async def go():
        client, d = detector(lab_server, max_requests_total=1)
        try:
            await d.audit_url(f"{lab_server.base_url}/vulnerable/search?q=a")
        finally:
            await client.aclose()

    with pytest.raises(RuntimeError):
        run(go())


def test_registro_de_peticiones_para_reproducibilidad(lab_server):
    async def go():
        logged = []

        def sink(**kw):
            logged.append(kw)

        client = httpx.AsyncClient(timeout=10)
        d = SqliDetector(client, ScopeGuard(["127.0.0.1"]), log_sink=sink)
        try:
            await d.audit_url(f"{lab_server.base_url}/vulnerable/product?id=1")
        finally:
            await client.aclose()
        return logged

    logged = run(go())
    assert logged, "cada petición debe quedar registrada"
    assert any(e["note"] == "baseline" for e in logged)
    assert any(str(e["note"]).startswith("probe-error") for e in logged)
    assert all(e.get("status_code") for e in logged)


def test_inject_parametros(lab_server):
    d = None
    client = httpx.AsyncClient()
    d = SqliDetector(client, ScopeGuard(["127.0.0.1"]))
    out = d._inject("http://h.local/p.php?id=1&cat=2", "id", "1'")
    assert "id=1%27" in out and "cat=2" in out
    out2 = d._inject("http://h.local/p.php", "id", "1")
    assert "id=1" in out2
    asyncio.get_event_loop_policy()
    run(client.aclose())
