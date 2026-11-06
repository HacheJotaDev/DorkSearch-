import asyncio

import httpx
import pytest

from app.proxies.manager import ProxyManager, ProxyManagerError, ProxyStats


def test_parse_line_formato_oficial():
    e = ProxyManager.parse_line("1.2.3.4:8080:usuario:clave123")
    assert (e.host, e.port, e.user, e.password) == ("1.2.3.4", 8080, "usuario", "clave123")
    assert e.url == "http://usuario:clave123@1.2.3.4:8080"


def test_parse_line_password_con_dos_puntos():
    e = ProxyManager.parse_line("10.0.0.1:3128:usr:cla:ve_secreta")
    assert e.password == "cla:ve_secreta"
    assert e.port == 3128


def test_parse_line_con_esquema():
    e = ProxyManager.parse_line("http://10.0.0.2:8080:u:p")
    assert e.scheme == "http" and e.host == "10.0.0.2"


def test_parse_line_invalido():
    for bad in ("1.2.3.4:abc:u:p", "1.2.3.4:99999:u:p", "1.2.3.4:8080:u", "sinformato"):
        with pytest.raises(ProxyManagerError):
            ProxyManager.parse_line(bad)


def test_mascara_protege_credenciales():
    e = ProxyManager.parse_line("1.2.3.4:8080:usuario:SECRETO")
    masked = e.masked
    assert "SECRETO" not in masked
    assert "usuario" in masked and "***" in masked


def test_carga_fichero(tmp_path):
    f = tmp_path / "proxies.txt"
    f.write_text(
        "# comentario\n"
        "1.1.1.1:8080:u1:p1\n"
        "2.2.2.2:8080:u2:p2\n"
        "linea-mala\n"
        "\n",
        encoding="utf-8",
    )
    pm = ProxyManager.load(f)
    assert len(pm) == 2


def test_rotacion_round_robin():
    pm = ProxyManager(strategy="round_robin")
    for i in range(1, 4):
        pm.entries.append(ProxyManager.parse_line(f"10.0.0.{i}:8080:u:p"))
        pm.stats[id(pm.entries[-1])] = ProxyStats()
    got = [pm.acquire().host for _ in range(3)]
    assert len(set(got)) == 3  # los 3 distintos en la primera vuelta


def test_estrategia_invalida():
    with pytest.raises(ProxyManagerError):
        ProxyManager(strategy="desconocida")


def test_expulsion_tras_fallos_consecutivos():
    pm = ProxyManager(max_consecutive_failures=2, ban_ttl_seconds=60)
    e1 = pm.parse_line("10.0.0.1:8080:u:p")
    e2 = pm.parse_line("10.0.0.2:8080:u:p")
    pm.entries = [e1, e2]
    pm.stats[id(e1)] = ProxyStats()
    pm.stats[id(e2)] = ProxyStats()
    pm.report_failure(e1)
    pm.report_failure(e1, "timeout")
    assert pm.stats[id(e1)].banned_until > 0
    # e1 expulsado: acquire devuelve e2
    assert pm.acquire().host == "10.0.0.2"
    s = pm.summary()
    assert all("p" not in r["proxy"].split(":")[-1] for r in s)


def test_ttl_recupera_el_proxy():
    import time
    pm = ProxyManager(max_consecutive_failures=1, ban_ttl_seconds=0.05)
    e = pm.parse_line("10.0.0.9:8080:u:p")
    pm.entries = [e]
    pm.stats[id(e)] = ProxyStats()
    pm.report_failure(e)
    assert pm.acquire() is None
    time.sleep(0.08)
    assert pm.acquire() is e


def test_estadisticas_por_proxy():
    pm = ProxyManager()
    e = pm.parse_line("10.0.0.5:8080:u:p")
    pm.entries = [e]
    pm.stats[id(e)] = ProxyStats()
    pm.report_success(e, 0.4)
    pm.report_success(e, 0.6)
    pm.report_failure(e)
    s = pm.summary()[0]
    assert s["requests"] == 3 and s["successes"] == 2 and s["failures"] == 1
    assert s["avg_latency"] == 0.5


def test_check_all_con_transport_mock():
    """Verificación asíncrona sin red usando httpx.MockTransport."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"origin": "1.2.3.4"})

    pm = ProxyManager()
    for i in range(3):
        e = pm.parse_line(f"10.1.0.{i}:8080:u:p")
        pm.entries.append(e)
        pm.stats[id(e)] = ProxyStats()
    results = asyncio.run(pm.check_all(transport=httpx.MockTransport(handler)))
    assert len(results) == 3 and all(r["ok"] for r in results)
    assert all("***" in r["proxy"] for r in results)
    summary = pm.summary()
    assert all(s["successes"] == 1 for s in summary)
