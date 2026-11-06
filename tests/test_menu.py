"""Pruebas del modo consola: menú interactivo (Termux-compatible) y subcomando proxies.

Todo se ejecuta SIN red: el proveedor offline y el modo --no-network garantizan
que la suite no toca ningún servidor externo.
"""
import json
from itertools import chain, repeat
from types import SimpleNamespace

import pytest

import main as cli
from app.config import AppConfig
from app.console_menu import run_menu


def make_cfg(tmp_path) -> AppConfig:
    cfg = AppConfig()
    cfg.search.provider = "offline"
    cfg.search.authorized_domains = ["shop.local"]
    cfg.search.rate_limit_rps = 0          # sin esperas en pruebas
    cfg.search.concurrency = 1
    cfg.storage.database = str(tmp_path / "urls.db")
    cfg.proxies.file = str(tmp_path / "proxies.txt")
    return cfg


def inputter(*answers):
    """input() simulado: respuestas pregrabadas; al agotarse responde '0' (salir)."""
    it = iter(chain(answers, repeat("0")))
    return lambda prompt="": next(it)


def collect(out_lines: list):
    return out_lines.append


# --------------------------------------------------------------------- parser
def test_version_flag(capsys):
    with pytest.raises(SystemExit) as e:
        cli.build_parser().parse_args(["--version"])
    assert e.value.code == 0
    assert "TERMUX" in capsys.readouterr().out.upper()


def test_subcomandos_nuevos_en_el_parser():
    args = cli.build_parser().parse_args(["menu"])
    assert args.cmd == "menu"
    args = cli.build_parser().parse_args(["proxies"])
    assert args.cmd == "proxies" and args.no_network is True   # sin red por defecto
    args = cli.build_parser().parse_args(["proxies", "--check-network"])
    assert args.no_network is False


# ----------------------------------------------------------------------- menú
def test_menu_salida_inmediata(tmp_path):
    out: list = []
    code = run_menu(make_cfg(tmp_path), {}, input_fn=inputter(),
                    print_fn=collect(out), colors=False)
    assert code == 0
    texto = "\n".join(out)
    assert "URLS GOOGLE DORKS SEARCHER" in texto
    assert "Hasta pronto" in texto


def test_menu_opcion_invalida_y_salir(tmp_path):
    out: list = []
    code = run_menu(make_cfg(tmp_path), {}, input_fn=inputter("99"),
                    print_fn=collect(out), colors=False)
    assert code == 0
    assert "no valida" in "\n".join(out)


def test_menu_muestra_configuracion_sin_secretos(tmp_path):
    out: list = []
    run_menu(make_cfg(tmp_path), {}, input_fn=inputter("9"),
             print_fn=collect(out), colors=False)
    texto = "\n".join(out)
    assert "Configuracion activa" in texto
    assert "offline" in texto
    # nunca debe imprimir el VALOR de las credenciales, solo si están definidas
    for var in ("GOOGLE_API_KEY", "GOOGLE_CSE_ID", "SERPAPI_KEY"):
        assert var in texto


def test_menu_search_offline_end_to_end(tmp_path):
    urls = [f"https://shop.local/p.php?id={i}" for i in range(1, 6)]
    fixture = tmp_path / "fixture.json"
    fixture.write_text(json.dumps({"*": urls}), encoding="utf-8")
    out_path = tmp_path / "exports" / "urls.txt"

    out: list = []
    code = run_menu(
        make_cfg(tmp_path),
        {"search": cli.cmd_search, "analyze": cli.cmd_analyze, "export": cli.cmd_export,
         "stats": cli.cmd_stats, "audit": cli.cmd_audit, "lab": cli.cmd_lab,
         "lab-demo": cli.cmd_lab_demo, "proxies": cli.cmd_proxies},
        input_fn=inputter(
            "1",                       # opción búsqueda
            "offline",                 # proveedor
            "",                        # presets (ninguno)
            "site:shop.local inurl:id=",   # dork literal
            "",                        # fichero de dorks
            "shop.local",              # dominios autorizados
            "n",                       # proxies: no
            str(out_path),             # exportar a...
            str(fixture),              # fixture offline
            "0",                       # salir
        ),
        print_fn=collect(out), colors=False)
    assert code == 0
    contenido = out_path.read_text(encoding="utf-8")
    assert "shop.local" in contenido and contenido.count("http") == len(urls)


def test_menu_search_sin_dorks_avisa(tmp_path):
    out: list = []
    run_menu(make_cfg(tmp_path), {"search": cli.cmd_search}, input_fn=inputter(
        "1",            # opción búsqueda
        "offline",      # proveedor
        "", "", "",     # presets, dorks, fichero
        "shop.local",   # dominios
        "n",            # proxies
        "",             # export: no
    ), print_fn=collect(out), colors=False)
    assert "al menos un preset" in "\n".join(out)


def test_menu_search_sin_whitelist_avisa(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg.search.authorized_domains = []       # sin lista blanca en config: debe exigirla
    out: list = []
    run_menu(cfg, {"search": cli.cmd_search}, input_fn=inputter(
        "1",                          # opción búsqueda
        "offline",                    # proveedor
        "", "site:x.com inurl:id=", "",   # presets, dorks, fichero
        "",                           # dominios VACÍO (sin default en config)
        "n",                          # proxies
        "",                           # export
    ), print_fn=collect(out), colors=False)
    assert "OBLIGATORIA" in "\n".join(out)


def test_menu_audit_se_cancela_sin_autorizacion(tmp_path):
    out: list = []
    run_menu(make_cfg(tmp_path), {"audit": cli.cmd_audit}, input_fn=inputter(
        "5",                                  # opción auditoría
        "https://shop.local/p.php?id=1",      # URL objetivo
        "shop.local",                         # dominios
        "no",                                 # confirmación: NO autoriza
        "0",                                  # salir
    ), print_fn=collect(out), colors=False)
    texto = "\n".join(out)
    assert "Cancelado" in texto
    assert "sin autorizacion expresa" in texto


# -------------------------------------------------------------------- proxies
def test_cmd_proxies_sin_red_valida_formato(tmp_path, capsys):
    pf = tmp_path / "proxies.txt"
    pf.write_text(
        "# comentario\n"
        "127.0.0.1:8888:user1:pass1\n"
        "http://192.0.2.10:3128:user2:pass2\n"
        "linea-invalida\n",
        encoding="utf-8")
    cfg = make_cfg(tmp_path)
    code = cli.cmd_proxies(SimpleNamespace(no_network=True), cfg)
    assert code == 0
    texto = capsys.readouterr().out
    assert "Proxies cargados" in texto and ": 2" in texto
    assert "Modo sin red" in texto
    # credenciales nunca en claro
    assert "pass1" not in texto and "pass2" not in texto


def test_cmd_proxies_fichero_inexistente(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg.proxies.file = str(tmp_path / "no-existe.txt")
    with pytest.raises(SystemExit):
        cli.cmd_proxies(SimpleNamespace(no_network=True), cfg)


def test_cmd_proxies_fichero_vacio(tmp_path, capsys):
    pf = tmp_path / "proxies.txt"
    pf.write_text("# solo comentarios\n", encoding="utf-8")
    cfg = make_cfg(tmp_path)
    code = cli.cmd_proxies(SimpleNamespace(no_network=True), cfg)
    assert code == 0
    assert "0 proxies" in capsys.readouterr().out
