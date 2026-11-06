"""Menú interactivo de consola (100% terminal, sin dependencias externas).

Diseñado para funcionar en cualquier terminal: Linux, Windows, macOS y
Termux/Android. No usa curses ni librerías externas: solo input()/print()
y códigos ANSI (con degradación automática a texto plano).

La GUI PySide6 es OPCIONAL: este menú da acceso a TODAS las funciones del
programa desde la consola, incluido Termux donde PySide6 no está soportado.

Cada opción construye los mismos argumentos que los subcomandos de main.py
y delega en los mismos manejadores, por lo que consola y CLI comparten toda
la lógica (lista blanca, cuota, no-destructividad, etc.).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Callable

Handler = Callable[[SimpleNamespace, object], int]
IOIn = Callable[[str], str]
IOOut = Callable[[str], object]

VERSION = "1.1.0"

MENU = """
  1) Busqueda masiva de URLs con dorks
  2) Analizar / priorizar URLs almacenadas
  3) Exportar URLs (TXT / CSV / JSON)
  4) Estadisticas de la base de datos
  5) Auditoria SQLi de una URL (no destructiva)
  6) Iniciar laboratorio SQLi local
  7) Demo completa (laboratorio + auditoria + informe)
  8) Comprobar proxies residenciales (proxies.txt)
  9) Ver configuracion activa
  0) Salir
"""

_SI = {"s", "si", "sí", "y", "yes", "1"}


class Palette:
    """Colores ANSI con degradación automática (NO_COLOR / salida no TTY)."""

    def __init__(self, enabled: bool = True) -> None:
        self.on = enabled

    def _c(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.on else text

    def title(self, t: str) -> str:
        return self._c("1;36", t)

    def ok(self, t: str) -> str:
        return self._c("32", t)

    def warn(self, t: str) -> str:
        return self._c("33", t)

    def err(self, t: str) -> str:
        return self._c("1;31", t)

    def info(self, t: str) -> str:
        return self._c("2", t)


def colors_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def is_termux() -> bool:
    return bool(os.environ.get("TERMUX_VERSION"))


# --------------------------------------------------------------- helpers I/O
def _ask(input_fn: IOIn, prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    val = input_fn(f"  {prompt}{suffix}: ").strip()
    return val or default


def _ask_yes(input_fn: IOIn, prompt: str, default: str = "n") -> bool:
    return _ask(input_fn, f"{prompt} (s/n)", default).lower() in _SI


def _ask_int(input_fn: IOIn, prompt: str, default: int | None = None) -> int | None:
    raw = _ask(input_fn, prompt, "" if default is None else str(default))
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _ask_list(input_fn: IOIn, prompt: str, default: str = "") -> list[str]:
    raw = _ask(input_fn, prompt, default)
    return [x.strip().lower() for x in raw.replace(";", ",").split(",") if x.strip()]


def _ns(**kw) -> SimpleNamespace:
    base = {"db": None}
    base.update(kw)
    return SimpleNamespace(**base)


# ------------------------------------------------------------------- banner
def banner(p: Palette) -> str:
    lines = [
        "",
        "=" * 62,
        p.title("  URLS GOOGLE DORKS SEARCHER - MODO CONSOLA  v" + VERSION),
        "  Advanced URL Discovery & SQLi Security Auditor",
        "=" * 62,
        p.warn("  Uso responsable: SOLO objetivos con AUTORIZACION expresa."),
    ]
    if is_termux():
        lines.append(p.info("  Entorno Termux detectado: modo consola activo "
                            "(la GUI PySide6 no esta soportada en Android)."))
    return "\n".join(lines)


# ----------------------------------------------------------------- opciones
def menu_search(cfg, handlers: dict[str, Handler], input_fn: IOIn, print_fn: IOOut,
                p: Palette) -> None:
    print_fn(p.title("\n[1] Busqueda masiva de URLs con dorks"))
    provider = _ask(input_fn, "Proveedor (google_cse / serpapi / offline)",
                    getattr(cfg.search, "provider", "google_cse")).lower()
    presets = _ask_list(input_fn,
                        "Presets separados por coma (ver 'main.py search --list-presets')", "")
    dorks = _ask_list(input_fn,
                      "Dorks literales separados por coma, p.ej. 'site:dom.com inurl:id='", "")
    dorks_file = _ask(input_fn, "Fichero de dorks (uno por linea, opcional)", "")
    if not (presets or dorks or dorks_file):
        print_fn(p.err("Necesitas al menos un preset, dork o fichero de dorks."))
        return
    domains = _ask_list(input_fn, "Dominios AUTORIZADOS separados por coma",
                        ",".join(cfg.search.authorized_domains))
    if not domains:
        print_fn(p.err("Lista blanca OBLIGATORIA: indica al menos un dominio autorizado."))
        return
    use_proxies = _ask_yes(input_fn, "Activar rotacion de proxies (solo rate limits)")
    out = _ask(input_fn, "Exportar al terminar (.txt/.csv/.json, vacio = no)", "")
    offline_fixture = None
    if provider == "offline":
        fx = _ask(input_fn, "Fixture JSON para el proveedor offline (opcional)", "")
        offline_fixture = fx or None

    print_fn(p.warn("  >> Confirma que TODOS los dominios estan autorizados "
                    "por su propietario antes de continuar."))
    ns = _ns(dorks_file=dorks_file or None, preset=presets or None, dork=dorks or None,
             list_presets=False, domain=domains, provider=provider or None,
             out=out or None, use_proxies=use_proxies, offline_fixture=offline_fixture)
    handlers["search"](ns, cfg)


def menu_analyze(cfg, handlers: dict[str, Handler], input_fn: IOIn, print_fn: IOOut,
                 p: Palette) -> None:
    print_fn(p.title("\n[2] Analizar / priorizar URLs almacenadas"))
    handlers["analyze"](_ns(), cfg)


def menu_export(cfg, handlers: dict[str, Handler], input_fn: IOIn, print_fn: IOOut,
                p: Palette) -> None:
    print_fn(p.title("\n[3] Exportar URLs"))
    out = _ask(input_fn, "Fichero de salida (.txt/.csv/.json)", "exports/urls.txt")
    if not out:
        print_fn(p.err("Indica un fichero de salida."))
        return
    parent = Path(out).parent
    if str(parent) not in ("", "."):
        parent.mkdir(parents=True, exist_ok=True)
    domain_filter = _ask(input_fn, "Filtrar por dominio (opcional)", "") or None
    ext = _ask(input_fn, "Filtrar por extension, p.ej. 'php' (opcional)", "") or None
    has_params = _ask_yes(input_fn, "Solo URLs con parametros GET")
    min_priority = _ask_int(input_fn, "Prioridad minima 0-100 (vacio = todas)")
    ns = _ns(out=out, domain_filter=domain_filter, ext=ext,
             has_params=has_params, min_priority=min_priority)
    handlers["export"](ns, cfg)


def menu_stats(cfg, handlers: dict[str, Handler], input_fn: IOIn, print_fn: IOOut,
               p: Palette) -> None:
    print_fn(p.title("\n[4] Estadisticas de la base de datos"))
    handlers["stats"](_ns(), cfg)


def menu_audit(cfg, handlers: dict[str, Handler], input_fn: IOIn, print_fn: IOOut,
               p: Palette) -> None:
    print_fn(p.title("\n[5] Auditoria SQLi NO destructiva de una URL"))
    url = _ask(input_fn, "URL objetivo (debe pertenecer a un dominio autorizado)", "")
    if not url:
        print_fn(p.err("Indica la URL a auditar."))
        return
    domains = _ask_list(input_fn, "Dominios AUTORIZADOS separados por coma",
                        ",".join(cfg.sqli.allowed_domains))
    confirm = _ask(input_fn, "Escribe SI para confirmar autorizacion expresa del propietario", "")
    if confirm.upper() not in ("SI", "SÍ"):
        print_fn(p.warn("Cancelado: sin autorizacion expresa no se audita ningun objetivo."))
        return
    handlers["audit"](_ns(url=url, domain=domains), cfg)


def menu_lab(cfg, handlers: dict[str, Handler], input_fn: IOIn, print_fn: IOOut,
             p: Palette) -> None:
    print_fn(p.title("\n[6] Laboratorio SQLi local (datos ficticios, 127.0.0.1)"))
    port = _ask_int(input_fn, "Puerto (0 = efimero)", 0) or 0
    handlers["lab"](_ns(port=port, lab_db="data/lab.db"), cfg)


def menu_lab_demo(cfg, handlers: dict[str, Handler], input_fn: IOIn, print_fn: IOOut,
                  p: Palette) -> None:
    print_fn(p.title("\n[7] Demo completa: laboratorio + auditoria + informe ejemplo"))
    handlers["lab-demo"](_ns(port=0, lab_db="data/lab.db"), cfg)


def menu_proxies(cfg, handlers: dict[str, Handler], input_fn: IOIn, print_fn: IOOut,
                 p: Palette) -> None:
    print_fn(p.title("\n[8] Comprobar proxies residenciales"))
    print_fn(p.info("  Formato esperado: IP:PORT:USER:PASSWORD  (credenciales nunca "
                    "se muestran en claro)"))
    network = _ask_yes(input_fn, "Probar conectividad real de cada proxy")
    handlers["proxies"](_ns(no_network=not network), cfg)


def menu_config(cfg, handlers: dict[str, Handler], input_fn: IOIn, print_fn: IOOut,
                p: Palette) -> None:
    print_fn(p.title("\n[9] Configuracion activa"))
    s, pr, sq, st = cfg.search, cfg.proxies, cfg.sqli, cfg.storage
    print_fn(f"  Proveedor de busqueda : {s.provider}")
    print_fn(f"  Dominios autorizados  : {', '.join(s.authorized_domains) or '(ninguno)'}")
    print_fn(f"  Busqueda sin restriccion: {'SI (no recomendado)' if s.allow_unrestricted_search else 'no'}")
    print_fn(f"  Max resultados/dork   : {s.max_results_per_dork} | total: {s.max_total_results} "
             f"| cuota API/dia: {s.max_api_requests_per_day}")
    print_fn(f"  Rate limit            : {s.rate_limit_rps} rps | concurrencia: {s.concurrency}")
    print_fn(f"  Fichero de proxies    : {pr.file} | estrategia: {pr.strategy}")
    print_fn(f"  SQLi dominios         : {', '.join(sq.allowed_domains) or '(ninguno)'}")
    print_fn(f"  SQLi tecnicas         : {', '.join(sq.techniques)} (no destructivas)")
    print_fn(f"  Base de datos         : {st.database}")
    print_fn("  Variables de entorno (solo se indica si estan definidas, nunca su valor):")
    for var in ("GOOGLE_API_KEY", "GOOGLE_CSE_ID", "SERPAPI_KEY"):
        estado = p.ok("definida") if os.environ.get(var) else p.err("NO definida")
        print_fn(f"    {var:15s}: {estado}")
    if is_termux():
        print_fn(p.info("  Termux: usa proveedor 'offline' o APIs sin bloqueo por region; "
                        "la GUI no esta disponible en Android."))


# ------------------------------------------------------------------ bucle
def run_menu(cfg, handlers: dict[str, Handler], *, input_fn: IOIn = input,
             print_fn: IOOut = print, colors: bool | None = None) -> int:
    """Bucle principal del menú. Devuelve 0 al salir.

    `handlers` debe contener las claves: search, analyze, export, stats,
    audit, lab, lab-demo, proxies. Los manejadores son las mismas funciones
    cmd_* de main.py (misma lógica, misma seguridad).
    """
    p = Palette(colors_enabled() if colors is None else colors)
    opciones = {
        "1": menu_search, "2": menu_analyze, "3": menu_export, "4": menu_stats,
        "5": menu_audit, "6": menu_lab, "7": menu_lab_demo, "8": menu_proxies,
        "9": menu_config,
    }
    try:
        while True:
            print_fn(banner(p))
            print_fn(MENU)
            try:
                choice = input_fn("Selecciona una opcion [0-9]: ").strip()
            except EOFError:
                print_fn("")
                return 0
            if choice == "0":
                print_fn("Hasta pronto. Recuerda: solo auditorias AUTORIZADAS.")
                return 0
            accion = opciones.get(choice)
            if accion is None:
                print_fn(p.err("Opcion no valida."))
                continue
            try:
                accion(cfg, handlers, input_fn, print_fn, p)
            except SystemExit as e:            # errores controlados de los cmd_*
                print_fn(p.err(str(e or "Operacion cancelada.")))
            except KeyboardInterrupt:          # Ctrl+C: volver al menu
                print_fn("\n" + p.warn("Operacion interrumpida; volvemos al menu."))
            except Exception as e:             # nunca morir: mostrar y seguir
                print_fn(p.err(f"Error: {type(e).__name__}: {e}"))
    except KeyboardInterrupt:                  # Ctrl+C en el propio menu: salir limpio
        print_fn("\nHasta pronto. Recuerda: solo auditorias AUTORIZADAS.")
        return 0
