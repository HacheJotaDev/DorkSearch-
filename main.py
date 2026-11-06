#!/usr/bin/env python3
"""URLS GOOGLE DORKS SEARCHER — Advanced URL Discovery & SQLi Security Auditor.

CLI principal. Uso responsable: SOLO para auditorías de seguridad AUTORIZADAS.

Comandos:
    gui            Interfaz gráfica PySide6
    search         Motor de descubrimiento de URLs con dorks
    analyze        Analiza/prioriza los parámetros de las URLs almacenadas
    audit          Auditoría SQLi no destructiva de una URL autorizada
    lab            Inicia el laboratorio SQLi local (datos ficticios)
    lab-demo       Demo completa: laboratorio + auditoría + informe de ejemplo
    export         Exporta las URLs almacenadas (TXT/CSV/JSON)
    stats          Estadísticas de la base de datos
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

from app.config import AppConfig, load_config


def _setup():
    from app.logging_setup import setup_logging
    setup_logging()


# --------------------------------------------------------------------------- GUI
def cmd_gui(args, cfg: AppConfig) -> int:
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        sys.exit("PySide6 no está instalado. Ejecuta: pip install -r requirements.txt")
    from app.gui.main_window import MainWindow

    qt_app = QApplication(sys.argv)
    win = MainWindow(cfg)
    win.show()
    return qt_app.exec()


# --------------------------------------------------------------------------- SEARCH
def cmd_search(args, cfg: AppConfig) -> int:
    _setup()
    from app.logging_setup import get_logger
    log = get_logger("cli")

    from app.search.api_client import create_provider
    from app.search.dork_builder import PRESETS, build_query, load_dorks_file
    from app.search.engine import SearchEngine
    from app.search.url_filter import UrlFilter, UrlFilterer
    from app.storage.database import Database

    if args.list_presets:
        print("Presets disponibles:")
        for name, spec in PRESETS.items():
            print(f"  {name:22s} -> {build_query(spec)}")
        return 0

    dorks: list[str] = []
    if args.dorks_file:
        dorks += load_dorks_file(args.dorks_file)
    if args.preset:
        for p in args.preset:
            if p not in PRESETS:
                sys.exit(f"Preset desconocido: {p} (usa --list-presets)")
            dorks.append(build_query(PRESETS[p]))
    dorks += args.dork or []
    dorks = list(dict.fromkeys(dorks))
    if not dorks:
        sys.exit("Sin dorks: usa --dork, --dorks-file o --preset (ver --list-presets)")

    whitelist = [d.strip().lower() for d in (args.domain or cfg.search.authorized_domains)]
    if not whitelist and not cfg.search.allow_unrestricted_search:
        sys.exit(
            "Lista blanca OBLIGATORIA: añade --domain ejemplo.com (repetible) o define "
            "search.authorized_domains en la configuración."
        )
    cfg.search.authorized_domains = whitelist
    if args.provider:
        cfg.search.provider = args.provider

    offline_fixture = None
    if cfg.search.provider == "offline" and args.offline_fixture:
        offline_fixture = json.loads(Path(args.offline_fixture).read_text(encoding="utf-8"))

    db = Database(args.db or cfg.storage.database)
    provider = create_provider(cfg.search, offline_fixture=offline_fixture)
    filterer = UrlFilterer(UrlFilter(allowed_domains=set(whitelist)))
    proxies = None
    if args.use_proxies:
        from app.proxies.manager import ProxyManager
        proxies = ProxyManager.load(
            cfg.proxies.file, strategy=cfg.proxies.strategy,
            max_consecutive_failures=cfg.proxies.max_consecutive_failures,
            ban_ttl_seconds=cfg.proxies.ban_ttl_seconds)
        log.info(f"Rotación de proxies activa: {len(proxies)} cargados (solo rate limits)")

    engine = SearchEngine(cfg, provider, db, filterer, proxies=proxies,
                          batch_size=cfg.storage.batch_size)
    engine.on_log = lambda m: print(m)
    stats = asyncio.run(engine.run(dorks))
    print("\n== RESULTADO ==")
    print(json.dumps(vars(stats), indent=2, ensure_ascii=False))

    if args.out:
        from app.storage.exporters import export_auto
        n = export_auto(args.out, db.iter_urls(batch=1000))
        print(f"Exportadas {n} URLs a {args.out}")
    return 0


# --------------------------------------------------------------------------- ANALYZE
def cmd_analyze(args, cfg: AppConfig) -> int:
    _setup()
    from app.analyzer.param_analyzer import ParamAnalyzer, analyze_database
    from app.storage.database import Database

    db = Database(args.db or cfg.storage.database)
    result = analyze_database(db, analyzer=ParamAnalyzer(), batch_size=cfg.storage.batch_size)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print(json.dumps(db.stats(), indent=2, ensure_ascii=False))
    return 0


# --------------------------------------------------------------------------- AUDIT
def cmd_audit(args, cfg: AppConfig) -> int:
    _setup()
    from app.reporting.report import generate_report
    from app.sqli.runner import run_audit
    from app.storage.database import Database

    whitelist = [d.strip().lower() for d in (args.domain or cfg.sqli.allowed_domains)]
    if not whitelist:
        sys.exit("Define los dominios autorizados con --domain (repetible) o en la config.")
    db = Database(args.db or cfg.storage.database)
    findings = asyncio.run(run_audit(
        [args.url], whitelist, techniques=tuple(args.techniques),
        timeout=cfg.sqli.timeout, user_agent=cfg.sqli.user_agent, db=db,
        max_requests=cfg.sqli.max_requests_per_audit,
        max_payloads_per_param=cfg.sqli.max_payloads_per_param,
    ))
    print(f"\nHallazgos: {len(findings)}")
    for f in findings:
        print(f"  [{f.evidence}] {f.url} · param={f.param} · técnica={f.technique} "
              f"· motor={f.dbms or '-'}")
        print(f"    {f.details}")
    Path("reports").mkdir(exist_ok=True)
    doc = generate_report(findings, whitelist, out_json="reports/audit_report.json",
                          out_md="reports/audit_report.md", meta={"targets": 1, "origen": "CLI"})
    print("\nInforme generado: reports/audit_report.md · reports/audit_report.json")
    print(f"Resumen: {doc['summary']}")
    return 0


# --------------------------------------------------------------------------- LAB
def cmd_lab(args, cfg: AppConfig) -> int:
    _setup()
    from app.sqli.lab.lab_server import start_lab

    lab = start_lab(port=args.port, db_path=args.lab_db)
    print(f"Laboratorio SQLi local en {lab.base_url}  (Ctrl+C para detener)")
    print("Endpoints:")
    print("  VULNERABLES: /vulnerable/product?id=1   /vulnerable/search?q=teclado")
    print("  CORREGIDOS : /fixed/product?id=1        /fixed/search?q=teclado")
    print("  Utilidades : /lab/reset")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        lab.stop()
        print("\nLaboratorio detenido.")
    return 0


# --------------------------------------------------------------------------- LAB-DEMO
def cmd_lab_demo(args, cfg: AppConfig) -> int:
    """Demostración completa en local: laboratorio + auditoría + informe ejemplo."""
    _setup()
    from collections import defaultdict

    from app.reporting.report import generate_report
    from app.sqli.lab.lab_server import start_lab
    from app.sqli.runner import run_audit
    from app.storage.database import Database

    print("== DEMO: laboratorio SQLi local con datos ficticios ==")
    lab = start_lab(port=args.port, db_path=args.lab_db)
    base = lab.base_url
    targets = [
        f"{base}/vulnerable/product?id=1",
        f"{base}/vulnerable/search?q=teclado",
        f"{base}/fixed/product?id=1",
        f"{base}/fixed/search?q=teclado",
    ]
    db = Database(args.db or cfg.storage.database)
    findings = asyncio.run(run_audit(targets, ["127.0.0.1"], techniques=("error", "boolean"),
                                     db=db))
    lab.stop()

    per_target: dict[str, str] = defaultdict(str)
    for f in findings:
        per_target[f.url.split("?")[0]] = f"[{f.evidence}·{f.dbms or '-'}]"
    print("\nResultados por objetivo:")
    for t in targets:
        print(f"  {t:60s} -> {per_target.get(t.split('?')[0], '[sin hallazgos]')}")
    print("\nNOTA: la presencia de parámetros NO implica inyección; los hallazgos "
          "provienen de las sondas no destructivas del auditor.")

    Path("reports").mkdir(exist_ok=True)
    doc = generate_report(
        findings, ["127.0.0.1"],
        out_json="reports/audit_report_example.json",
        out_md="reports/audit_report_example.md",
        meta={
            "targets": len(targets),
            "origen": "lab-demo",
            "entorno": "laboratorio LOCAL con datos ficticios (127.0.0.1)",
        })
    print(f"\nInforme de ejemplo generado: reports/audit_report_example.md")
    print(f"Resumen: {doc['summary']}")
    return 0


# --------------------------------------------------------------------------- EXPORT
def cmd_export(args, cfg: AppConfig) -> int:
    from app.storage.database import Database
    from app.storage.exporters import export_auto

    db = Database(args.db or cfg.storage.database)
    rows = db.iter_urls(
        batch=1000,
        domain=args.domain_filter,
        ext=args.ext,
        has_params=args.has_params,
        min_priority=args.min_priority,
    )
    n = export_auto(args.out, rows)
    print(f"Exportadas {n} URLs a {args.out}")
    return 0


# --------------------------------------------------------------------------- STATS
def cmd_stats(args, cfg: AppConfig) -> int:
    from app.storage.database import Database

    db = Database(args.db or cfg.storage.database)
    print(json.dumps(db.stats(), indent=2, ensure_ascii=False))
    return 0


# --------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python main.py",
        description="Advanced URL Discovery & SQLi Security Auditor (solo uso autorizado)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--config", default=None, help="fichero JSON de configuración "
                   "(p.ej. config.example.json)")
    p.add_argument("--db", default=None, help="ruta de la base de datos SQLite "
                   "(por defecto: config storage.database)")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gui", help="interfaz gráfica PySide6")

    s = sub.add_parser("search", help="motor de descubrimiento de URLs con dorks")
    s.add_argument("--dork", action="append", default=None, help="dork literal (repetible)")
    s.add_argument("--dorks-file", default=None, help="fichero con un dork por línea")
    s.add_argument("--preset", action="append", default=None,
                   help="preset de dork (repetible; ver --list-presets)")
    s.add_argument("--list-presets", action="store_true", help="lista los presets y sale")
    s.add_argument("--domain", action="append", default=None,
                   help="dominio autorizado de la lista blanca (repetible)")
    s.add_argument("--provider", default=None,
                   help="proveedor de búsqueda (google_cse | serpapi | offline)")
    s.add_argument("--out", default=None, help="exportar URLs al terminar (.txt/.csv/.json)")
    s.add_argument("--use-proxies", action="store_true",
                   help="activar rotación de proxies (solo para respetar rate limits)")
    s.add_argument("--offline-fixture", default=None,
                   help="JSON fixture para el proveedor offline (pruebas/demo)")

    a = sub.add_parser("analyze", help="analiza y prioriza los parámetros de las URLs")

    au = sub.add_parser("audit", help="auditoría SQLi no destructiva de una URL")
    au.add_argument("--url", required=True, help="URL objetivo (DEBE estar autorizada)")
    au.add_argument("--domain", action="append", default=None,
                    help="dominio autorizado (repetible)")

    l = sub.add_parser("lab", help="inicia el laboratorio SQLi local")
    l.add_argument("--port", type=int, default=8000)
    l.add_argument("--lab-db", default="data/lab.db")

    ld = sub.add_parser("lab-demo", help="demo: laboratorio + auditoría + informe ejemplo")
    ld.add_argument("--port", type=int, default=0, help="0 = puerto efímero")
    ld.add_argument("--lab-db", default="data/lab.db")

    e = sub.add_parser("export", help="exporta URLs (por extensión: .txt/.csv/.json)")
    e.add_argument("--out", required=True)
    e.add_argument("--domain-filter", default=None)
    e.add_argument("--ext", default=None)
    e.add_argument("--has-params", action="store_true")
    e.add_argument("--min-priority", type=int, default=None)

    st = sub.add_parser("stats", help="estadísticas de la base de datos")
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        cfg = load_config(args.config)
    except Exception as e:
        sys.exit(f"Error de configuración: {e}")
    handlers = {
        "gui": cmd_gui, "search": cmd_search, "analyze": cmd_analyze,
        "audit": cmd_audit, "lab": cmd_lab, "lab-demo": cmd_lab_demo,
        "export": cmd_export, "stats": cmd_stats,
    }
    return handlers[args.cmd](args, cfg)


if __name__ == "__main__":
    raise SystemExit(main())
