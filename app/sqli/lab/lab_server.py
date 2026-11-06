"""Laboratorio SQLi LOCAL (127.0.0.1) con datos ficticios.

Sirve pares de endpoints VULNERABLES (concatenación de strings) y CORREGIDOS
(consultas parametrizadas + validación de entrada) para:
- demostrar cómo se detecta la inyección con técnicas no destructivas;
- verificar que la versión corregida NO es vulnerable.

Garantías del laboratorio:
- Escucha SOLO en localhost (no accesible desde la red).
- Solo acepta consultas SELECT (nunca modifica datos).
- Los datos son 100% ficticios (lab_data.py).
"""
from __future__ import annotations

import json
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from ...logging_setup import get_logger
from .lab_data import init_lab_db

log = get_logger("lab")

INDEX = {
    "lab": "uds-sqli-lab (datos ficticios, solo localhost, solo SELECT)",
    "endpoints": {
        "vulnerable": [
            "/vulnerable/product?id=1",
            "/vulnerable/search?q=teclado",
        ],
        "fixed": [
            "/fixed/product?id=1",
            "/fixed/search?q=teclado",
        ],
        "utilidades": ["/lab/reset"],
    },
}


def _run_vulnerable(conn: sqlite3.Connection, sql: str):
    """Ejecuta la consulta construida por concatenación (SOLO SELECT)."""
    if not sql.lstrip().lower().startswith("select"):
        return 400, {"error": "laboratorio: solo se permiten SELECT"}
    try:
        rows = conn.execute(sql).fetchall()
    except sqlite3.Error as e:
        # VULNERABLE: expone el error de la BD en la respuesta (display_errors on)
        return 500, {"error": str(e), "sql": sql}
    return 200, {"sql": sql, "rows": rows}


def _run_fixed(conn: sqlite3.Connection, sql: str, params: tuple):
    """Versión CORREGIDA: consulta parametrizada + validación; sin detalles de BD."""
    try:
        rows = conn.execute(sql, params).fetchall()
    except sqlite3.Error:
        # CORRECTO: mensaje genérico, sin filtrar detalles del motor
        return 400, {"error": "entrada no válida"}
    return 200, {"sql": sql, "params": list(params), "rows": rows}


class LabServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 0,
                 db_path: str | Path = "data/lab.db"):
        self.host = host
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        init_lab_db(self.db_path).close()
        self.httpd = ThreadingHTTPServer((host, port), self._make_handler())
        self.port = self.httpd.server_address[1]
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def _make_handler(self):
        lab = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):  # silenciar log por petición
                log.debug(f"{self.address_string()} {fmt % args}")

            def _json(self, code: int, payload: dict) -> None:
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _conn(self):
                return sqlite3.connect(lab.db_path)

            def do_GET(self):  # noqa: N802
                parts = urlsplit(self.path)
                route = parts.path.rstrip("/") or "/"
                qs = parse_qs(parts.query)

                if route == "/":
                    return self._json(200, INDEX)
                if route == "/lab/reset":
                    init_lab_db(lab.db_path).close()
                    return self._json(200, {"reset": True})

                # -------- endpoints VULNERABLES (concatenación de strings) --------
                if route == "/vulnerable/product":
                    pid = unquote(qs.get("id", ["1"])[0])
                    sql = f"SELECT id, name, price, stock FROM products WHERE id = '{pid}'"
                    with self._conn() as conn:
                        code, payload = _run_vulnerable(conn, sql)
                    return self._json(code, payload)

                if route == "/vulnerable/search":
                    q = unquote(qs.get("q", [""])[0])
                    sql = f"SELECT id, name, price FROM products WHERE name LIKE '%{q}%'"
                    with self._conn() as conn:
                        code, payload = _run_vulnerable(conn, sql)
                    return self._json(code, payload)

                # -------- endpoints CORREGIDOS (parametrizados + validación) --------
                if route == "/fixed/product":
                    pid = unquote(qs.get("id", ["1"])[0])
                    if not pid.isdigit():
                        return self._json(400, {"error": "entrada no válida"})
                    with self._conn() as conn:
                        code, payload = _run_fixed(
                            conn, "SELECT id, name, price, stock FROM products WHERE id = ?",
                            (int(pid),))
                    return self._json(code, payload)

                if route == "/fixed/search":
                    q = unquote(qs.get("q", [""])[0])
                    with self._conn() as conn:
                        code, payload = _run_fixed(
                            conn, "SELECT id, name, price FROM products WHERE name LIKE ?",
                            (f"%{q}%",))
                    return self._json(code, payload)

                return self._json(404, {"error": "endpoint desconocido"})

        return Handler

    def start(self) -> None:
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()
        log.info(f"Laboratorio SQLi disponible en {self.base_url} (solo localhost)")

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)
        log.info("Laboratorio SQLi detenido")


def start_lab(host: str = "127.0.0.1", port: int = 0,
              db_path: str | Path = "data/lab.db") -> LabServer:
    lab = LabServer(host=host, port=port, db_path=db_path)
    lab.start()
    return lab
