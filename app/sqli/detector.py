"""Detector NO destructivo de inyección SQL para auditorías AUTORIZADAS.

Técnicas implementadas (ambas no destructivas):
- ERROR: sondas que provocan un error de sintaxis y buscan firmas de error
  de la base de datos en la respuesta (MySQL, PostgreSQL, MSSQL, Oracle,
  SQLite, JDBC/ODBC genérico).
- BOOLEAN: comparación de respuestas entre una condición verdadera (1=1) y
  una falsa (1=2), con controles para descartar falsos positivos.

Garantías del módulo:
- NO extrae datos, NO enumera credenciales, NO ejecuta consultas apiladas,
  NO usa técnicas basadas en tiempo (SLEEP/WAITFOR) y NO intenta evadir WAFs.
- Valida cada URL contra ScopeGuard ANTES de cada petición.
- Registra cada petición (audit log) para reproducibilidad.
- Verifica reproducibilidad (repite sondas) y usa payloads de control
  aleatorios para descartar errores genéricos de la aplicación.
"""
from __future__ import annotations

import difflib
import re
import time
from typing import Callable, Optional

import httpx

from ..logging_setup import get_logger
from ..models import Finding
from ..storage.database import utcnow
from .findings import EVIDENCE_LEVELS, REMEDIATION_BASE, REMEDIATION_SNIPPETS
from .scope import ScopeGuard, ScopeViolation

log = get_logger("sqli")

ERROR_SIGNATURES: dict[str, list[str]] = {
    "MySQL/MariaDB": [
        r"you have an error in your sql syntax",
        r"warning:\s*mysql[i]?_",
        r"mysqli?_fetch",
        r"mariadb server version",
        r"com\.mysql\.jdbc",
    ],
    "PostgreSQL": [
        r"pg::syntaxerror",
        r"postgresql.*error",
        r"warning:\s*pg_",
        r"pg_query\(\)",
        r"unterminated quoted string",
    ],
    "SQLite": [
        r"sqlite3?::query",
        r"sqlite_master",
        r"sqlite3\.operationalerror",
        r"unrecognized token",
        r"sql logic error",
        r"incomplete input",
    ],
    "MSSQL": [
        r"microsoft ole db provider",
        r"odbc sql server driver",
        r"sqlserverjdbc",
        r"unclosed quotation mark after the character string",
        r"incorrect syntax near",
    ],
    "Oracle": [
        r"ora-\d{5}",
        r"oracle error",
        r"quoted string not properly terminated",
    ],
    "JDBC/ODBC genérico": [
        r"jdbcexception",
        r"sqlstate\d*",
        r"syntax error at or near",
        r"java\.sql\.sqlexception",
        r"pdoexception",
        r"sql syntax.*?error",
    ],
}
_COMPILED = {dbms: [re.compile(p, re.IGNORECASE) for p in pats]
             for dbms, pats in ERROR_SIGNATURES.items()}

# Sondas de error NO destructivas (solo provocan fallo de sintaxis)
ERROR_PROBES = ["'", '"', "')", "`"]
# Payload de control: cadena aleatoria que NO debe provocar errores
CONTROL_SUFFIX = "'ZzQx7NoSig41"


class SqliDetector:
    def __init__(self, client: httpx.AsyncClient, scope: ScopeGuard,
                 log_sink: Optional[Callable] = None,
                 max_requests_total: int = 200, max_payloads_per_param: int = 12):
        self.client = client
        self.scope = scope
        self.log_sink = log_sink or (lambda **kw: None)
        self.max_requests_total = max_requests_total
        self.max_payloads_per_param = max_payloads_per_param
        self._requests = 0

    # ---------- infraestructura ----------
    def _log_request(self, url: str, status: Optional[int], elapsed_ms: float, note: str) -> None:
        self._requests += 1
        try:
            self.log_sink(url=url, status_code=status, elapsed_ms=round(elapsed_ms, 1), note=note)
        except Exception:
            pass

    def _inject(self, url: str, param: str, value: str) -> str:
        from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
        parts = urlsplit(url)
        qs = parse_qsl(parts.query, keep_blank_values=True)
        new_qs = [(k, value if k == param else v) for k, v in qs]
        if param not in [k for k, _ in qs]:
            new_qs.append((param, value))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(new_qs), parts.fragment))

    async def _get(self, url: str, note: str):
        self.scope.assert_allowed(url)  # verificación OBLIGATORIA antes de CADA petición
        if self._requests >= self.max_requests_total:
            raise RuntimeError("Límite de peticiones de auditoría alcanzado "
                               f"({self.max_requests_total}). Aumenta sqli.max_requests_per_audit "
                               "solo si es necesario.")
        t0 = time.monotonic()
        resp = await self.client.get(url)
        ms = (time.monotonic() - t0) * 1000
        self._log_request(url, resp.status_code, ms, note)
        return resp, ms

    @staticmethod
    def _match_signatures(text: str) -> list[tuple[str, str]]:
        found: list[tuple[str, str]] = []
        for dbms, regexes in _COMPILED.items():
            for rx in regexes:
                m = rx.search(text)
                if m:
                    start = max(0, m.start() - 60)
                    end = min(len(text), m.end() + 60)
                    snippet = " ".join(text[start:end].split())
                    found.append((dbms, snippet))
        return found

    @staticmethod
    def _similar(a: str, b: str) -> float:
        return difflib.SequenceMatcher(None, a, b).ratio()

    @staticmethod
    def _params_of(url: str) -> list[str]:
        from urllib.parse import parse_qsl, urlsplit
        return [n for n, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]

    # ---------- auditoría ----------
    async def audit_url(self, url: str, params: Optional[list[str]] = None,
                        techniques: tuple = ("error", "boolean")) -> list[Finding]:
        self.scope.assert_allowed(url)
        params = params or self._params_of(url)
        findings: list[Finding] = []
        for param in params:
            try:
                f = await self._audit_param(url, param, techniques)
            except ScopeViolation:
                raise
            except httpx.HTTPError as e:
                log.warning(f"Error de red auditando '{param}' en {url}: {e}")
                f = None
            if f is not None:
                findings.append(f)
        return findings

    async def _audit_param(self, url: str, param: str, techniques) -> Optional[Finding]:
        from urllib.parse import parse_qsl, urlsplit
        original = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True)).get(param, "")
        used = 0

        baseline, base_ms = await self._get(self._inject(url, param, original), "baseline")
        used += 1
        base_text = baseline.text
        base_sigs = self._match_signatures(base_text)
        if base_sigs:
            return self._finding(
                url, param, "error", base_sigs[0][0], "POSSIBLE",
                "La respuesta BASE ya contiene firmas de error de BD: posible mala "
                "configuración de la aplicación. Se requiere revisión manual "
                "(no se confirma por payload).",
                baseline, base_ms, extra_snapshot={"note": "sin-payload"},
            )

        # ---------- técnica 1: errores ----------
        if "error" in techniques:
            for probe in ERROR_PROBES:
                if used >= self.max_payloads_per_param:
                    break
                probe_val = (original or "1") + probe
                probe_url = self._inject(url, param, probe_val)
                r, ms = await self._get(probe_url, f"probe-error:{probe}")
                used += 1
                sigs = self._match_signatures(r.text)
                if not sigs:
                    continue
                # Control anti-falsos-positivos: una cadena aleatoria NO debe
                # provocar el mismo error.
                control_url = self._inject(url, param, (original or "1") + CONTROL_SUFFIX)
                c, _ = await self._get(control_url, "control")
                used += 1
                if self._match_signatures(c.text):
                    continue  # la app falla con cualquier entrada: descartar
                dbms, snippet = sigs[0]
                # Reproducibilidad: repetir la misma sonda
                r2, ms2 = await self._get(probe_url, "probe-error-repeat")
                used += 1
                sigs2 = self._match_signatures(r2.text)
                level = "CONFIRMED" if (sigs2 and sigs2[0][0] == dbms) else "LIKELY"
                return self._finding(
                    url, param, "error", dbms, level,
                    f"El parámetro '{param}' provoca un error visible de {dbms} al "
                    f"alterar su valor (sonda no destructiva '{probe}'). "
                    f"Reproducible: {'sí' if level == 'CONFIRMED' else 'parcialmente'}.",
                    r, ms, snippet_list=[s for _, s in sigs[:3]],
                    extra_snapshot={"probe": probe, "repeat_status": r2.status_code},
                )

        # ---------- técnica 2: booleana ----------
        if "boolean" in techniques:
            if used >= self.max_payloads_per_param:
                return None
            if original.isdigit():
                t_val, f_val = f"{original} AND 1=1", f"{original} AND 1=2"
            else:
                t_val, f_val = f"{original}' AND '1'='1", f"{original}' AND '1'='2"
            rt, rt_ms = await self._get(self._inject(url, param, t_val), "boolean-true")
            rf, rf_ms = await self._get(self._inject(url, param, f_val), "boolean-false")
            used += 2
            # Si el objetivo rechaza ambas entradas (validación), no hay señal.
            if rt.status_code >= 400 and rf.status_code >= 400:
                return None
            sim_tf = self._similar(rt.text, rf.text)
            sim_tb = self._similar(rt.text, base_text)
            if rt.status_code == baseline.status_code and sim_tb >= 0.98 \
                    and sim_tf <= 0.95 and abs(len(rt.text) - len(rf.text)) > 20:
                if used + 2 > self.max_payloads_per_param:
                    level = "LIKELY"
                else:
                    rt2, _ = await self._get(self._inject(url, param, t_val), "boolean-true-repeat")
                    rf2, _ = await self._get(self._inject(url, param, f_val), "boolean-false-repeat")
                    used += 2
                    consistent = (self._similar(rt2.text, rt.text) >= 0.98
                                  and self._similar(rf2.text, rf.text) >= 0.98)
                    level = "LIKELY" if consistent else "POSSIBLE"
                return self._finding(
                    url, param, "boolean", "", level,
                    f"Diferencia CONSISTENTE de respuesta entre la condición verdadera "
                    f"'{t_val}' y la falsa '{f_val}' (similitud V-F={sim_tf:.2f}, "
                    f"V-base={sim_tb:.2f}). Comportamiento típico de inyección booleana; "
                    f"revisar manualmente en un entorno autorizado.",
                    rt, rt_ms,
                    snippet_list=[f"len(true)={len(rt.text)}", f"len(false)={len(rf.text)}",
                                  f"len(base)={len(base_text)}"],
                )
            # Anomalía débil: solo si la condición verdadera se comporta como la base
            if rt.status_code == baseline.status_code and \
                    (sim_tf <= 0.90 or abs(len(rt.text) - len(rf.text)) > 100):
                return self._finding(
                    url, param, "boolean", "", "POSSIBLE",
                    "Diferencia de respuesta entre condiciones verdadera/falsa; se "
                    "requiere verificación manual (posible falso positivo por contenido "
                    "dinámico de la página).",
                    rt, rt_ms,
                )
        return None

    def _finding(self, url, param, technique, dbms, level, details, resp, elapsed_ms=None,
                 snippet_list=None, extra_snapshot=None) -> Finding:
        remediation = list(REMEDIATION_BASE)
        if dbms:
            remediation.insert(1, f"Motor de base de datos detectado: {dbms}.")
        remediation.append("Ejemplos de consultas parametrizadas:")
        for lang, snippet in REMEDIATION_SNIPPETS.items():
            remediation.append(f"  {lang}: {snippet}")
        snap = {
            "url": str(resp.request.url), "method": "GET", "status": resp.status_code,
            "length": len(resp.text), "elapsed_ms": round(elapsed_ms, 1) if elapsed_ms else None,
        }
        if extra_snapshot:
            snap.update(extra_snapshot)
        return Finding(
            url=url, param=param, technique=technique, dbms=dbms, evidence=level,
            evidence_level=EVIDENCE_LEVELS[level], details=details,
            request_snapshot=snap, evidence_snippets=snippet_list or [],
            remediation=remediation, timestamp=utcnow(),
        )
