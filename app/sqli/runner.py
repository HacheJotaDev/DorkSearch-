"""Runner de auditoría: orquesta ScopeGuard + SqliDetector + registro en BD."""
from __future__ import annotations

from typing import Callable, Optional

import httpx

from ..logging_setup import get_logger
from ..storage.database import Database, utcnow
from .detector import SqliDetector
from .scope import ScopeGuard

log = get_logger("sqli.runner")


async def run_audit(urls: list[str], allowed_domains: list[str],
                    techniques: tuple = ("error", "boolean"), timeout: float = 10.0,
                    user_agent: str = "uds-auditor/1.0 (auditoria autorizada)",
                    db: Optional[Database] = None, log_cb: Optional[Callable] = None,
                    max_requests: int = 200, max_payloads_per_param: int = 12) -> list:
    """Ejecuta una auditoría NO destructiva sobre las URLs (dominios autorizados)."""
    scope = ScopeGuard(allowed_domains)
    if not scope.allowed:
        raise ValueError("Lista blanca de dominios vacía: define sqli.allowed_domains.")

    if db is not None:
        def log_sink(**kw):
            db.add_audit_log([{"ts": utcnow(), **kw}])
    else:
        def log_sink(**kw):
            log.debug(f"petición de auditoría: {kw.get('url')} [{kw.get('note')}]")

    findings = []
    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=True, headers={"User-Agent": user_agent}
    ) as client:
        detector = SqliDetector(client, scope, log_sink=log_sink,
                                max_requests_total=max_requests,
                                max_payloads_per_param=max_payloads_per_param)
        for url in urls:
            fs = await detector.audit_url(url, techniques=techniques)
            findings.extend(fs)
            if log_cb:
                try:
                    log_cb(url, fs)
                except Exception:
                    pass
    if db is not None and findings:
        db.add_findings(findings)
    return findings
