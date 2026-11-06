"""Control estricto de alcance (scope) para la auditoría SQLi.

TODA petición de auditoría debe pasar por ScopeGuard.assert_allowed() ANTES
de ejecutarse. Si el objetivo no está en la lista blanca de dominios
autorizados, se lanza ScopeViolation y la petición NO se realiza.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from ..logging_setup import get_logger

log = get_logger("scope")


class ScopeViolation(Exception):
    """Se intentó auditar un objetivo fuera de la lista blanca autorizada."""


class ScopeGuard:
    def __init__(self, allowed_domains):
        if isinstance(allowed_domains, str):
            allowed_domains = [allowed_domains]
        self.allowed = {d.lower().strip() for d in (allowed_domains or []) if d and d.strip()}

    def is_allowed(self, url: str) -> bool:
        try:
            parts = urlsplit(url.strip())
        except ValueError:
            return False
        if parts.scheme not in ("http", "https"):
            return False
        host = (parts.hostname or "").lower()
        if not host:
            return False
        for d in self.allowed:
            if host == d or host.endswith("." + d):
                return True
        return False

    def assert_allowed(self, url: str) -> None:
        if not self.is_allowed(url):
            log.error(f"SCOPE VIOLATION bloqueado: {url}")
            raise ScopeViolation(
                f"Objetivo FUERA de la lista blanca autorizada: {url}. "
                f"Añádelo a sqli.allowed_domains SOLO si tienes autorización expresa."
            )
