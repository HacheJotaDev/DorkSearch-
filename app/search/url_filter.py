"""Filtrado y normalización de URLs descubiertas.

La lista blanca de dominios autorizados es OBLIGATORIA para la búsqueda:
toda URL que no pertenezca a la whitelist se descarta con motivo
'fuera-de-whitelist'.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

from ..models import get_extension


@dataclass
class UrlFilter:
    allowed_domains: set[str] = field(default_factory=set)   # lista blanca obligatoria
    blocked_domains: set[str] = field(default_factory=set)
    allowed_extensions: set[str] = field(default_factory=set)  # vacío = todas
    blocked_extensions: set[str] = field(default_factory=set)
    require_params: bool | None = None      # True = solo URLs con query string
    param_name_include: list[str] = field(default_factory=list)
    path_include: list[str] = field(default_factory=list)
    path_exclude: list[str] = field(default_factory=list)
    url_regex_include: str = ""
    url_regex_exclude: str = ""


class UrlFilterer:
    def __init__(self, f: UrlFilter):
        self.f = f
        self._inc_re = re.compile(f.url_regex_include) if f.url_regex_include else None
        self._exc_re = re.compile(f.url_regex_exclude) if f.url_regex_exclude else None
        self._params = {p.lower() for p in f.param_name_include}
        self._path_inc = list(f.path_include)
        self._path_exc = list(f.path_exclude)

    def check(self, url: str) -> tuple[bool, str]:
        try:
            parts = urlsplit(url.strip())
        except ValueError:
            return False, "malformada"
        if not url.strip():
            return False, "vacia"
        if parts.scheme not in ("http", "https"):
            return False, "esquema-no-http"
        host = (parts.hostname or "").lower()
        if not host:
            return False, "sin-dominio"
        if self.f.allowed_domains:
            if not any(host == d or host.endswith("." + d) for d in self.f.allowed_domains):
                return False, "fuera-de-whitelist"
        if any(host == d or host.endswith("." + d) for d in self.f.blocked_domains):
            return False, "dominio-bloqueado"
        ext = get_extension(url)
        if ext and self.f.allowed_extensions and ext not in self.f.allowed_extensions:
            return False, "extension-no-permitida"
        if ext and ext in self.f.blocked_extensions:
            return False, "extension-bloqueada"
        if self.f.require_params and not parts.query:
            return False, "sin-parametros"
        if self._params:
            names = {n.lower() for n, _ in parse_qsl(parts.query, keep_blank_values=True)}
            if not (names & self._params):
                return False, "parametro-requerido-ausente"
        if self._path_inc and not any(s in parts.path for s in self._path_inc):
            return False, "ruta-no-incluida"
        if self._path_exc and any(s in parts.path for s in self._path_exc):
            return False, "ruta-excluida"
        if self._inc_re and not self._inc_re.search(url):
            return False, "regex-no-incluida"
        if self._exc_re and self._exc_re.search(url):
            return False, "regex-excluida"
        return True, "ok"

    def filter_batch(self, urls: list[str]) -> list[str]:
        return [u for u in urls if self.check(u)[0]]
