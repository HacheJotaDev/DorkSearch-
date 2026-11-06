"""Modelos de datos centrales del proyecto."""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit


def get_domain(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def get_extension(url: str) -> str:
    try:
        path = urlsplit(url).path
    except ValueError:
        return ""
    name = path.rsplit("/", 1)[-1]
    if "." in name:
        return name.rsplit(".", 1)[-1].lower()[:10]
    return ""


@dataclass
class UrlRecord:
    url: str
    domain: str = ""
    path: str = ""
    query: str = ""
    ext: str = ""
    params_count: int = 0
    db_related: str = ""
    priority: int = 0
    source: str = ""
    dork: str = ""
    discovered_at: str = ""

    @classmethod
    def from_url(cls, url: str, source: str = "", dork: str = "", timestamp: str = ""):
        from urllib.parse import parse_qsl

        try:
            parts = urlsplit(url)
        except ValueError:
            return None
        if not parts.scheme or not parts.hostname:
            return None
        return cls(
            url=url,
            domain=(parts.hostname or "").lower(),
            path=parts.path or "/",
            query=parts.query,
            ext=get_extension(url),
            params_count=len(parse_qsl(parts.query, keep_blank_values=True)),
            source=source,
            dork=dork,
            discovered_at=timestamp,
        )

    def to_row(self) -> tuple:
        return (
            self.url, self.domain, self.path, self.query, self.ext,
            self.params_count, self.db_related, self.priority,
            self.source, self.dork, self.discovered_at,
        )


@dataclass
class ProxyEntry:
    host: str
    port: int
    user: str
    password: str
    scheme: str = "http"

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.user}:{self.password}@{self.host}:{self.port}"

    @property
    def masked(self) -> str:
        """Representación SEGURA para logs/exports: nunca muestra la contraseña."""
        return f"{self.scheme}://{self.user}:***@{self.host}:{self.port}"

    def display(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class Finding:
    """Hallazgo de auditoría SQLi con evidencia y remediación."""
    url: str
    param: str
    technique: str
    dbms: str
    evidence: str           # INFO | POSSIBLE | LIKELY | CONFIRMED
    evidence_level: int     # 10 | 20 | 30 | 40
    details: str
    request_snapshot: dict = field(default_factory=dict)
    evidence_snippets: list = field(default_factory=list)
    remediation: list = field(default_factory=list)
    timestamp: str = ""

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class SearchPage:
    query: str
    start: int
    results: list
    total: int
    provider: str
