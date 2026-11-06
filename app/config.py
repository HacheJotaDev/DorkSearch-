"""Configuración de la aplicación.

- Carga un fichero JSON de configuración sobre valores por defecto.
- Las credenciales NUNCA van en el código: se leen de variables de
  entorno (fichero .env) mediante get_credentials().
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    def load_dotenv(*a, **k):  # type: ignore[misc]
        return False


class ConfigError(Exception):
    """Error de configuración."""


@dataclass
class SearchConfig:
    provider: str = "google_cse"            # google_cse | serpapi | offline
    results_per_page: int = 10
    max_results_per_dork: int = 100
    max_total_results: int = 100_000
    max_api_requests_per_day: int = 5000
    concurrency: int = 3
    rate_limit_rps: float = 1.0
    backoff_base_seconds: float = 0.5
    max_retries: int = 5
    user_agent: str = "uds-searcher/1.0 (auditoria autorizada)"
    authorized_domains: list[str] = field(default_factory=list)
    allow_unrestricted_search: bool = False
    dedupe: bool = True


@dataclass
class ProxyConfig:
    file: str = "proxies.txt"
    strategy: str = "round_robin"           # round_robin | random | least_used
    check_url: str = "https://httpbin.org/ip"
    check_timeout: float = 10.0
    check_concurrency: int = 10
    max_consecutive_failures: int = 3
    ban_ttl_seconds: float = 300.0


@dataclass
class AnalyzerConfig:
    min_priority_for_sqli_review: int = 30


@dataclass
class SqliConfig:
    allowed_domains: list[str] = field(default_factory=lambda: ["127.0.0.1", "localhost"])
    timeout: float = 10.0
    user_agent: str = "uds-auditor/1.0 (auditoria autorizada)"
    techniques: list[str] = field(default_factory=lambda: ["error", "boolean"])
    max_payloads_per_param: int = 12
    max_requests_per_audit: int = 200


@dataclass
class StorageConfig:
    database: str = "data/urls.db"
    batch_size: int = 500


@dataclass
class ExportConfig:
    dir: str = "exports"


@dataclass
class AppConfig:
    search: SearchConfig = field(default_factory=SearchConfig)
    proxies: ProxyConfig = field(default_factory=ProxyConfig)
    analyzer: AnalyzerConfig = field(default_factory=AnalyzerConfig)
    sqli: SqliConfig = field(default_factory=SqliConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    export: ExportConfig = field(default_factory=ExportConfig)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _merge_dataclass(instance: Any, data: dict[str, Any]) -> None:
    for key, value in data.items():
        if hasattr(instance, key):
            current = getattr(instance, key)
            if isinstance(current, list) and isinstance(value, list):
                setattr(instance, key, value)
            elif isinstance(current, (int, float, str, bool)) or current is None:
                setattr(instance, key, type(current)(value) if current is not None and not isinstance(value, bool) else value)


def load_config(path: str | Path | None = None) -> AppConfig:
    """Carga la configuración JSON (si existe) sobre los valores por defecto."""
    cfg = AppConfig()
    if path is not None:
        p = Path(path)
        if not p.exists():
            raise ConfigError(f"No existe el fichero de configuración: {p}")
        raw = json.loads(p.read_text(encoding="utf-8"))
        for section, sub in (
            ("search", cfg.search), ("proxies", cfg.proxies), ("analyzer", cfg.analyzer),
            ("sqli", cfg.sqli), ("storage", cfg.storage), ("export", cfg.export),
        ):
            if section in raw and isinstance(raw[section], dict):
                _merge_dataclass(sub, raw[section])
    return cfg


def get_credentials() -> dict[str, str]:
    """Credenciales SOLO desde variables de entorno / fichero .env."""
    load_dotenv()
    return {
        "GOOGLE_API_KEY": os.getenv("GOOGLE_API_KEY", "").strip(),
        "GOOGLE_CSE_ID": os.getenv("GOOGLE_CSE_ID", "").strip(),
        "SERPAPI_KEY": os.getenv("SERPAPI_KEY", "").strip(),
    }
