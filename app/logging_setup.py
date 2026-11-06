"""Configuración de logging: consola + fichero rotativo.

Las contraseñas de proxies NUNCA se registran: usa siempre
`ProxyEntry.masked` en los mensajes.
"""
from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

_CONFIGURED = False


def setup_logging(level: str = "INFO", logfile: str = "logs/uds.log") -> logging.Logger:
    global _CONFIGURED
    root = logging.getLogger("uds")
    if _CONFIGURED:
        return root
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    fmt = logging.Formatter("%(asctime)s | %(levelname)-7s | %(name)s | %(message)s")

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    root.addHandler(ch)

    if logfile:
        p = Path(logfile)
        p.parent.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(p, maxBytes=5_000_000, backupCount=5, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)

    for noisy in ("httpx", "httpcore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    root.propagate = False
    _CONFIGURED = True
    return root


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger("uds").getChild(name)
