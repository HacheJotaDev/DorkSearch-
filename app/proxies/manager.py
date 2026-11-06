"""Administrador de proxies residenciales rotativos.

Formato soportado (una línea por proxy, en proxies.txt):

    IP:PORT:USER:PASSWORD

Funcionalidad:
- Carga y validación del fichero (líneas inválidas se descartan con log).
- Estrategias de rotación: round_robin, random, least_used.
- Autenticación por usuario/contraseña (URL http://user:pass@ip:port).
- Verificación asíncrona de conectividad (check_all) con concurrencia.
- Estadísticas por proxy (peticiones, éxitos, fallos, latencia media).
- Expulsión temporal (ban con TTL) tras N fallos consecutivos.
- Protección de credenciales: masked() nunca muestra la contraseña.

USO RESPONSABLE: la rotación existe para respetar los límites de tasa del
servicio autorizado. Está PROHIBIDO usarla para evadir CAPTCHAs, bloqueos
o controles de acceso.
"""
from __future__ import annotations

import asyncio
import random
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

from ..logging_setup import get_logger
from ..models import ProxyEntry

log = get_logger("proxies")

STRATEGIES = ("round_robin", "random", "least_used")


class ProxyManagerError(Exception):
    pass


@dataclass
class ProxyStats:
    requests: int = 0
    successes: int = 0
    failures: int = 0
    consecutive_failures: int = 0
    total_latency: float = 0.0
    last_used: float = 0.0
    banned_until: float = 0.0
    last_error: str = ""

    @property
    def avg_latency(self) -> float:
        return (self.total_latency / self.successes) if self.successes else 0.0


class ProxyManager:
    def __init__(self, strategy: str = "round_robin", max_consecutive_failures: int = 3,
                 ban_ttl_seconds: float = 300.0):
        if strategy not in STRATEGIES:
            raise ProxyManagerError(f"Estrategia inválida: {strategy}. Usa una de {STRATEGIES}")
        self.strategy = strategy
        self.max_consecutive_failures = max(1, int(max_consecutive_failures))
        self.ban_ttl = float(ban_ttl_seconds)
        self.entries: list[ProxyEntry] = []
        self.stats: dict[int, ProxyStats] = {}
        self._rr = 0
        self._lock = threading.RLock()

    # ---------- carga ----------
    @classmethod
    def load(cls, path: str | Path, **kwargs) -> "ProxyManager":
        pm = cls(**kwargs)
        pm.load_file(path)
        return pm

    def load_file(self, path: str | Path) -> int:
        p = Path(path)
        if not p.exists():
            raise ProxyManagerError(f"No existe el fichero de proxies: {p}")
        count = 0
        for lineno, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                entry = self.parse_line(line)
            except ProxyManagerError as e:
                log.warning(f"proxies.txt:{lineno}: línea descartada ({e})")
                continue
            self.entries.append(entry)
            self.stats[id(entry)] = ProxyStats()
            count += 1
        log.info(f"Cargados {count} proxies desde {p} (formato IP:PORT:USER:PASSWORD)")
        return count

    @staticmethod
    def parse_line(line: str) -> ProxyEntry:
        raw = line.strip()
        scheme = "http"
        if "://" in raw:
            scheme, raw = raw.split("://", 1)
            scheme = scheme.lower() or "http"
        parts = raw.split(":", 3)   # la contraseña PUEDE contener ':'
        if len(parts) != 4:
            raise ProxyManagerError("formato inválido; se espera IP:PORT:USER:PASSWORD")
        host, port_s, user, password = (p.strip() for p in parts)
        if not host:
            raise ProxyManagerError("IP vacía")
        try:
            port = int(port_s)
        except ValueError:
            raise ProxyManagerError(f"puerto inválido: {port_s!r}") from None
        if not (0 < port < 65536):
            raise ProxyManagerError(f"puerto fuera de rango: {port}")
        if not user or not password:
            raise ProxyManagerError("USER o PASSWORD vacíos")
        return ProxyEntry(host=host, port=port, user=user, password=password, scheme=scheme)

    def __len__(self) -> int:
        return len(self.entries)

    # ---------- rotación ----------
    def _available(self) -> list[ProxyEntry]:
        now = time.time()
        return [e for e in self.entries if self.stats[id(e)].banned_until <= now]

    def acquire(self) -> ProxyEntry | None:
        """Devuelve el siguiente proxy según la estrategia (omitiendo expulsados)."""
        with self._lock:
            avail = self._available()
            if not avail:
                return None
            if self.strategy == "round_robin":
                self._rr += 1
                return avail[self._rr % len(avail)]
            if self.strategy == "random":
                return random.choice(avail)
            return min(avail, key=lambda e: (self.stats[id(e)].requests, self.stats[id(e)].last_used))

    def rotate(self) -> ProxyEntry | None:
        return self.acquire()

    # ---------- estadísticas y salud ----------
    def report_success(self, entry: ProxyEntry, latency: float = 0.0) -> None:
        with self._lock:
            s = self.stats[id(entry)]
            s.requests += 1
            s.successes += 1
            s.consecutive_failures = 0
            s.total_latency += latency
            s.last_used = time.time()
            s.banned_until = 0.0

    def report_failure(self, entry: ProxyEntry, error: str = "") -> None:
        with self._lock:
            s = self.stats[id(entry)]
            s.requests += 1
            s.failures += 1
            s.consecutive_failures += 1
            s.last_used = time.time()
            s.last_error = (error or "")[:200]
            if s.consecutive_failures >= self.max_consecutive_failures:
                s.banned_until = time.time() + self.ban_ttl
                s.consecutive_failures = 0
                log.warning(
                    f"Proxy expulsado temporalmente {entry.masked} durante {self.ban_ttl:.0f}s "
                    f"(fallos acumulados: {s.failures})"
                )

    async def check_all(self, check_url: str = "https://httpbin.org/ip", timeout: float = 10.0,
                        concurrency: int = 10, transport=None) -> list[dict]:
        """Verifica la conectividad de todos los proxies de forma asíncrona."""
        sem = asyncio.Semaphore(max(1, concurrency))

        async def check(entry: ProxyEntry) -> dict:
            async with sem:
                kwargs: dict = {"timeout": timeout, "follow_redirects": True}
                if transport is not None:
                    kwargs["transport"] = transport
                else:
                    kwargs["proxy"] = entry.url
                t0 = time.monotonic()
                try:
                    async with httpx.AsyncClient(**kwargs) as client:
                        resp = await client.get(check_url)
                    ok = resp.status_code < 400
                    err = None if ok else f"HTTP {resp.status_code}"
                except Exception as e:
                    ok, err = False, f"{type(e).__name__}: {e}"[:120]
                latency = time.monotonic() - t0
                if ok:
                    self.report_success(entry, latency)
                else:
                    self.report_failure(entry, err or "")
                return {"proxy": entry.masked, "ok": ok,
                        "latency": round(latency, 3) if ok else None, "error": err}

        tasks = [asyncio.create_task(check(e)) for e in self.entries]
        return list(await asyncio.gather(*tasks))

    def summary(self) -> list[dict]:
        now = time.time()
        out = []
        for e in self.entries:
            s = self.stats[id(e)]
            out.append({
                "proxy": e.masked,                 # SIN credenciales en claro
                "host": e.host, "port": e.port,
                "state": "expulsado" if s.banned_until > now else "ok",
                "requests": s.requests, "successes": s.successes, "failures": s.failures,
                "avg_latency": round(s.avg_latency, 3),
                "banned_remaining": round(max(0.0, s.banned_until - now), 1),
                "last_error": s.last_error,
            })
        return out
