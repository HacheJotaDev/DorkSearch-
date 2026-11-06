"""Motor de descubrimiento de URLs con dorks (módulo principal).

Características:
- Cola asyncio + pool de workers (concurrencia configurable).
- Paginación continua por dork con checkpoint en SQLite (reanudación).
- Deduplicación por URL (índice UNIQUE) y filtrado por lista blanca.
- Límite de cuota diaria de peticiones a la API (por fecha UTC).
- Rate limit global (token bucket) + reintentos con backoff exponencial.
- Rotación opcional de proxies residenciales SOLO para respetar límites
  de tasa del servicio autorizado (nunca para evadir controles).
- La lista blanca de dominios autorizados es OBLIGATORIA (o la opción
  explícita allow_unrestricted_search, pensada para laboratorios locales).
"""
from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

import httpx

from ..config import AppConfig
from ..logging_setup import get_logger
from ..models import UrlRecord
from ..storage.database import Database, utcnow
from .api_client import BaseSearchProvider, ProviderError
from .url_filter import UrlFilterer

log = get_logger("engine")


class RateLimiter:
    """Token bucket sencillo para respetar las peticiones por segundo."""

    def __init__(self, rps: float):
        self.interval = 1.0 / rps if rps > 0 else 0.0
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self.interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            wait = self._next - now
            if wait > 0:
                await asyncio.sleep(wait)
                self._next += self.interval
            else:
                self._next = time.monotonic() + self.interval


@dataclass
class SearchRunStats:
    dorks_total: int = 0
    dorks_completed: int = 0
    api_requests: int = 0
    results_seen: int = 0
    results_collected: int = 0
    urls_new: int = 0
    quota_exhausted: bool = False
    started_at: str = ""
    finished_at: str = ""


class SearchEngine:
    def __init__(self, config: AppConfig, provider: BaseSearchProvider, db: Database,
                 filterer: UrlFilterer, proxies=None, batch_size: int = 500):
        self.config = config
        self.provider = provider
        self.db = db
        self.filterer = filterer
        self.proxies = proxies
        self.batch_size = max(10, batch_size)
        self.rate = RateLimiter(config.search.rate_limit_rps)
        self.on_log: Optional[Callable[[str], None]] = None
        self.on_progress: Optional[Callable[[str, int, int], None]] = None
        self.on_urls: Optional[Callable[[list[dict]], None]] = None
        self.paused = asyncio.Event()
        self.paused.set()          # set = en ejecución; clear = pausado
        self.stopped = asyncio.Event()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._queue: Optional[asyncio.Queue] = None
        self._buffer: list[UrlRecord] = []
        self.stats = SearchRunStats()

    # ---------- control (seguro desde otros hilos vía call_soon_threadsafe) ----------
    def attach_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def pause(self) -> None:
        self.paused.clear()
        self._emit_log("Búsqueda PAUSADA")

    def resume(self) -> None:
        self.paused.set()
        self._emit_log("Búsqueda REANUDADA")

    def stop(self) -> None:
        self.stopped.set()
        self.paused.set()
        self._emit_log("Búsqueda DETENIDA por el usuario")

    def _emit_log(self, msg: str) -> None:
        log.info(msg)
        if self.on_log:
            try:
                self.on_log(msg)
            except Exception:
                pass

    async def _checkpoint_wait(self) -> None:
        await self.paused.wait()

    # ---------- ejecución principal ----------
    async def run(self, dorks: list[str]) -> SearchRunStats:
        if not self.config.search.authorized_domains and not self.config.search.allow_unrestricted_search:
            raise RuntimeError(
                "Búsqueda bloqueada: define search.authorized_domains (lista blanca "
                "OBLIGATORIA) o activa explícitamente allow_unrestricted_search=true "
                "solo para laboratorios locales."
            )
        self.stopped.clear()
        self.paused.set()
        self._buffer.clear()
        self.stats = SearchRunStats()
        self.stats.started_at = utcnow()
        self._loop = asyncio.get_running_loop()

        dorks = list(dict.fromkeys(d.strip() for d in dorks if d.strip()))
        done = {t["query"] for t in self.db.get_dork_tasks(status="done")}
        pending = [d for d in dorks if d not in done]
        self.stats.dorks_total = len(dorks)
        if not pending:
            self._emit_log("Nada pendiente: todos los dorks ya estaban completados.")
            self.stats.dorks_completed = len(done)
            self.stats.finished_at = utcnow()
            return self.stats

        self._emit_log(
            f"Iniciando búsqueda con proveedor '{self.provider.name}': "
            f"{len(pending)} dork(s) pendientes de {len(dorks)}"
        )
        self._queue = asyncio.Queue(maxsize=max(2, self.config.search.concurrency * 4))
        workers = [
            asyncio.create_task(self._worker(i))
            for i in range(max(1, self.config.search.concurrency))
        ]
        producer = asyncio.create_task(self._producer(pending))
        try:
            await producer
            # Los jobs encolan los siguientes dinámicamente: join() espera a que
            # TODOS estén procesados (cada get() termina en task_done()).
            await self._queue.join()
        finally:
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
        self._flush_buffer()
        self.stats.dorks_completed = self.db.count_dork_tasks(status="done")
        self.stats.finished_at = utcnow()
        self._emit_log(
            f"Búsqueda finalizada: {self.stats.urls_new} URLs nuevas · "
            f"{self.stats.api_requests} peticiones API · cuota agotada: {self.stats.quota_exhausted}"
        )
        return self.stats

    async def _producer(self, pending: list[str]) -> None:
        for query in pending:
            if self.stopped.is_set():
                break
            await self._checkpoint_wait()
            task = next((t for t in self.db.get_dork_tasks() if t["query"] == query), None)
            start = int(task["next_start"]) if task and task.get("next_start") else 1
            results_so_far = int(task["results"]) if task and task.get("results") else 0
            if task is None:
                self.db.upsert_dork_task(query, self.provider.name, next_start=start, status="running")
            else:
                self.db.upsert_dork_task(query, status="running")
            self._emit_log(f"Dork en cola (checkpoint start={start}): {query}")
            await self._enqueue(query, start, results_so_far)

    async def _enqueue(self, query: str, start: int, results_so_far: int) -> None:
        if self.stopped.is_set() or self._queue is None:
            return
        await self._queue.put((query, start, results_so_far))

    async def _worker(self, wid: int) -> None:
        while True:
            job = await self._queue.get()
            try:
                # Si está detenido, consume y descarta (mantiene join consistente);
                # si está pausado, espera en el checkpoint.
                await self._checkpoint_wait()
                if not self.stopped.is_set():
                    await self._process_job(job)
            except asyncio.CancelledError:
                return
            except Exception as e:  # nunca tumba el motor
                self._emit_log(f"Error en worker {wid}: {type(e).__name__}: {e}")
            finally:
                if self._queue is not None:
                    self._queue.task_done()

    async def _process_job(self, job: tuple[str, int, int]) -> None:
        query, start, results_so_far = job
        cfg = self.config.search

        if self.stats.results_collected >= cfg.max_total_results:
            self._emit_log("Se alcanzó max_total_results: deteniendo el motor.")
            self.stopped.set()
            return
        if not self.db.quota_used_today() < cfg.max_api_requests_per_day:
            self.stats.quota_exhausted = True
            self._emit_log("Cuota diaria de la API agotada: deteniendo el motor.")
            self.stopped.set()
            return
        if results_so_far >= cfg.max_results_per_dork or start > self.provider.max_start:
            self._mark_done(query, "completado")
            return

        per_page = max(1, min(cfg.results_per_page, self.provider.max_per_page))
        page = None
        attempts = 0
        while attempts <= cfg.max_retries:
            if self.stopped.is_set():
                return
            try:
                await self.rate.acquire()
                page = await self._fetch_page(query, start, per_page)
                break
            except ProviderError as e:
                if not e.retryable or attempts == cfg.max_retries:
                    self._emit_log(f"Dork '{query}' falla en start={start}: {e}")
                    self.db.upsert_dork_task(query, status="error", next_start=start)
                    return
                delay = cfg.backoff_base_seconds * (2 ** attempts) + random.uniform(0, 0.3)
                attempts += 1
                self._emit_log(
                    f"Reintento {attempts}/{cfg.max_retries} tras error ({e}) en {delay:.1f}s"
                )
                await asyncio.sleep(delay)

        if page is None:
            return
        self.db.quota_add(1)
        self.stats.api_requests += 1
        self.stats.results_seen += len(page.results)
        self._consume_page(query, page)

        collected = results_so_far + len(page.results)
        if page.results and start + per_page <= self.provider.max_start \
                and collected < cfg.max_results_per_dork and not self.stopped.is_set():
            self.db.upsert_dork_task(query, next_start=start + per_page,
                                     add_results=len(page.results))
            await self._enqueue(query, start + per_page, collected)
        else:
            self._mark_done(query, "completado" if page.results else "sin-resultados")
        if self.on_progress:
            try:
                self.on_progress(query, start, self.stats.urls_new)
            except Exception:
                pass

    def _mark_done(self, query: str, reason: str) -> None:
        self.db.upsert_dork_task(query, status="done")
        self._emit_log(f"Dork finalizado ({reason}): {query}")

    async def _fetch_page(self, query: str, start: int, num: int):
        proxy = None
        if self.proxies is not None:
            proxy = self.proxies.acquire()
            if proxy is None:
                self._emit_log("Sin proxies disponibles ahora mismo; se continúa sin proxy.")
        client_kwargs: dict = {
            "timeout": httpx.Timeout(30.0),
            "headers": {"User-Agent": self.config.search.user_agent},
            "follow_redirects": True,
        }
        transport = getattr(self.provider, "_transport", None)
        if transport is not None:
            client_kwargs["transport"] = transport
        elif proxy is not None:
            client_kwargs["proxy"] = proxy.url
        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                page = await self.provider.fetch(client, query, start, num)
        except httpx.HTTPError as e:
            if proxy is not None and self.proxies is not None:
                self.proxies.report_failure(proxy, str(e))
            raise ProviderError(f"Error de red: {type(e).__name__}: {e}", retryable=True) from e
        if proxy is not None and self.proxies is not None:
            self.proxies.report_success(proxy, time.monotonic() - t0)
        return page

    def _consume_page(self, query: str, page) -> None:
        accepted: list[UrlRecord] = []
        for raw in page.results:
            url = (raw.url or "").strip()
            if not url:
                continue
            ok, reason = self.filterer.check(url)
            if not ok:
                continue
            rec = UrlRecord.from_url(url, source=self.provider.name, dork=query, timestamp=utcnow())
            if rec is not None:
                accepted.append(rec)
        if accepted:
            self._buffer.extend(accepted)
            self.stats.results_collected += len(accepted)
            if len(self._buffer) >= self.batch_size:
                self._flush_buffer()
            if self.on_urls:
                try:
                    self.on_urls([r.__dict__.copy() for r in accepted])
                except Exception:
                    pass

    def _flush_buffer(self) -> None:
        if not self._buffer:
            return
        inserted = self.db.add_urls(self._buffer, batch_size=self.batch_size)
        self.stats.urls_new += inserted
        self._buffer.clear()
