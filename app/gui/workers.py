"""Workers de fondo para la GUI: QThread + asyncio sin bloquear la interfaz."""
from __future__ import annotations

import asyncio

from PySide6.QtCore import QObject, QThread, Signal


class WorkerSignals(QObject):
    log = Signal(str)
    progress = Signal(str, int, int)      # dork, start, urls_nuevas
    urls = Signal(list)                   # lote de dicts de URLs
    stats = Signal(dict)
    findings = Signal(list)               # lista de Finding
    done = Signal(object)                 # resultado final
    error = Signal(str)


class SearchWorker(QThread):
    """Ejecuta SearchEngine en un hilo propio con su propio event loop."""

    def __init__(self, engine, dorks: list[str], parent=None):
        super().__init__(parent)
        self.engine = engine
        self.dorks = dorks
        self.signals = WorkerSignals()
        engine.on_log = lambda m: self.signals.log.emit(str(m))
        engine.on_progress = lambda d, s, n: self.signals.progress.emit(str(d), int(s), int(n))
        engine.on_urls = lambda batch: self.signals.urls.emit(list(batch))

    def run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self.engine.attach_loop(loop)
        try:
            stats = loop.run_until_complete(self.engine.run(self.dorks))
            self.signals.done.emit(vars(stats))
        except Exception as e:
            self.signals.error.emit(f"{type(e).__name__}: {e}")
        finally:
            try:
                loop.close()
            except Exception:
                pass

    def _call(self, fn) -> None:
        if self.engine._loop is not None:
            self.engine._loop.call_soon_threadsafe(fn)

    def pause(self) -> None:
        self._call(self.engine.pause)

    def resume(self) -> None:
        self._call(self.engine.resume)

    def stop(self) -> None:
        self._call(self.engine.stop)


class ProxyCheckWorker(QThread):
    """Verifica la conectividad de todos los proxies de forma asíncrona."""

    def __init__(self, manager, check_url: str, timeout: float, concurrency: int, parent=None):
        super().__init__(parent)
        self.manager = manager
        self.check_url = check_url
        self.timeout = timeout
        self.concurrency = concurrency
        self.signals = WorkerSignals()

    def run(self) -> None:
        async def job():
            return await self.manager.check_all(self.check_url, self.timeout, self.concurrency)

        try:
            results = asyncio.run(job())
            self.signals.done.emit(results)
        except Exception as e:
            self.signals.error.emit(f"{type(e).__name__}: {e}")


class AuditWorker(QThread):
    """Ejecuta la auditoría SQLi no destructiva fuera del hilo de la UI."""

    def __init__(self, urls: list[str], allowed_domains: list[str], techniques: tuple,
                 timeout: float, db=None, user_agent: str = "uds-auditor/1.0",
                 max_requests: int = 200, parent=None):
        super().__init__(parent)
        self.urls = urls
        self.allowed_domains = allowed_domains
        self.techniques = techniques
        self.timeout = timeout
        self.db = db
        self.user_agent = user_agent
        self.max_requests = max_requests
        self.signals = WorkerSignals()

    def run(self) -> None:
        from ..sqli.runner import run_audit
        try:
            findings = asyncio.run(run_audit(
                self.urls, self.allowed_domains, techniques=self.techniques,
                timeout=self.timeout, db=self.db, user_agent=self.user_agent,
                max_requests=self.max_requests,
                log_cb=lambda url, fs: self.signals.log.emit(
                    f"{url} → {len(fs)} hallazgo(s)"),
            ))
            self.signals.done.emit(findings)
        except Exception as e:
            self.signals.error.emit(f"{type(e).__name__}: {e}")
