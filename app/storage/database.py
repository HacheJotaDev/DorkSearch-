"""Almacenamiento SQLite: URLs con índice de deduplicación, tareas de dorks
con checkpoint (reanudación), cuota diaria de la API, registro de auditoría
y hallazgos. Diseñado para millones de registros sin cargar todo en memoria
(paginación por keyset + escritura por lotes)."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Optional

from ..models import Finding, UrlRecord

SCHEMA = """
CREATE TABLE IF NOT EXISTS urls(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    domain TEXT NOT NULL DEFAULT '',
    path TEXT DEFAULT '',
    query TEXT DEFAULT '',
    ext TEXT DEFAULT '',
    params_count INTEGER DEFAULT 0,
    db_related TEXT DEFAULT '',
    priority INTEGER DEFAULT 0,
    source TEXT DEFAULT '',
    dork TEXT DEFAULT '',
    discovered_at TEXT DEFAULT '',
    analyzed INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_urls_domain ON urls(domain);
CREATE INDEX IF NOT EXISTS idx_urls_priority ON urls(priority);
CREATE INDEX IF NOT EXISTS idx_urls_analyzed ON urls(analyzed);

CREATE TABLE IF NOT EXISTS dork_tasks(
    query TEXT PRIMARY KEY,
    provider TEXT DEFAULT '',
    next_start INTEGER DEFAULT 1,
    status TEXT DEFAULT 'pending',
    results INTEGER DEFAULT 0,
    updated_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS audit_log(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    url TEXT,
    status_code INTEGER,
    elapsed_ms REAL,
    note TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_url ON audit_log(url);

CREATE TABLE IF NOT EXISTS findings(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    url TEXT,
    param TEXT,
    technique TEXT,
    dbms TEXT,
    evidence TEXT,
    details TEXT,
    request_json TEXT,
    snippets TEXT,
    remediation TEXT
);

CREATE TABLE IF NOT EXISTS meta(
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: str | Path = "data/urls.db"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    # ---------------- URLs ----------------

    def _insert_rows(self, rows: list[tuple]) -> int:
        if not rows:
            return 0
        with self._lock:
            cur = self.conn.executemany(
                "INSERT OR IGNORE INTO urls(url, domain, path, query, ext, params_count, "
                "db_related, priority, source, dork, discovered_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                rows,
            )
            self.conn.commit()
            return cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0

    def add_urls(self, records: Iterable[UrlRecord], batch_size: int = 500) -> int:
        """Inserción por lotes con deduplicación por URL (UNIQUE + INSERT OR IGNORE)."""
        inserted = 0
        buf: list[tuple] = []
        for r in records:
            buf.append(r.to_row())
            if len(buf) >= batch_size:
                inserted += self._insert_rows(buf)
                buf = []
        inserted += self._insert_rows(buf)
        return inserted

    def iter_urls(
        self,
        batch: int = 500,
        domain: Optional[str] = None,
        ext: Optional[str] = None,
        has_params: bool = False,
        min_priority: Optional[int] = None,
        analyzed: Optional[bool] = None,
        dork: Optional[str] = None,
    ) -> Iterator[dict]:
        """Itera por keyset (id > last): apto para millones de filas."""
        where: list[str] = []
        args: list = []
        if domain:
            where.append("domain = ?")
            args.append(domain.lower())
        if ext:
            where.append("ext = ?")
            args.append(ext.lower())
        if has_params:
            where.append("params_count > 0")
        if min_priority is not None:
            where.append("priority >= ?")
            args.append(min_priority)
        if analyzed is True:
            where.append("analyzed = 1")
        elif analyzed is False:
            where.append("analyzed = 0")
        if dork:
            where.append("dork = ?")
            args.append(dork)
        cond = ("WHERE " + " AND ".join(where)) if where else ""
        last = 0
        while True:
            extra = "AND" if where else "WHERE"
            sql = f"SELECT * FROM urls {cond} {extra} id > ? ORDER BY id LIMIT ?"
            rows = self.conn.execute(sql, (*args, last, batch)).fetchall()
            if not rows:
                break
            for r in rows:
                yield dict(r)
            last = rows[-1]["id"]
            if len(rows) < batch:
                break

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) c FROM urls").fetchone()["c"]

    def update_analysis(self, rows: list[tuple]) -> None:
        """rows: (params_count, db_related, priority, url)"""
        if not rows:
            return
        with self._lock:
            self.conn.executemany(
                "UPDATE urls SET params_count=?, db_related=?, priority=?, analyzed=1 WHERE url=?",
                rows,
            )
            self.conn.commit()

    def stats(self) -> dict:
        c = self.conn.execute
        total = c("SELECT COUNT(*) c FROM urls").fetchone()["c"]
        with_params = c("SELECT COUNT(*) c FROM urls WHERE params_count > 0").fetchone()["c"]
        analyzed = c("SELECT COUNT(*) c FROM urls WHERE analyzed = 1").fetchone()["c"]
        high = c("SELECT COUNT(*) c FROM urls WHERE priority >= 60").fetchone()["c"]
        medium = c("SELECT COUNT(*) c FROM urls WHERE priority >= 30 AND priority < 60").fetchone()["c"]
        domains = [dict(r) for r in c(
            "SELECT domain, COUNT(*) AS count FROM urls GROUP BY domain ORDER BY count DESC LIMIT 10")]
        exts = [dict(r) for r in c(
            "SELECT ext, COUNT(*) AS count FROM urls WHERE ext != '' GROUP BY ext ORDER BY count DESC LIMIT 10")]
        return {
            "total_urls": total,
            "with_params": with_params,
            "analyzed": analyzed,
            "high_priority": high,
            "medium_priority": medium,
            "unique_domains": len(c("SELECT DISTINCT domain FROM urls").fetchall()),
            "top_domains": domains,
            "top_extensions": exts,
            "dorks_done": self.count_dork_tasks("done"),
            "dorks_total": self.count_dork_tasks(),
            "quota_used_today": self.quota_used_today(),
            "findings": c("SELECT COUNT(*) c FROM findings").fetchone()["c"],
        }

    # ------------- Tareas de dorks (checkpoint / reanudación) -------------

    def upsert_dork_task(self, query: str, provider: Optional[str] = None,
                         next_start: Optional[int] = None, status: Optional[str] = None,
                         add_results: int = 0) -> None:
        with self._lock:
            row = self.conn.execute("SELECT * FROM dork_tasks WHERE query=?", (query,)).fetchone()
            if row is None:
                self.conn.execute(
                    "INSERT INTO dork_tasks(query, provider, next_start, status, results, updated_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (query, provider or "", next_start or 1, status or "pending", add_results, utcnow()),
                )
            else:
                ns = row["next_start"] if next_start is None else next_start
                st = row["status"] if status is None else status
                self.conn.execute(
                    "UPDATE dork_tasks SET provider=COALESCE(NULLIF(?,''), provider), "
                    "next_start=?, status=?, results=results+?, updated_at=? WHERE query=?",
                    (provider or "", ns, st, add_results, utcnow(), query),
                )
            self.conn.commit()

    def get_dork_tasks(self, status: Optional[str] = None) -> list[dict]:
        q = "SELECT * FROM dork_tasks"
        args: tuple = ()
        if status:
            q += " WHERE status=?"
            args = (status,)
        q += " ORDER BY rowid"
        return [dict(r) for r in self.conn.execute(q, args).fetchall()]

    def pending_dorks(self) -> list[dict]:
        return [t for t in self.get_dork_tasks() if t["status"] in ("pending", "running", "error")]

    def count_dork_tasks(self, status: Optional[str] = None) -> int:
        q = "SELECT COUNT(*) c FROM dork_tasks"
        args: tuple = ()
        if status:
            q += " WHERE status=?"
            args = (status,)
        return self.conn.execute(q, args).fetchone()["c"]

    # ---------------- Cuota diaria ----------------

    def quota_key(self) -> str:
        return f"quota:{datetime.now(timezone.utc):%Y-%m-%d}"

    def quota_used_today(self) -> int:
        v = self.meta_get(self.quota_key())
        try:
            return int(v or 0)
        except ValueError:
            return 0

    def quota_add(self, n: int = 1) -> int:
        used = self.quota_used_today() + n
        self.meta_set(self.quota_key(), str(used))
        return used

    # ---------------- meta ----------------

    def meta_get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def meta_set(self, key: str, value: str) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO meta(key, value) VALUES (?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
            self.conn.commit()

    # ---------------- Auditoría ----------------

    def add_audit_log(self, entries: Iterable[dict], batch: int = 200) -> None:
        buf: list[tuple] = []
        for e in entries:
            buf.append((
                e.get("ts") or utcnow(), e.get("url", ""), e.get("status_code"),
                e.get("elapsed_ms"), e.get("note", ""),
            ))
            if len(buf) >= batch:
                self._insert_audit(buf)
                buf = []
        self._insert_audit(buf)

    def _insert_audit(self, rows: list[tuple]) -> None:
        if not rows:
            return
        with self._lock:
            self.conn.executemany(
                "INSERT INTO audit_log(ts, url, status_code, elapsed_ms, note) VALUES (?,?,?,?,?)",
                rows,
            )
            self.conn.commit()

    def add_findings(self, findings: list[Finding], batch: int = 100) -> None:
        rows = []
        for f in findings:
            rows.append((
                f.timestamp or utcnow(), f.url, f.param, f.technique, f.dbms, f.evidence,
                f.details, json.dumps(f.request_snapshot, ensure_ascii=False),
                json.dumps(f.evidence_snippets, ensure_ascii=False),
                json.dumps(f.remediation, ensure_ascii=False),
            ))
            if len(rows) >= batch:
                self._insert_findings(rows)
                rows = []
        self._insert_findings(rows)

    def _insert_findings(self, rows: list[tuple]) -> None:
        if not rows:
            return
        with self._lock:
            self.conn.executemany(
                "INSERT INTO findings(ts, url, param, technique, dbms, evidence, details, "
                "request_json, snippets, remediation) VALUES (?,?,?,?,?,?,?,?,?,?)",
                rows,
            )
            self.conn.commit()

    def list_findings(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM findings ORDER BY id DESC").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            for key in ("request_json", "snippets", "remediation"):
                try:
                    d[key] = json.loads(d.get(key) or "[]")
                except (json.JSONDecodeError, TypeError):
                    d[key] = []
            out.append(d)
        return out
