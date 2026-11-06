"""Analizador de parámetros de URLs.

Clasifica las URLs descubiertas según su superficie potencial para consultas
a bases de datos, con el fin de PRIORIZAR la revisión manual autorizada:

- Detecta parámetros GET y nombres relacionados con BD (id, item, product,
  category, search, ...).
- Detecta rutas dinámicas (segmentos numéricos / UUID).
- Asigna una puntuación de prioridad (0-100) para ordenar la revisión.
- Genera estadísticas agregadas.

AVISO IMPORTANTE: que una URL tenga parámetros NO significa que exista
inyección SQL. Este módulo NO confirma vulnerabilidades; solo prioriza.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit
from typing import Iterable, Iterator, Optional

STRONG_DB_PARAMS = {
    "id", "uid", "pid", "cid", "aid", "bid", "tid", "rid", "mid", "sid", "fid", "nid",
    "user_id", "userid", "productid", "product_id", "itemid", "item_id",
    "categoryid", "category_id", "cat_id",
    "item", "product", "prod", "category", "cat", "article", "news", "post",
    "record", "entry", "page_id", "order_id", "ref_id",
}
SOFT_DB_PARAMS = {
    "search", "q", "query", "keyword", "keywords", "s", "view", "show", "display",
    "user", "username", "email", "name", "code", "num", "no", "n", "ref", "filter",
    "sort", "order", "orderby", "group", "type", "class", "action", "do", "cmd",
    "file", "path", "doc", "download", "lang", "module", "task", "option",
}
ID_SUFFIX_RE = re.compile(r"(?:^|_)id$", re.IGNORECASE)
NUMERIC_RE = re.compile(r"^\d+$")
DYNAMIC_PATH_RE = re.compile(
    r"^(?:\d+|[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12})$", re.IGNORECASE
)
DYNAMIC_EXT = {"php", "asp", "aspx", "jsp", "cfm", "cgi", "pl"}


def priority_label(p: int) -> str:
    return "ALTA" if p >= 60 else "MEDIA" if p >= 30 else "BAJA" if p > 0 else "NULA"


@dataclass
class UrlAnalysis:
    url: str
    params: dict = field(default_factory=dict)
    db_related: list = field(default_factory=list)
    dynamic_path_segments: list = field(default_factory=list)
    priority: int = 0
    category: str = "static"        # parameterized | dynamic_path | static
    notes: str = ""


class ParamAnalyzer:
    def analyze(self, url: str) -> UrlAnalysis:
        try:
            parts = urlsplit(url.strip())
        except ValueError:
            return UrlAnalysis(url=url, notes="url inválida")
        if not parts.scheme or not parts.hostname:
            return UrlAnalysis(url=url, notes="url no http(s)")

        qs = parse_qsl(parts.query, keep_blank_values=True)
        params = {k: v for k, v in qs}
        db_related: list[str] = []
        score = 0

        for name, value in params.items():
            n = name.lower()
            strong = n in STRONG_DB_PARAMS or bool(ID_SUFFIX_RE.search(n))
            soft = n in SOFT_DB_PARAMS
            if strong:
                if name not in db_related:
                    db_related.append(name)
                score += 15
            elif soft:
                if name not in db_related:
                    db_related.append(name)
                score += 6
            if NUMERIC_RE.match(value or ""):
                score += 6

        dyn_segments = [s for s in parts.path.split("/") if s and DYNAMIC_PATH_RE.match(s)]
        if dyn_segments:
            score += 10 * min(len(dyn_segments), 2)

        last_seg = parts.path.rsplit("/", 1)[-1]
        ext = last_seg.rsplit(".", 1)[-1].lower() if "." in last_seg else ""
        if ext in DYNAMIC_EXT:
            score += 8

        score += min(len(params), 5) * 2

        if params:
            category = "parameterized"
        elif dyn_segments:
            category = "dynamic_path"
        else:
            category = "static"
        if not params and not dyn_segments:
            score = 0

        return UrlAnalysis(
            url=url, params=params, db_related=db_related,
            dynamic_path_segments=dyn_segments,
            priority=min(score, 100), category=category,
        )

    def analyze_batch(self, urls: Iterable[str]) -> Iterator[UrlAnalysis]:
        for u in urls:
            yield self.analyze(u)

    @staticmethod
    def stats(analyses: Iterable[UrlAnalysis]) -> dict:
        items = list(analyses)
        param_counter: Counter = Counter()
        for a in items:
            for p in a.db_related:
                param_counter[p.lower()] += 1
        with_params = sum(1 for a in items if a.category == "parameterized")
        dyn = sum(1 for a in items if a.category == "dynamic_path")
        return {
            "total": len(items),
            "parameterized": with_params,
            "dynamic_path": dyn,
            "static": len(items) - with_params - dyn,
            "high_priority": sum(1 for a in items if a.priority >= 60),
            "medium_priority": sum(1 for a in items if 30 <= a.priority < 60),
            "top_params": param_counter.most_common(15),
        }


def analyze_database(db, analyzer: Optional[ParamAnalyzer] = None, batch_size: int = 500,
                     progress: Optional[Callable[[int], None]] = None) -> dict:
    """Analiza todas las URLs no analizadas de la base de datos (streaming)."""
    analyzer = analyzer or ParamAnalyzer()
    rows: list[tuple] = []
    total = 0
    for row in db.iter_urls(batch=batch_size, analyzed=False):
        a = analyzer.analyze(row["url"])
        rows.append((len(a.params), ",".join(a.db_related), a.priority, row["url"]))
        total += 1
        if len(rows) >= batch_size:
            db.update_analysis(rows)
            if progress:
                progress(total)
            rows = []
    if rows:
        db.update_analysis(rows)
    return {"analyzed": total}
