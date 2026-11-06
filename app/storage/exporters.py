"""Exportación a TXT / CSV / JSON.

Todos los exportadores aceptan un ITERADOR de filas (dicts) para poder
exportar millones de registros sin cargarlos en memoria.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable

CSV_COLUMNS = [
    "url", "domain", "path", "query", "ext",
    "params_count", "db_related", "priority", "dork", "discovered_at",
]


def export_txt(path: str | Path, rows: Iterable[dict]) -> int:
    """Una URL por línea (formato clásico para herramientas de auditoría)."""
    n = 0
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(r["url"] + "\n")
            n += 1
    return n


def export_csv(path: str | Path, rows: Iterable[dict]) -> int:
    n = 0
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in CSV_COLUMNS})
            n += 1
    return n


def export_json(path: str | Path, rows: Iterable[dict]) -> int:
    """JSON en streaming (abre/escribe/cierra el array por lotes)."""
    n = 0
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("[\n")
        first = True
        for r in rows:
            item = {k: r.get(k, "") for k in CSV_COLUMNS}
            if not first:
                f.write(",\n")
            f.write("  " + json.dumps(item, ensure_ascii=False))
            first = False
            n += 1
        f.write("\n]\n")
    return n


def export_auto(path: str | Path, rows: Iterable[dict]) -> int:
    """Elige el formato por la extensión del fichero: .txt / .csv / .json."""
    ext = Path(path).suffix.lower()
    if ext == ".txt":
        return export_txt(path, rows)
    if ext == ".csv":
        return export_csv(path, rows)
    if ext == ".json":
        return export_json(path, rows)
    raise ValueError(f"Extensión de export no soportada: {ext} (usa .txt, .csv o .json)")
