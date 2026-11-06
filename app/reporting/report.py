"""Generación de informes de auditoría (JSON + Markdown)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def generate_report(findings: list, scope_domains: list[str],
                    out_json: str | Path | None = None,
                    out_md: str | Path | None = None,
                    meta: dict | None = None) -> dict:
    doc = {
        "generated_at": _ts(),
        "tool": "Advanced URL Discovery & SQLi Security Auditor",
        "scope": {
            "authorized_domains": scope_domains,
            "authorization_note": (
                "Auditoría limitada EXCLUSIVAMENTE a los dominios autorizados por el "
                "propietario del sistema. Verificación de alcance antes de cada petición."
            ),
        },
        "context": meta or {},
        "summary": {
            "targets_audited": (meta or {}).get("targets", 0),
            "findings": len(findings),
            "confirmed": sum(1 for f in findings if f.evidence == "CONFIRMED"),
            "likely": sum(1 for f in findings if f.evidence == "LIKELY"),
            "possible": sum(1 for f in findings if f.evidence == "POSSIBLE"),
            "info": sum(1 for f in findings if f.evidence == "INFO"),
        },
        "methodology": [
            "Detección NO destructiva: firmas de error de BD y comparación booleana (1=1 vs 1=2).",
            "No se extraen datos, no se enumeran credenciales, no se evaden controles ni WAFs.",
            "Cada petición se valida contra la lista blanca autorizada antes de ejecutarse.",
            "Las sondas se repiten para verificar reproducibilidad y se usan payloads de "
            "control aleatorios para descartar falsos positivos.",
        ],
        "findings": [f.to_dict() for f in findings],
    }
    if out_json:
        p = Path(out_json)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
    if out_md:
        p = Path(out_md)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(render_markdown(doc), encoding="utf-8")
    return doc


def render_markdown(doc: dict) -> str:
    lines: list[str] = []
    lines.append("# Informe de auditoría SQLi (no destructiva)")
    lines.append("")
    lines.append(f"- **Generado:** {doc['generated_at']}")
    lines.append(f"- **Herramienta:** {doc['tool']}")
    ctx = doc.get("context") or {}
    if ctx:
        lines.append(f"- **Contexto:** {json.dumps(ctx, ensure_ascii=False)}")
    lines.append("")
    lines.append("## Alcance autorizado")
    lines.append("")
    for d in doc["scope"]["authorized_domains"]:
        lines.append(f"- `{d}`")
    lines.append(f"> {doc['scope']['authorization_note']}")
    lines.append("")
    s = doc["summary"]
    lines.append("## Resumen")
    lines.append("")
    lines.append(f"- Objetivos auditados: **{s['targets_audited']}**")
    lines.append(f"- Hallazgos: **{s['findings']}** "
                 f"(Confirmados: {s['confirmed']} · Probables: {s['likely']} · "
                 f"Posibles: {s['possible']} · Informativos: {s['info']})")
    lines.append("")
    lines.append("## Hallazgos")
    lines.append("")
    if not doc["findings"]:
        lines.append("Sin hallazgos: no se detectaron indicios de inyección SQL con "
                     "las técnicas no destructivas en los objetivos auditados.")
        lines.append("")
    for i, f in enumerate(doc["findings"], 1):
        lines.append(f"### {i}. [{f['evidence']}] {f['url']} — parámetro `{f['param']}`")
        lines.append("")
        lines.append(f"- **Técnica:** {f['technique']} · **Motor:** {f['dbms'] or 'no determinado'}")
        lines.append(f"- **Detalle:** {f['details']}")
        if f.get("evidence_snippets"):
            ev = "; ".join(f"`{sn}`" for sn in f["evidence_snippets"][:3])
            lines.append(f"- **Evidencia:** {ev}")
        snap = json.dumps(f.get("request_snapshot", {}), ensure_ascii=False)
        lines.append(f"- **Snapshot de la petición (reproducibilidad):** `{snap}`")
        lines.append("- **Recomendaciones:**")
        for r in f.get("remediation", []):
            lines.append(f"    - {r}")
        lines.append("")
    lines.append("## Metodología")
    lines.append("")
    for m in doc["methodology"]:
        lines.append(f"- {m}")
    return "\n".join(lines) + "\n"
