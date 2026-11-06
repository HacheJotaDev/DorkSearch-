"""Constructor de Google Dorks: operadores site:, inurl:, intitle:, filetype:,
intext: y exclusiones, con presets habituales y generación de matrices de
consultas combinadas."""
from __future__ import annotations

from dataclasses import dataclass, field
from itertools import product
from pathlib import Path


@dataclass
class DorkSpec:
    site: list[str] = field(default_factory=list)
    inurl: list[str] = field(default_factory=list)
    intitle: list[str] = field(default_factory=list)
    filetype: list[str] = field(default_factory=list)
    intext: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)


def _group(op: str, values: list[str]) -> str:
    vals = [v for v in values if v]
    if not vals:
        return ""
    if len(vals) == 1:
        return f"{op}{vals[0]}"
    return "(" + " OR ".join(f"{op}{v}" for v in vals) + ")"


def build_query(spec: DorkSpec) -> str:
    parts: list[str] = []
    if spec.site:
        parts.append(_group("site:", spec.site))
    if spec.inurl:
        parts.append(_group("inurl:", spec.inurl))
    if spec.intitle:
        parts.append(_group("intitle:", spec.intitle))
    if spec.filetype:
        parts.append(_group("filetype:", spec.filetype))
    if spec.intext:
        parts.append(_group("intext:", spec.intext))
    for w in spec.exclude:
        parts.append(f'-"{w}"' if " " in w else f"-{w}")
    return " ".join(p for p in parts if p).strip()


class DorkBuilder:
    """API fluida para construir dorks."""

    def __init__(self) -> None:
        self.spec = DorkSpec()

    def site(self, *values: str) -> "DorkBuilder":
        self.spec.site.extend(values)
        return self

    def inurl(self, *values: str) -> "DorkBuilder":
        self.spec.inurl.extend(values)
        return self

    def intitle(self, *values: str) -> "DorkBuilder":
        self.spec.intitle.extend(values)
        return self

    def filetype(self, *values: str) -> "DorkBuilder":
        self.spec.filetype.extend(values)
        return self

    def intext(self, *values: str) -> "DorkBuilder":
        self.spec.intext.extend(values)
        return self

    def exclude(self, *values: str) -> "DorkBuilder":
        self.spec.exclude.extend(values)
        return self

    def build(self) -> str:
        return build_query(self.spec)


# Presets habituales de reconocimiento (SOLO sobre dominios autorizados)
PRESETS: dict[str, DorkSpec] = {
    "php_id": DorkSpec(inurl=[".php?id="]),
    "asp_id": DorkSpec(inurl=[".asp?id="]),
    "jsp_id": DorkSpec(inurl=[".jsp?id="]),
    "param_id_generico": DorkSpec(inurl=["id=", "item=", "product=", "category="]),
    "paginas_login": DorkSpec(intitle=["login", "signin"], inurl=["login", "signin"]),
    "paneles_admin": DorkSpec(intitle=["admin", "panel"], inurl=["admin", "panel"]),
    "listado_directorios": DorkSpec(intitle=["index of"]),
    "backups_sql": DorkSpec(filetype=["sql", "bak"], inurl=["backup", "dump", "db"]),
    "config_env": DorkSpec(filetype=["env", "conf", "cfg"], inurl=["config"]),
    "endpoints_api": DorkSpec(inurl=["api/v1", "api/v2"], filetype=["json"]),
    "formularios_upload": DorkSpec(inurl=["upload"], filetype=["php", "asp", "aspx", "jsp"]),
}

PRESET_NAMES = sorted(PRESETS)


def dorks_from_presets(names: list[str]) -> list[str]:
    out = []
    for n in names:
        if n not in PRESETS:
            raise KeyError(f"Preset desconocido: {n}. Disponibles: {', '.join(PRESET_NAMES)}")
        out.append(build_query(PRESETS[n]))
    return out


def generate_matrix(spec: DorkSpec, inurl_tokens: list[str],
                    filetype_tokens: list[str] | None = None) -> list[str]:
    """Genera consultas combinando inurl: y filetype: (producto cartesiano)."""
    ft_tokens = filetype_tokens or [None]
    queries = []
    for inurl, ft in product(inurl_tokens, ft_tokens):
        s = DorkSpec(
            site=list(spec.site), intitle=list(spec.intitle),
            intext=list(spec.intext), exclude=list(spec.exclude),
            inurl=list(spec.inurl) + [inurl],
            filetype=(list(spec.filetype) + [ft]) if ft else list(spec.filetype),
        )
        q = build_query(s)
        if q:
            queries.append(q)
    return list(dict.fromkeys(queries))


def load_dorks_file(path: str | Path) -> list[str]:
    """Lee un fichero con un dork por línea (# = comentario)."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"No existe el fichero de dorks: {p}")
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def save_dorks_file(path: str | Path, queries: list[str]) -> None:
    Path(path).write_text("\n".join(queries) + "\n", encoding="utf-8")
