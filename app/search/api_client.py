"""Proveedores de búsqueda autorizada.

- GoogleCSEProvider: Google Custom Search JSON API (requiere GOOGLE_API_KEY
  y GOOGLE_CSE_ID en variables de entorno / .env).
- SerpAPIProvider: API comercial SerpAPI (requiere SERPAPI_KEY).
- OfflineReplayProvider: proveedor SIN RED con fixtures deterministas para
  pruebas automatizadas y demostraciones.

Nunca se hace scraping no autorizado de Google: solo APIs con credencial.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..config import get_credentials
from ..models import SearchPage


class ProviderError(Exception):
    def __init__(self, message: str, retryable: bool = False, status: int | None = None):
        super().__init__(message)
        self.retryable = retryable
        self.status = status


@dataclass
class RawResult:
    url: str
    title: str = ""
    snippet: str = ""


class BaseSearchProvider(ABC):
    name = "base"
    max_per_page = 10
    max_start = 91

    def __init__(self, transport=None):
        self._transport = transport

    @abstractmethod
    async def fetch(self, client, query: str, start: int, num: int) -> SearchPage: ...


def _raise_http(resp) -> None:
    retryable = resp.status_code in (429, 500, 502, 503, 504)
    raise ProviderError(
        f"HTTP {resp.status_code} del proveedor de búsqueda: {resp.text[:200]}",
        retryable=retryable,
        status=resp.status_code,
    )


class GoogleCSEProvider(BaseSearchProvider):
    """Google Custom Search JSON API (límite de paginación: start <= 91)."""

    name = "google_cse"
    max_per_page = 10
    max_start = 91
    ENDPOINT = "https://www.googleapis.com/customsearch/v1"

    def __init__(self, api_key: str | None = None, cx: str | None = None, transport=None):
        super().__init__(transport)
        creds = get_credentials()
        self.api_key = api_key or creds["GOOGLE_API_KEY"]
        self.cx = cx or creds["GOOGLE_CSE_ID"]
        if not self.api_key or not self.cx:
            raise ProviderError(
                "Faltan GOOGLE_API_KEY / GOOGLE_CSE_ID. Copia .env.example a .env y "
                "define tus credenciales de la API de Google Custom Search.",
                retryable=False,
            )

    async def fetch(self, client, query: str, start: int, num: int) -> SearchPage:
        num = max(1, min(num, self.max_per_page))
        resp = await client.get(
            self.ENDPOINT,
            params={"key": self.api_key, "cx": self.cx, "q": query,
                    "num": num, "start": start},
        )
        if resp.status_code != 200:
            _raise_http(resp)
        data = resp.json()
        if "error" in data:
            raise ProviderError(str(data["error"].get("message", "error de la API")),
                                retryable=False)
        items = data.get("items") or []
        results = [
            RawResult(url=i.get("link", ""), title=i.get("title", ""), snippet=i.get("snippet", ""))
            for i in items
        ]
        results = [r for r in results if r.url]
        total = int(data.get("searchInformation", {}).get("totalResults", 0) or 0)
        return SearchPage(query=query, start=start, results=results, total=total,
                          provider=self.name)


class SerpAPIProvider(BaseSearchProvider):
    """SerpAPI (engine=google). Soporta paginación amplia vía start."""

    name = "serpapi"
    max_per_page = 100
    max_start = 901
    ENDPOINT = "https://serpapi.com/search.json"

    def __init__(self, api_key: str | None = None, transport=None):
        super().__init__(transport)
        creds = get_credentials()
        self.api_key = api_key or creds["SERPAPI_KEY"]
        if not self.api_key:
            raise ProviderError("Falta SERPAPI_KEY en las variables de entorno (.env).",
                                retryable=False)

    async def fetch(self, client, query: str, start: int, num: int) -> SearchPage:
        num = max(1, min(num, self.max_per_page))
        resp = await client.get(
            self.ENDPOINT,
            params={"engine": "google", "q": query, "num": num, "start": start,
                    "api_key": self.api_key},
        )
        if resp.status_code != 200:
            _raise_http(resp)
        data = resp.json()
        if data.get("error"):
            raise ProviderError(str(data["error"]), retryable=False)
        organic = data.get("organic_results") or []
        results = [RawResult(url=o.get("link", ""), title=o.get("title", ""),
                             snippet=o.get("snippet", "")) for o in organic]
        results = [r for r in results if r.url]
        total = int(data.get("search_information", {}).get("total_results", 0) or 0)
        return SearchPage(query=query, start=start, results=results, total=total,
                          provider=self.name)


class OfflineReplayProvider(BaseSearchProvider):
    """Proveedor sin red para pruebas y demostraciones.

    fixture: {query: [url1, url2, ...]} — la clave '*' sirve para cualquier
    consulta. Devuelve páginas deterministas según start/num.
    """

    name = "offline"
    max_per_page = 100
    max_start = 10 ** 9

    def __init__(self, fixture: dict | None = None, transport=None):
        super().__init__(transport)
        self.fixture = fixture or {}
        self.calls: list[tuple[str, int]] = []

    async def fetch(self, client, query: str, start: int, num: int) -> SearchPage:
        self.calls.append((query, start))
        urls = self.fixture.get(query) or self.fixture.get("*") or []
        window = urls[start - 1: start - 1 + num]
        return SearchPage(query=query, start=start,
                          results=[RawResult(url=u) for u in window],
                          total=len(urls), provider=self.name)


def create_provider(cfg_search, transport=None, offline_fixture: dict | None = None) -> BaseSearchProvider:
    name = getattr(cfg_search, "provider", "google_cse")
    if name == "google_cse":
        return GoogleCSEProvider(transport=transport)
    if name == "serpapi":
        return SerpAPIProvider(transport=transport)
    if name == "offline":
        return OfflineReplayProvider(offline_fixture, transport=transport)
    raise ProviderError(f"Proveedor de búsqueda desconocido: {name}")
