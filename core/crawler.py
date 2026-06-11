"""Crawler same-origin liviano — descubre páginas para escanear el sitio entero."""
from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from .http import Response, fetch


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for k, v in attrs:
                if k == "href" and v:
                    self.links.append(v)


def _links(resp: Response) -> list[str]:
    p = _LinkParser()
    try:
        p.feed(resp.body or "")
    except Exception:  # noqa: BLE001 — HTML roto no debe romper el crawl
        pass
    return p.links


def _is_html(resp: Response) -> bool:
    return "html" in resp.headers.get("content-type", "").lower()


def crawl(base_url: str, max_pages: int = 12, max_depth: int = 2) -> list[Response]:
    """Devuelve las Response de páginas HTML same-origin (incluye la base primero)."""
    base = fetch(base_url)
    if base.error:
        return [base]
    host = base.host
    seen = {base.final_url.split("#")[0]}
    pages = [base]
    queue: list[tuple[Response, int]] = [(base, 1)]

    while queue and len(pages) < max_pages:
        resp, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        for href in _links(resp):
            nxt = urljoin(resp.final_url, href).split("#")[0]
            if not nxt.startswith(("http://", "https://")):
                continue
            if urlparse(nxt).hostname != host or nxt in seen:
                continue
            seen.add(nxt)
            r = fetch(nxt)
            if r.error or r.status != 200 or not _is_html(r):
                continue
            pages.append(r)
            queue.append((r, depth + 1))
            if len(pages) >= max_pages:
                break
    return pages
