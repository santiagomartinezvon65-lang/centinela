"""Centinela Templates — motor de chequeos por plantilla (estilo Nuclei, en JSON).

Cada plantilla es un archivo .json en templates/ que describe un request y qué
buscar en la respuesta. Permite sumar miles de chequeos SIN tocar el código.
Sin dependencias (json + re de stdlib).

Esquema:
{
  "id": "git-config-exposure",
  "info": {"name": "...", "severity": "high", "category": "disclosure",
           "remediation": "...", "reference": "..."},
  "requests": [{
    "method": "GET", "path": "/.git/config",
    "matchers_condition": "and",
    "matchers": [
      {"type": "status", "status": [200]},
      {"type": "word", "part": "body", "words": ["[core]"], "condition": "or"}
    ]
  }]
}
"""
from __future__ import annotations

import json
import os
import re
from urllib.parse import urlparse


def _root(u: str) -> str:
    p = urlparse(u)
    return f"{p.scheme}://{p.netloc}"


def load(tdir: str) -> list[dict]:
    out = []
    if not os.path.isdir(tdir):
        return out
    for fn in sorted(os.listdir(tdir)):
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(tdir, fn), encoding="utf-8") as fh:
                tpl = json.load(fh)
            if tpl.get("id") and tpl.get("info") and tpl.get("requests"):
                out.append(tpl)
        except Exception:  # noqa: BLE001 — una plantilla rota no rompe el resto
            continue
    return out


def _sub(target: str, path: str) -> str:
    root = _root(target)
    if "{{BaseURL}}" in path:
        return path.replace("{{BaseURL}}", root)
    if path.startswith("http"):
        return path
    return root + (path if path.startswith("/") else "/" + path)


def do_request(target: str, req: dict, fetch):
    url = _sub(target, req.get("path", "/"))
    r = fetch(url, method=req.get("method", "GET"),
              headers=req.get("headers"), data=req.get("body"))
    return url, (None if r.error else r)


def _part_text(resp, part: str) -> str:
    if part == "header":
        return "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    if part == "status":
        return str(resp.status)
    if part == "all":
        return (resp.body or "") + "\n" + "\n".join(
            f"{k}: {v}" for k, v in resp.headers.items())
    return resp.body or ""


def _one(resp, m: dict) -> bool:
    t = m.get("type")
    ok = False
    if t == "status":
        ok = resp.status in m.get("status", [])
    elif t == "word":
        hay = _part_text(resp, m.get("part", "body"))
        words = m.get("words", [])
        cond = m.get("condition", "or")
        ok = all(w in hay for w in words) if cond == "and" else any(w in hay for w in words)
    elif t == "regex":
        hay = _part_text(resp, m.get("part", "body"))
        ok = any(re.search(p, hay) for p in m.get("regex", []))
    elif t == "header":
        name = m.get("name", "").lower()
        present = name in resp.headers
        words = m.get("words", [])
        ok = present and (not words or any(w in resp.headers[name] for w in words))
    return (not ok) if m.get("negative") else ok


def matches(resp, req: dict) -> bool:
    ms = req.get("matchers", [])
    if not ms:
        return False
    res = [_one(resp, m) for m in ms]
    return all(res) if req.get("matchers_condition", "and") == "and" else any(res)
