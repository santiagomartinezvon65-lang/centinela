"""Centinela Guardian — bot protector que vigila el sistema en forma continua.

Registrás activos (sitios) y el guardián los re-escanea en loop, compara contra
la última línea base y dispara alertas SOLO de lo nuevo o lo que empeoró
(no repite lo de siempre). Sin dependencias.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from . import store
from .http import normalize, set_default_headers

ASSETS = os.path.join(store.DATA, "assets.json")
ALERTS = os.path.join(store.DATA, "alerts.json")
_SEV = ["critical", "high", "medium", "low", "info"]


# ── registro de activos ─────────────────────────────────────────────
def list_assets() -> list[dict]:
    try:
        with open(ASSETS, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, ValueError):
        return []


def _save_assets(items: list[dict]) -> None:
    os.makedirs(store.DATA, exist_ok=True)
    with open(ASSETS, "w", encoding="utf-8") as fh:
        json.dump(items, fh, ensure_ascii=False, indent=2)


def add_asset(url: str, mode: str = "scan", interval: int = 60,
              cookie: str = "", lab: bool = False) -> dict:
    url = normalize(url)
    items = [a for a in list_assets() if a["url"] != url]
    asset = {"url": url, "mode": mode, "interval": interval, "cookie": cookie,
             "lab": lab, "added_at": _now(), "last_check": 0.0}
    items.append(asset)
    _save_assets(items)
    return asset


def remove_asset(url: str) -> bool:
    url = normalize(url)
    items = list_assets()
    kept = [a for a in items if a["url"] != url]
    _save_assets(kept)
    return len(kept) < len(items)


# ── alertas ─────────────────────────────────────────────────────────
def list_alerts(limit: int = 100) -> list[dict]:
    try:
        with open(ALERTS, encoding="utf-8") as fh:
            return json.load(fh)[:limit]
    except (FileNotFoundError, ValueError):
        return []


def _save_alerts(new: list[dict]) -> None:
    if not new:
        return
    os.makedirs(store.DATA, exist_ok=True)
    alla = new + list_alerts(500)
    with open(ALERTS, "w", encoding="utf-8") as fh:
        json.dump(alla[:500], fh, ensure_ascii=False, indent=2)


# ── escaneo de un activo + diff inteligente ─────────────────────────
def _run_one(asset: dict) -> dict:
    set_default_headers({"Cookie": asset["cookie"]} if asset.get("cookie") else {})
    try:
        if asset.get("mode") == "pentest":
            from .engine import LocalPentester
            return LocalPentester(asset["url"], lab=asset.get("lab", False)).run()
        from .scanner import scan
        report, err = scan(asset["url"], crawl=True)
        return report if not err else _unreachable(asset["url"], err)
    finally:
        set_default_headers({})


def _unreachable(url: str, err: str) -> dict:
    return {"target": url, "kind": "scan", "reachable": False, "http_status": 0,
            "notice": f"No se pudo conectar: {err}", "score": 0, "grade": "F",
            "counts": {s: 0 for s in _SEV}, "pages": [url], "findings": [],
            "scanned_at": _now()}


def _prev_report(target: str, kind: str) -> dict | None:
    host = urlparse(target).hostname
    for h in store.list_history():
        if (urlparse(h.get("target", "")).hostname == host
                and h.get("kind", "scan") == kind):
            return store.get_scan(h["id"])
    return None


def _diff(prev: dict | None, rep: dict) -> list[dict]:
    t = rep["target"]
    if prev is None:
        return [_alert(t, "info", "baseline",
                       f"Vigilancia iniciada — nota base {rep['grade']} ({rep['score']})")]
    out = []
    from . import vulns
    host = urlparse(t).hostname or t
    pf = {f["id"]: f for f in prev.get("findings", []) if not f.get("passed")}
    nf = {f["id"]: f for f in rep.get("findings", []) if not f.get("passed")}
    for fid, f in nf.items():
        if vulns.is_muted(host, fid, f.get("page", "")):
            continue  # falso-positivo / riesgo aceptado: no molestar
        if fid not in pf:
            out.append(_alert(t, f["severity"], "nuevo",
                              f"Nuevo hallazgo: {f['title']}", f.get("evidence", "")))
        elif _SEV.index(f["severity"]) < _SEV.index(pf[fid]["severity"]):
            out.append(_alert(t, f["severity"], "agravado",
                              f"Se agravó: {f['title']}",
                              f"{pf[fid]['severity']} → {f['severity']}"))
    resolved = [pf[i]["title"] for i in pf if i not in nf]
    if resolved:
        out.append(_alert(t, "info", "resuelto",
                          f"Se resolvieron {len(resolved)} hallazgo(s)",
                          ", ".join(resolved[:4])))
    if rep.get("score", 0) < prev.get("score", 0) - 5:
        out.append(_alert(t, "medium", "nota",
                          f"Bajó la nota: {prev['grade']}({prev['score']}) → "
                          f"{rep['grade']}({rep['score']})"))
    if prev.get("reachable", True) and not rep.get("reachable", True):
        out.append(_alert(t, "high", "caido",
                          "El sitio dejó de responder / quedó inaccesible",
                          f"HTTP {rep.get('http_status')}"))
    elif not prev.get("reachable", True) and rep.get("reachable", True):
        out.append(_alert(t, "info", "recuperado", "El sitio volvió a responder"))
    return out


def check_asset(asset: dict) -> tuple[dict, list[dict]]:
    rep = _run_one(asset)
    prev = _prev_report(rep["target"], rep.get("kind", "scan"))
    alerts = _diff(prev, rep)
    store.save_scan(rep)
    _save_alerts(alerts)
    asset["last_check"] = time.time()
    return rep, alerts


# ── loop del guardián ───────────────────────────────────────────────
def _due(asset: dict, now: float) -> bool:
    return (now - asset.get("last_check", 0.0)) >= asset.get("interval", 60) * 60


def guard_once(force: bool = False) -> list[dict]:
    items = list_assets()
    if not items:
        return []
    now = time.time()
    fired = []
    for asset in items:
        if force or _due(asset, now):
            _, alerts = check_asset(asset)
            fired += alerts
    _save_assets(items)  # persiste last_check
    return fired


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _alert(target: str, severity: str, kind: str, title: str, detail: str = "") -> dict:
    return {"ts": _now(), "target": target, "severity": severity, "kind": kind,
            "title": title, "detail": detail}
