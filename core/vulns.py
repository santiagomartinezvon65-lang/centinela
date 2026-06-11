"""Centinela Vuln Management — convierte hallazgos en un backlog gestionable.

Cada hallazgo tiene identidad estable entre escaneos (host+id+página), un estado
de ciclo de vida y responsable. Se auto-resuelve: si re-escaneás y la vuln ya no
aparece, pasa a 'fixed' sola; si reaparece, se reabre. Sin dependencias.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

from . import store

VULNS = os.path.join(store.DATA, "vulns.json")
STATUSES = ("open", "acknowledged", "false_positive", "accepted_risk", "fixed")
MUTED = ("false_positive", "accepted_risk")
_RISK_W = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _host(t: str) -> str:
    return urlparse(t).hostname or t


def _key(host: str, fid: str, page: str = "") -> str:
    return hashlib.sha1(f"{host}|{fid}|{page}".encode("utf-8")).hexdigest()[:8]


def _load() -> dict:
    try:
        with open(VULNS, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, ValueError):
        return {}


def _save(v: dict) -> None:
    os.makedirs(store.DATA, exist_ok=True)
    with open(VULNS, "w", encoding="utf-8") as fh:
        json.dump(v, fh, ensure_ascii=False, indent=2)


# ── ingesta: se llama tras cada escaneo (desde store.save_scan) ─────
def ingest(report: dict) -> None:
    if not report or report.get("reachable") is False:
        return  # sitio caído: no auto-resolver nada
    host = _host(report.get("target", ""))
    kind = report.get("kind", "scan")
    vulns = _load()
    now = _now()
    current = set()
    for f in report.get("findings", []):
        if f.get("passed"):
            continue
        k = _key(host, f["id"], f.get("page", ""))
        current.add(k)
        v = vulns.get(k)
        if v is None:
            vulns[k] = {
                "key": k, "host": host, "target": report.get("target", ""),
                "kind": kind, "finding_id": f["id"], "page": f.get("page", ""),
                "title": f["title"], "severity": f["severity"],
                "category": f.get("category", ""), "owasp": f.get("owasp", ""),
                "evidence": f.get("evidence", ""), "remediation": f.get("remediation", ""),
                "status": "open", "assignee": "", "note": "",
                "first_seen": now, "last_seen": now, "times_seen": 1, "fixed_at": ""}
        else:
            v["last_seen"] = now
            v["times_seen"] = v.get("times_seen", 1) + 1
            v["severity"] = f["severity"]
            v["title"] = f["title"]
            v["evidence"] = f.get("evidence", v.get("evidence", ""))
            if v["status"] == "fixed":
                v["status"] = "open"
                v["fixed_at"] = ""
                v["note"] = (v.get("note", "") + f" · reapareció {now}").strip(" ·")
    # auto-resolución: lo que estaba abierto y ya no aparece (mismo host+kind) → fixed
    for k, v in vulns.items():
        if (v["host"] == host and v.get("kind", "scan") == kind and k not in current
                and v["status"] in ("open", "acknowledged")):
            v["status"] = "fixed"
            v["fixed_at"] = now
            v["note"] = (v.get("note", "") + f" · auto-resuelto {now}").strip(" ·")
    _save(vulns)


# ── workflow ────────────────────────────────────────────────────────
def set_status(key: str, status: str) -> bool:
    if status not in STATUSES:
        return False
    v = _load()
    if key not in v:
        return False
    v[key]["status"] = status
    v[key]["fixed_at"] = _now() if status == "fixed" else v[key].get("fixed_at", "")
    _save(v)
    return True


def assign(key: str, who: str) -> bool:
    v = _load()
    if key not in v:
        return False
    v[key]["assignee"] = who
    _save(v)
    return True


def get(key: str) -> dict | None:
    return _load().get(key)


def is_muted(host: str, fid: str, page: str = "") -> bool:
    v = _load().get(_key(host, fid, page))
    return bool(v and v["status"] in MUTED)


def list_vulns(status: str = "", severity: str = "", host: str = "") -> list[dict]:
    order = list(_RISK_W)
    items = list(_load().values())
    if status:
        items = [v for v in items if v["status"] == status]
    if severity:
        items = [v for v in items if v["severity"] == severity]
    if host:
        items = [v for v in items if host in v["host"]]
    return sorted(items, key=lambda v: (order.index(v["severity"])
                                        if v["severity"] in order else 9, v["host"]))


def stats() -> dict:
    items = list(_load().values())
    by_status = {s: 0 for s in STATUSES}
    by_sev = {s: 0 for s in _RISK_W}
    risk = 0
    for v in items:
        by_status[v["status"]] = by_status.get(v["status"], 0) + 1
        if v["status"] in ("open", "acknowledged"):
            by_sev[v["severity"]] = by_sev.get(v["severity"], 0) + 1
            risk += _RISK_W.get(v["severity"], 0)
    return {"total": len(items), "by_status": by_status, "open_by_severity": by_sev,
            "open_risk_score": risk}
