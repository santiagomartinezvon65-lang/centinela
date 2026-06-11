"""Persistencia de escaneos e historial (JSON en disco)."""
from __future__ import annotations

import json
import os
import re
import time
import uuid

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(_ROOT, "data")
SCANS = os.path.join(DATA, "scans")
HISTORY = os.path.join(DATA, "history.json")
MAX_HISTORY = 200
_ID_RE = re.compile(r"^[0-9A-Za-z-]+$")


def _ensure() -> None:
    os.makedirs(SCANS, exist_ok=True)


def list_history() -> list[dict]:
    try:
        with open(HISTORY, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, ValueError):
        return []


def save_scan(report: dict) -> str:
    """Guarda el reporte completo y agrega un resumen al historial. Devuelve el id."""
    _ensure()
    sid = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:4]
    report["id"] = sid
    with open(os.path.join(SCANS, sid + ".json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False)

    hist = list_history()
    hist.insert(0, {
        "id": sid,
        "target": report["target"],
        "grade": report["grade"],
        "score": report["score"],
        "counts": report["counts"],
        "pages": len(report.get("pages", [])) or 1,
        "profile": (report.get("profile") or {}).get("label", ""),
        "kind": report.get("kind", "scan"),
        "scanned_at": report["scanned_at"],
    })
    with open(HISTORY, "w", encoding="utf-8") as fh:
        json.dump(hist[:MAX_HISTORY], fh, ensure_ascii=False, indent=2)

    try:  # gestión de vulnerabilidades (import perezoso, no debe romper el guardado)
        from . import vulns
        vulns.ingest(report)
    except Exception:  # noqa: BLE001
        pass
    return sid


def get_scan(sid: str) -> dict | None:
    if not _ID_RE.match(sid or ""):
        return None
    path = os.path.join(SCANS, sid + ".json")
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, ValueError):
        return None
