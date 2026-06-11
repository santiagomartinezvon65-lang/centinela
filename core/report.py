"""Scoring, grading and report serialization."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .checks import Finding

PENALTY = {"critical": 30, "high": 15, "medium": 7, "low": 3, "info": 0}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _grade(score: int) -> str:
    for cut, g in ((90, "A"), (80, "B"), (70, "C"), (55, "D"), (35, "E")):
        if score >= cut:
            return g
    return "F"


def build(target: str, findings: list[Finding], pages: list[str] | None = None,
          profile: dict | None = None, http_status: int = 200,
          notice: str | None = None) -> dict:
    score = 100
    for f in findings:
        if not f.passed:
            score -= PENALTY.get(f.severity, 0)
    score = max(0, min(100, score))

    counts = {s: 0 for s in PENALTY}
    for f in findings:
        if not f.passed:
            counts[f.severity] += 1

    findings_sorted = sorted(
        findings, key=lambda f: (f.passed, SEV_ORDER.get(f.severity, 9)))

    return {
        "target": target,
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "score": score,
        "grade": _grade(score),
        "counts": counts,
        "total_checks": len(findings),
        "passed": sum(1 for f in findings if f.passed),
        "pages": pages or [target],
        "profile": profile or {},
        "http_status": http_status,
        "reachable": 200 <= http_status < 400,
        "notice": notice,
        "findings": [f.dict() for f in findings_sorted],
    }


def write(report: dict, json_path: str, jsfile_path: str) -> None:
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    with open(jsfile_path, "w", encoding="utf-8") as fh:
        fh.write("window.REPORT = ")
        json.dump(report, fh, ensure_ascii=False, indent=2)
        fh.write(";\n")
