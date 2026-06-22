"""Centinela Benchmark — mide cuánto resuelve SOLO el agente sobre labs conocidos.

Apunta el pentester (cualquier cerebro: motor de reglas, Ollama local o Claude)
a un set de labs públicos y autorizados con vulnerabilidades conocidas, y puntúa
qué porcentaje de esas vulns encuentra sin ayuda. Sirve como prueba de capacidad
y para comparar cerebros entre sí.

Uso ÉTICO: los targets de bench/targets.json son labs hechos a propósito para
ser auditados. No agregues sitios que no sean tuyos o autorizados.

Sin dependencias externas: solo librería estándar.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGETS_PATH = os.path.join(ROOT, "bench", "targets.json")

C = {"crit": "\033[91m", "high": "\033[93m", "ok": "\033[92m", "blue": "\033[96m",
     "dim": "\033[90m", "b": "\033[1m", "x": "\033[0m"}

BRAINS = ("engine", "brain", "ollama", "groq", "anthropic")


# ── carga de targets ────────────────────────────────────────────────
def load_targets(path: str = TARGETS_PATH, only: list[str] | None = None) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    targets = data["targets"]
    if only:
        names = {n.strip().lower() for n in only}
        targets = [t for t in targets if t["name"].lower() in names]
    return targets


# ── scoring: ¿qué vulns conocidas cubrió el reporte? ────────────────
def _norm(finding: dict) -> str:
    return " ".join(str(finding.get(k, ""))
                    for k in ("title", "category", "evidence")).lower()


def score_report(report: dict, vulns: list[dict]) -> dict:
    texts = [_norm(f) for f in report.get("findings", [])]
    matched_findings: set[int] = set()
    detected, missed = [], []
    for v in vulns:
        kws = [k.lower() for k in v["match"]]
        hit = next((i for i, t in enumerate(texts)
                    if any(k in t for k in kws)), None)
        if hit is not None:
            detected.append(v["id"])
            matched_findings.add(hit)
        else:
            missed.append(v["id"])
    extra = len(texts) - len(matched_findings)
    coverage = len(detected) / len(vulns) if vulns else 0.0
    return {"detected": detected, "missed": missed, "extra": extra,
            "coverage": coverage, "n_expected": len(vulns),
            "n_findings": len(texts)}


# ── correr un (cerebro × target) ────────────────────────────────────
def _run_one(brain: str, target: dict, model: str | None,
             max_steps: int, verbose: bool) -> dict:
    url = target["url"]
    lab = target.get("lab", True)
    buf = io.StringIO()
    ctx = contextlib.nullcontext() if verbose else contextlib.redirect_stdout(buf)
    t0 = time.time()
    try:
        with ctx:
            if brain == "engine":
                from .engine import LocalPentester
                report = LocalPentester(url, lab=lab).run()
            elif brain == "brain":
                from .brain import BrainPentester
                report = BrainPentester(url, lab=lab).run()
            else:
                from .agent import CentinelaAgent
                report = CentinelaAgent(url, lab=lab, provider=brain,
                                        model=model, max_steps=max_steps).run()
        return {"ok": True, "report": report, "time": time.time() - t0}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e), "time": time.time() - t0}


def run_benchmark(targets: list[dict], brains: list[str], model: str | None = None,
                  max_steps: int = 14, verbose: bool = False,
                  progress: bool = True) -> list[dict]:
    results: list[dict] = []
    for t in targets:
        for b in brains:
            if progress:
                print(f"{C['dim']}▸ {b:9s} → {t['name']:12s} …{C['x']}",
                      end="", flush=True)
            r = _run_one(b, t, model, max_steps, verbose)
            row = {"target": t["name"], "url": t["url"], "brain": b,
                   "time": round(r["time"], 1)}
            if not r["ok"]:
                row["error"] = r["error"]
                results.append(row)
                if progress:
                    print(f"  {C['crit']}✗ {r['error'][:70]}{C['x']}")
                continue
            rep = r["report"]
            if not rep.get("reachable", True):
                row["unreachable"] = True
                row["notice"] = rep.get("notice")
                results.append(row)
                if progress:
                    print(f"  {C['high']}⚠ inalcanzable{C['x']}")
                continue
            sc = score_report(rep, t["vulns"])
            row.update({
                "coverage": sc["coverage"], "detected": sc["detected"],
                "missed": sc["missed"], "extra": sc["extra"],
                "n_expected": sc["n_expected"], "n_findings": sc["n_findings"],
                "score": rep.get("score"), "grade": rep.get("grade"),
                "steps": rep.get("steps", 0),
                "cost": rep.get("usage", {}).get("est_cost_usd", 0.0),
                "provider": rep.get("provider"), "model": rep.get("model"),
            })
            results.append(row)
            if progress:
                bar = _bar(sc["coverage"])
                print(f"  {bar} {C['ok']}{sc['coverage']*100:3.0f}%{C['x']} "
                      f"({len(sc['detected'])}/{sc['n_expected']}) "
                      f"· {row['time']:.0f}s")
    return results


# ── presentación ────────────────────────────────────────────────────
def _bar(frac: float, width: int = 10) -> str:
    fill = round(frac * width)
    return "█" * fill + "░" * (width - fill)


def _aggregate(results: list[dict]) -> dict:
    agg: dict[str, dict] = {}
    for r in results:
        if "coverage" not in r:
            continue
        a = agg.setdefault(r["brain"], {"cov": [], "time": 0.0, "cost": 0.0,
                                        "n": 0})
        a["cov"].append(r["coverage"])
        a["time"] += r["time"]
        a["cost"] += r.get("cost", 0.0) or 0.0
        a["n"] += 1
    for a in agg.values():
        a["avg_cov"] = sum(a["cov"]) / len(a["cov"]) if a["cov"] else 0.0
    return agg


def print_leaderboard(results: list[dict]) -> None:
    print(f"\n{C['b']}── Leaderboard ──{C['x']}")
    print(f"{C['dim']}{'TARGET':13s}{'CEREBRO':10s}{'COBERTURA':22s}"
          f"{'HALLAZGOS':10s}{'PASOS':7s}{'TIEMPO':8s}{'COSTO':8s}{C['x']}")
    for r in results:
        tgt, brain = r["target"], r["brain"]
        if "error" in r:
            print(f"{tgt:13s}{brain:10s}{C['crit']}error: {r['error'][:40]}{C['x']}")
            continue
        if r.get("unreachable"):
            print(f"{tgt:13s}{brain:10s}{C['high']}inalcanzable{C['x']}")
            continue
        cov = r["coverage"]
        col = C["ok"] if cov >= 0.7 else (C["high"] if cov >= 0.4 else C["crit"])
        cov_s = f"{_bar(cov)} {col}{cov*100:3.0f}%{C['x']} ({len(r['detected'])}/{r['n_expected']})"
        cost = f"${r['cost']:.3f}" if r.get("cost") else "gratis"
        # padding manual porque los códigos de color rompen el ancho
        print(f"{tgt:13s}{brain:10s}{cov_s:31s}"
              f"  {r['n_findings']:<8d}{r['steps']:<7d}{r['time']:<7.0f}{cost}")

    agg = _aggregate(results)
    if agg:
        print(f"\n{C['b']}Promedio por cerebro:{C['x']}")
        for brain, a in sorted(agg.items(), key=lambda kv: -kv[1]["avg_cov"]):
            cost = f"${a['cost']:.3f}" if a["cost"] else "gratis"
            print(f"  {brain:10s} cobertura {C['ok']}{a['avg_cov']*100:3.0f}%{C['x']}"
                  f"  ·  {a['time']:.0f}s total  ·  {cost}  ·  {a['n']} target(s)")


# ── exportar ────────────────────────────────────────────────────────
def to_json(results: list[dict], path: str) -> None:
    out = {"generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
           "results": results, "summary": _aggregate(results)}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2)


def to_html(results: list[dict], path: str) -> None:
    agg = _aggregate(results)
    rows = []
    for r in results:
        if "error" in r:
            rows.append(f"<tr><td>{r['target']}</td><td>{r['brain']}</td>"
                        f"<td colspan=5 class=err>error: {r['error'][:60]}</td></tr>")
            continue
        if r.get("unreachable"):
            rows.append(f"<tr><td>{r['target']}</td><td>{r['brain']}</td>"
                        f"<td colspan=5 class=warn>inalcanzable</td></tr>")
            continue
        cov = r["coverage"]
        cls = "good" if cov >= 0.7 else ("mid" if cov >= 0.4 else "bad")
        cost = f"${r['cost']:.3f}" if r.get("cost") else "gratis"
        rows.append(
            f"<tr><td>{r['target']}</td><td>{r['brain']}</td>"
            f"<td class={cls}><b>{cov*100:.0f}%</b> ({len(r['detected'])}/{r['n_expected']})</td>"
            f"<td>{r['n_findings']}</td><td>{r['steps']}</td>"
            f"<td>{r['time']:.0f}s</td><td>{cost}</td></tr>")
    summary = "".join(
        f"<tr><td>{b}</td><td><b>{a['avg_cov']*100:.0f}%</b></td>"
        f"<td>{a['time']:.0f}s</td><td>{'$%.3f'%a['cost'] if a['cost'] else 'gratis'}</td></tr>"
        for b, a in sorted(agg.items(), key=lambda kv: -kv[1]["avg_cov"]))
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    html = f"""<!doctype html><html lang=es><meta charset=utf-8>
<title>Centinela Benchmark</title>
<style>
 body{{font:15px/1.5 system-ui,sans-serif;background:#0d1117;color:#e6edf3;max-width:900px;margin:2rem auto;padding:0 1rem}}
 h1{{font-size:1.5rem}} .dim{{color:#8b949e}}
 table{{border-collapse:collapse;width:100%;margin:1rem 0}}
 th,td{{padding:.5rem .7rem;text-align:left;border-bottom:1px solid #21262d}}
 th{{color:#8b949e;font-weight:600;font-size:.85rem;text-transform:uppercase}}
 .good{{color:#3fb950}} .mid{{color:#d29922}} .bad,.err{{color:#f85149}} .warn{{color:#d29922}}
</style>
<h1>🛡 Centinela Benchmark</h1>
<p class=dim>Cobertura de vulnerabilidades conocidas resueltas por el agente · {gen}</p>
<h2>Resultados</h2>
<table><tr><th>Target</th><th>Cerebro</th><th>Cobertura</th><th>Hallazgos</th><th>Pasos</th><th>Tiempo</th><th>Costo</th></tr>{''.join(rows)}</table>
<h2>Promedio por cerebro</h2>
<table><tr><th>Cerebro</th><th>Cobertura media</th><th>Tiempo total</th><th>Costo</th></tr>{summary}</table>
</html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
