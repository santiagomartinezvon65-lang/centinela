"""Centinela Reports — informe profesional autocontenido (HTML imprimible a PDF) + CSV.

Pensado como deliverable de auditoría: resumen ejecutivo, mapeo OWASP Top-10,
y hallazgos detallados con evidencia y remediación. Sin dependencias.
"""
from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

from .engine import _OWASP, _OWASP_DEFAULT

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_ES = {"critical": "Crítica", "high": "Alta", "medium": "Media",
           "low": "Baja", "info": "Informativa"}
_SEV_COLOR = {"critical": "#cf222e", "high": "#bc4c00", "medium": "#9a6700",
              "low": "#57606a", "info": "#57606a"}
# OWASP Top 10 2021 (código → nombre) para la tabla de cumplimiento
_OWASP_TOP10 = [
    ("A01", "Pérdida de control de acceso"),
    ("A02", "Fallas criptográficas"),
    ("A03", "Inyección"),
    ("A04", "Diseño inseguro"),
    ("A05", "Configuración de seguridad incorrecta"),
    ("A06", "Componentes vulnerables y desactualizados"),
    ("A07", "Fallas de identificación y autenticación"),
    ("A08", "Fallas de integridad de software y datos"),
    ("A09", "Fallas de registro y monitoreo"),
    ("A10", "Server-Side Request Forgery (SSRF)"),
]


def _esc(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _owasp_of(f: dict) -> str:
    return f.get("owasp") or _OWASP.get(f.get("category", ""), _OWASP_DEFAULT)


def _fails(report: dict) -> list[dict]:
    return [f for f in report.get("findings", []) if not f.get("passed")]


# ── CSV ──────────────────────────────────────────────────────────────
def build_csv(report: dict) -> str:
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["severidad", "owasp", "categoria", "titulo", "evidencia",
                "remediacion", "pagina", "estado"])
    for f in sorted(_fails(report), key=lambda x: _SEV_ORDER.index(x["severity"])
                    if x["severity"] in _SEV_ORDER else 9):
        w.writerow([f["severity"], _owasp_of(f), f.get("category", ""), f["title"],
                    f.get("evidence", ""), f.get("remediation", ""),
                    f.get("page", ""), f.get("confidence", "")])
    return out.getvalue()


# ── HTML ─────────────────────────────────────────────────────────────
def build_html(report: dict) -> str:
    fails = _fails(report)
    counts = report.get("counts", {})
    grade = report.get("grade", "—")
    score = report.get("score", 0)
    target = report.get("target", "")
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    gcolor = "#1a7f37" if grade in "AB" else ("#9a6700" if grade in "CD" else "#cf222e")
    npages = len(report.get("pages", [])) or 1
    is_pentest = report.get("kind") == "agent"

    # tarjetas de severidad
    cards = ""
    for s in _SEV_ORDER[:4]:
        n = counts.get(s, 0)
        cards += (f'<div class="card"><div class="num" style="color:{_SEV_COLOR[s]}">{n}</div>'
                  f'<div class="lbl">{_SEV_ES[s]}s</div></div>')

    # tabla de cumplimiento OWASP
    owasp_counts: dict[str, int] = {}
    for f in fails:
        code = _owasp_of(f).split(":")[0]
        owasp_counts[code] = owasp_counts.get(code, 0) + 1
    rows_owasp = ""
    for code, name in _OWASP_TOP10:
        n = owasp_counts.get(code, 0)
        badge = (f'<span class="pill bad">{n} hallazgo(s)</span>' if n
                 else '<span class="pill ok">sin hallazgos</span>')
        rows_owasp += f"<tr><td><b>{code}:2021</b> {_esc(name)}</td><td>{badge}</td></tr>"

    # hallazgos detallados
    findings_html = ""
    if not fails:
        findings_html = '<p class="ok-msg">✓ No se detectaron vulnerabilidades en los controles ejecutados.</p>'
    for f in sorted(fails, key=lambda x: _SEV_ORDER.index(x["severity"])
                    if x["severity"] in _SEV_ORDER else 9):
        sc = _SEV_COLOR.get(f["severity"], "#57606a")
        page = f.get("page", "")
        findings_html += f"""
        <div class="finding" style="border-left-color:{sc}">
          <div class="f-head">
            <span class="sev" style="background:{sc}">{_SEV_ES.get(f['severity'], f['severity']).upper()}</span>
            <span class="f-title">{_esc(f['title'])}</span>
          </div>
          <div class="f-meta">{_esc(_owasp_of(f))} · categoría: {_esc(f.get('category', '—'))}
            {(' · ' + _esc(page)) if page and page != target else ''}</div>
          {f'<div class="ev"><b>Evidencia:</b> <code>{_esc(f.get("evidence", ""))}</code></div>' if f.get('evidence') else ''}
          {f'<div class="fix"><b>Remediación:</b> {_esc(f.get("remediation", ""))}</div>' if f.get('remediation') else ''}
        </div>"""

    summary = report.get("summary") or (
        f"Se evaluaron {npages} página(s) de {target}. "
        f"Se identificaron {len(fails)} hallazgo(s): "
        f"{counts.get('critical', 0)} críticos, {counts.get('high', 0)} altos, "
        f"{counts.get('medium', 0)} medios y {counts.get('low', 0)} bajos.")

    from . import remediate
    fix_html = ""
    if remediate.missing_headers(report):
        cfg = _esc(remediate.generate(report, "vercel"))
        fix_html = ('<h2>Remediación rápida (headers de seguridad)</h2>'
                    '<p class="sub">Pegá esta config (formato Vercel) para corregir los '
                    'headers faltantes:</p>'
                    f'<pre class="fixcode">{cfg}</pre>')

    return f"""<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe de Seguridad — {_esc(target)}</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#1c2128;
  max-width:900px;margin:0 auto;padding:40px 28px;line-height:1.5;background:#fff}}
h1{{font-size:24px;margin:0 0 4px}} h2{{font-size:16px;margin:32px 0 12px;
  border-bottom:2px solid #e1e4e8;padding-bottom:6px}}
.brand{{color:#2da44e;font-weight:800;letter-spacing:.12em;font-size:13px}}
.sub{{color:#57606a;font-size:13px}}
.hero{{display:flex;gap:28px;align-items:center;margin:24px 0;padding:24px;
  background:#f6f8fa;border:1px solid #e1e4e8;border-radius:12px}}
.grade{{font-size:72px;font-weight:800;width:120px;height:120px;display:flex;
  align-items:center;justify-content:center;border:3px solid {gcolor};color:{gcolor};
  border-radius:16px;flex-shrink:0}}
.hero-meta{{flex:1}} .score{{font-size:26px;font-weight:700}}
.cards{{display:flex;gap:12px;margin-top:14px;flex-wrap:wrap}}
.card{{background:#fff;border:1px solid #e1e4e8;border-radius:10px;padding:12px 18px;text-align:center;min-width:80px}}
.num{{font-size:28px;font-weight:800}} .lbl{{font-size:12px;color:#57606a}}
.risk{{display:inline-block;padding:4px 12px;border-radius:20px;font-size:13px;font-weight:600;
  background:{gcolor}1a;color:{gcolor};margin-top:8px}}
table{{width:100%;border-collapse:collapse;font-size:14px}}
td{{padding:9px 10px;border-bottom:1px solid #eaecef}}
.pill{{font-size:12px;padding:3px 10px;border-radius:20px;font-weight:600}}
.pill.ok{{background:#dafbe1;color:#1a7f37}} .pill.bad{{background:#ffebe9;color:#cf222e}}
.finding{{border:1px solid #e1e4e8;border-left:4px solid;border-radius:8px;padding:14px 16px;margin:10px 0}}
.f-head{{display:flex;align-items:center;gap:10px}}
.sev{{color:#fff;font-size:11px;font-weight:700;padding:3px 9px;border-radius:5px}}
.f-title{{font-weight:600}} .f-meta{{font-size:12px;color:#57606a;margin:6px 0}}
.ev{{font-size:13px;margin-top:6px}} .ev code{{background:#f6f8fa;padding:2px 6px;border-radius:4px;
  word-break:break-all;font-size:12px}}
.fix{{font-size:13px;margin-top:6px;color:#1a4f8a}}
.ok-msg{{color:#1a7f37;font-weight:600}}
.fixcode{{background:#0d1117;color:#c9d1d9;padding:16px;border-radius:8px;font-size:12px;
  overflow-x:auto;white-space:pre;line-height:1.45;border:1px solid #30363d}}
footer{{margin-top:40px;padding-top:16px;border-top:1px solid #e1e4e8;color:#57606a;font-size:12px}}
@media print{{body{{padding:0}}.finding,.hero{{break-inside:avoid}}}}
</style></head><body>
<div class="brand">◣ CENTINELA</div>
<h1>Informe de Seguridad</h1>
<div class="sub">{_esc(target)} · generado {gen} · {'pentest' if is_pentest else 'escaneo'} · {npages} página(s)</div>

<div class="hero">
  <div class="grade">{grade}</div>
  <div class="hero-meta">
    <div class="score">{score}/100</div>
    <div class="risk">Riesgo {report.get('overall_risk', 'medium')}</div>
    <div class="cards">{cards}</div>
  </div>
</div>

<h2>Resumen ejecutivo</h2>
<p>{_esc(summary)}</p>

<h2>Cumplimiento — OWASP Top 10 (2021)</h2>
<table>{rows_owasp}</table>

<h2>Hallazgos detallados ({len(fails)})</h2>
{findings_html}

{fix_html}

<footer>Generado por Centinela · herramienta de seguridad de uso ético — solo sitios
propios o autorizados. Este informe refleja los controles ejecutados al momento del escaneo.</footer>
</body></html>"""
