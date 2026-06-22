"""Compliance mapping — convierte los hallazgos de Centinela en un informe de
cumplimiento contra un estándar que el comprador está OBLIGADO a cumplir.

Hoy: PCI DSS (e-commerce que cobra con tarjeta). El documento es el "imposible
de rechazar" en USA: no le vendés seguridad, le mostrás en qué requisitos
obligatorios está en falta. Salida en inglés (deliverable para el cliente).

Diseñado para extenderse a HIPAA u otros: agregá una entrada en STANDARDS.
"""
from __future__ import annotations

from urllib.parse import urlparse

# severidades que hacen FALLAR un requisito (low/info quedan como advisory)
_FAIL_SEV = {"critical", "high", "medium"}

# ── etiquetas en inglés por id/categoría de hallazgo ────────────────
_ID_LABEL = {
    "strict-transport-security": "Missing HSTS (forces HTTPS in the browser)",
    "content-security-policy": "Missing Content-Security-Policy",
    "x-frame-options": "Missing clickjacking protection",
    "x-content-type-options": "Missing X-Content-Type-Options",
    "referrer-policy": "Missing Referrer-Policy",
    "permissions-policy": "Missing Permissions-Policy",
    "https": "Site not served over HTTPS",
    "tls-version": "Outdated TLS version",
    "tls-expiry": "TLS certificate expiring soon",
    "tls-conn": "TLS certificate could not be validated",
    "redirect": "HTTP does not redirect to HTTPS",
    "reflect": "Reflected user input (possible XSS)",
    "form-pw-http": "Password submitted over plain HTTP",
    "mixed": "Mixed content (insecure resources on a secure page)",
    "cors": "CORS misconfiguration",
    "trace": "HTTP TRACE method enabled",
    "methods": "Unsafe HTTP methods enabled",
}
_ID_PREFIX = {
    "cookie-": "Insecure session cookie",
    "leak-": "Software version disclosure",
    "path": "Sensitive file publicly accessible",
    "sqli": "SQL injection",
    "csrf": "Missing anti-CSRF protection",
}
_CAT_LABEL = {
    "headers": "Missing security header", "tls": "TLS / HTTPS weakness",
    "injection": "Injection / XSS vulnerability", "cookies": "Insecure cookie",
    "cors": "CORS misconfiguration", "csrf": "Missing CSRF protection",
    "disclosure": "Information disclosure", "methods": "Unsafe HTTP method",
    "forms": "Insecure form handling",
}
_CAT_FIX = {
    "headers": "Add the missing response header at the edge/server.",
    "tls": "Serve all traffic over TLS 1.2+ and redirect HTTP to HTTPS.",
    "injection": "Validate and encode all user input; use parameterized queries.",
    "cookies": "Set Secure; HttpOnly; SameSite on session cookies.",
    "cors": "Restrict Access-Control-Allow-Origin to your own domains.",
    "csrf": "Add anti-CSRF tokens to state-changing requests.",
    "disclosure": "Remove version banners and block access to sensitive files.",
    "methods": "Disable HTTP methods the app does not need.",
    "forms": "Submit all forms over HTTPS; remove mixed content.",
}


def _label(f: dict) -> str:
    fid = f.get("id", "")
    if fid in _ID_LABEL:
        return _ID_LABEL[fid]
    for pre, lab in _ID_PREFIX.items():
        if fid.startswith(pre):
            return lab
    return _CAT_LABEL.get(f.get("category", ""), f.get("title", "Security finding"))


# ── definición de estándares ────────────────────────────────────────
STANDARDS = {
    "pci": {
        "name": "PCI DSS v4.0",
        "subtitle": "Payment Card Industry Data Security Standard",
        "intro": ("Any business that accepts card payments must comply with PCI DSS. "
                  "This report maps the latest security scan to the requirements most "
                  "relevant to a public-facing storefront."),
        "requirements": [
            {"code": "2.2", "title": "Secure system configuration",
             "desc": "No insecure defaults, exposed versions or unnecessary methods.",
             "cats": ["disclosure", "methods"]},
            {"code": "4.2.1", "title": "Encrypt cardholder data in transit",
             "desc": "All transmission of account data must use strong TLS.",
             "cats": ["tls", "forms"]},
            {"code": "6.2.4", "title": "Protect against common web attacks",
             "desc": "Defend against injection, XSS, CSRF and similar OWASP risks.",
             "cats": ["injection", "csrf", "cors"]},
            {"code": "6.4.2", "title": "Browser security controls",
             "desc": "Security headers that harden the storefront in the browser.",
             "cats": ["headers"]},
            {"code": "8.3 / 6.3", "title": "Secure session handling",
             "desc": "Session cookies protected with Secure, HttpOnly and SameSite.",
             "cats": ["cookies"]},
            {"code": "11.3.2", "title": "Regular external vulnerability scanning",
             "desc": "External scans at least quarterly and after every change.",
             "cats": [], "monitored": True},
        ],
    },
}


# ── evaluación ──────────────────────────────────────────────────────
def _host(report: dict) -> str:
    return urlparse(report.get("target", "")).hostname or report.get("target", "")


def assess(report: dict, standard: str = "pci") -> dict:
    std = STANDARDS[standard]
    open_f = [f for f in report.get("findings", []) if not f.get("passed")]
    results = []
    for r in std["requirements"]:
        if r.get("monitored"):
            results.append({"code": r["code"], "title": r["title"], "desc": r["desc"],
                            "status": "pass", "monitored": True, "findings": []})
            continue
        matched = [f for f in open_f if f.get("category") in r["cats"]]
        fails = [f for f in matched if f.get("severity") in _FAIL_SEV]
        views = [{"label": _label(f), "severity": f.get("severity", "info"),
                  "page": f.get("page", ""), "evidence": f.get("evidence", ""),
                  "fix": _CAT_FIX.get(f.get("category", ""), "")}
                 for f in sorted(matched, key=lambda x: x.get("severity", "info"))]
        results.append({"code": r["code"], "title": r["title"], "desc": r["desc"],
                        "status": "fail" if fails else "pass", "findings": views})
    passing = sum(1 for r in results if r["status"] == "pass")
    total = len(results)
    return {"host": _host(report), "standard": standard, "std_name": std["name"],
            "std_subtitle": std["subtitle"], "intro": std["intro"],
            "scanned_at": report.get("scanned_at", ""),
            "grade": report.get("grade", ""), "score": report.get("score", ""),
            "results": results, "passing": passing, "total": total,
            "verdict": "Compliant" if passing == total else "Non-compliant",
            "gaps": total - passing}


# ── deliverable HTML (inglés, imprimible a PDF) ─────────────────────
def build_html(report: dict, standard: str = "pci") -> str:
    a = assess(report, standard)
    compliant = a["verdict"] == "Compliant"
    vcolor = "#127c3a" if compliant else "#b42318"
    vbg = "#e7f6ec" if compliant else "#fdeceb"

    rows = ""
    for r in a["results"]:
        ok = r["status"] == "pass"
        chip = ("PASS", "#127c3a", "#e7f6ec") if ok else ("ACTION REQUIRED", "#b42318", "#fdeceb")
        note = ""
        if r.get("monitored"):
            note = ("<div class='note'>Satisfied by Centinela continuous monitoring — "
                    "scans run automatically, covering the quarterly requirement.</div>")
        elif r["findings"]:
            items = "".join(
                f"<li><span class='sev sev-{f['severity']}'>{f['severity'].upper()}</span> "
                f"{f['label']}"
                + (f" <span class='pg'>{f['page']}</span>" if f['page'] else "")
                + (f"<div class='fix'>Fix: {f['fix']}</div>" if f['fix'] else "")
                + "</li>"
                for f in r["findings"])
            note = f"<ul class='finds'>{items}</ul>"
        rows += f"""<tr>
          <td class='code'>{r['code']}</td>
          <td><div class='rt'>{r['title']}</div><div class='rd'>{r['desc']}</div>{note}</td>
          <td><span class='chip' style='color:{chip[1]};background:{chip[2]}'>{chip[0]}</span></td>
        </tr>"""

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{a['std_name']} Compliance Report — {a['host']}</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,Arial,sans-serif;color:#1a2433;background:#f4f6f9;
margin:0;padding:32px;line-height:1.5}}
.doc{{max-width:840px;margin:0 auto;background:#fff;border:1px solid #e3e8ef;border-radius:14px;
padding:40px 44px;box-shadow:0 8px 30px rgba(16,24,40,.06)}}
.brand{{color:#127c3a;font-weight:800;letter-spacing:.14em;font-size:12px}}
h1{{font-size:23px;margin:6px 0 2px}}
.sub{{color:#667085;font-size:13px;margin:0 0 22px}}
.meta{{display:flex;flex-wrap:wrap;gap:22px;font-size:13px;color:#475467;
border-top:1px solid #eef1f5;border-bottom:1px solid #eef1f5;padding:14px 0;margin-bottom:22px}}
.meta b{{color:#1a2433;font-weight:600}}
.verdict{{display:flex;align-items:center;justify-content:space-between;gap:16px;
background:{vbg};border:1px solid {vcolor}33;border-radius:12px;padding:18px 22px;margin-bottom:8px}}
.verdict .v{{color:{vcolor};font-size:20px;font-weight:800}}
.verdict .n{{font-size:13px;color:#475467;margin-top:2px}}
.score{{text-align:right;font-size:13px;color:#475467}}
.score b{{font-size:26px;color:{vcolor};display:block;font-weight:800}}
.intro{{font-size:13px;color:#475467;margin:18px 0 18px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{text-align:left;color:#667085;font-weight:600;font-size:11px;letter-spacing:.06em;
text-transform:uppercase;padding:8px 10px;border-bottom:2px solid #eef1f5}}
td{{padding:14px 10px;border-bottom:1px solid #eef1f5;vertical-align:top}}
.code{{font-family:Consolas,monospace;color:#667085;white-space:nowrap;font-weight:600}}
.rt{{font-weight:600;font-size:14px}}
.rd{{color:#667085;font-size:12.5px;margin-top:2px}}
.chip{{font-size:11px;font-weight:700;padding:4px 10px;border-radius:20px;white-space:nowrap}}
.note{{font-size:12.5px;color:#127c3a;background:#f0faf3;border-radius:8px;padding:8px 11px;margin-top:9px}}
.finds{{list-style:none;margin:10px 0 0;padding:0}}
.finds li{{padding:8px 0;border-top:1px dashed #eef1f5;font-size:12.5px}}
.sev{{font-size:10px;font-weight:700;padding:2px 7px;border-radius:5px;margin-right:7px}}
.sev-critical,.sev-high{{background:#fdeceb;color:#b42318}}
.sev-medium{{background:#fef3e6;color:#b54708}}
.sev-low,.sev-info{{background:#eef1f5;color:#667085}}
.pg{{color:#98a2b3;font-size:11px;margin-left:6px}}
.fix{{color:#475467;margin-top:4px}}
.foot{{margin-top:26px;padding-top:16px;border-top:1px solid #eef1f5;font-size:11.5px;
color:#98a2b3;display:flex;justify-content:space-between}}
@media print{{body{{background:#fff;padding:0}}.doc{{border:0;box-shadow:none}}}}
</style></head><body>
<div class="doc">
  <div class="brand">◣ CENTINELA</div>
  <h1>{a['std_name']} Compliance Report</h1>
  <p class="sub">{a['std_subtitle']}</p>
  <div class="meta">
    <div>Website<br><b>{a['host']}</b></div>
    <div>Assessment date<br><b>{a['scanned_at'] or '—'}</b></div>
    <div>Standard<br><b>{a['std_name']}</b></div>
  </div>
  <div class="verdict">
    <div><div class="v">{a['verdict']}</div>
    <div class="n">{a['passing']} of {a['total']} requirements met
    {'· ' + str(a['gaps']) + ' gap(s) to close' if a['gaps'] else '· no open gaps'}</div></div>
    <div class="score"><b>{a['passing']}/{a['total']}</b>requirements passing</div>
  </div>
  <p class="intro">{a['intro']}</p>
  <table>
    <thead><tr><th>Req.</th><th>Requirement</th><th>Status</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <div class="foot">
    <span>Generated by Centinela · Continuous security monitoring</span>
    <span>{a['host']}</span>
  </div>
</div></body></html>"""
