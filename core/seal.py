"""Centinela Trust Seal — sello de confianza público y verificable.

Emite un sello por sitio monitoreado. El sello está VIVO: refleja el último
escaneo. Si el monitoreo se corta (no pagan) o aparecen fallas críticas, el
sello deja de mostrarse "verified". Ése es el gancho recurrente — el badge
sólo sigue verde mientras Centinela siga vigilando.

Cara al cliente final (USA): textos en inglés. El negocio pega el badge en su
web/checkout; cualquiera puede abrir la página de verificación y comprobarlo.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone

from . import store
from .http import normalize

SEALS = os.path.join(store.DATA, "seals.json")
FRESH_DAYS = 35  # un escaneo más viejo que esto = sello vencido (no se está monitoreando)

# estado → (texto del badge, color, titular en inglés)
_STATES = {
    "verified": ("VERIFIED", "#3fb950", "Secured &amp; actively monitored"),
    "expired":  ("EXPIRED",  "#8b949e", "Monitoring lapsed"),
    "at_risk":  ("AT RISK",  "#f85149", "Open security issues found"),
    "pending":  ("PENDING",  "#d29922", "Awaiting first audit"),
}


# ── identidad del sello ─────────────────────────────────────────────
def _host(url: str) -> str:
    from urllib.parse import urlparse
    return (urlparse(normalize(url)).hostname or url).lower().lstrip("www.")


def seal_id(host: str) -> str:
    """ID corto, determinista y público por host (no expone nada sensible)."""
    return hashlib.sha256(host.encode("utf-8")).hexdigest()[:12]


def _load() -> dict:
    try:
        with open(SEALS, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, ValueError):
        return {}


def _save(seals: dict) -> None:
    os.makedirs(store.DATA, exist_ok=True)
    with open(SEALS, "w", encoding="utf-8") as fh:
        json.dump(seals, fh, ensure_ascii=False, indent=2)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def issue(url: str, base_url: str = "http://localhost:8077") -> dict:
    """Emite (o reusa) el sello de un host y devuelve el snippet listo para pegar."""
    host = _host(url)
    sid = seal_id(host)
    seals = _load()
    if sid not in seals:
        seals[sid] = {"host": host, "issued_at": _now()}
        _save(seals)
    base = base_url.rstrip("/")
    snippet = (
        f'<a href="{base}/verify/{sid}" target="_blank" rel="noopener">\n'
        f'  <img src="{base}/badge/{sid}.svg" '
        f'alt="Secured &amp; Monitored by Centinela" height="38">\n'
        f'</a>'
    )
    return {"seal_id": sid, "host": host, "verify_url": f"{base}/verify/{sid}",
            "badge_url": f"{base}/badge/{sid}.svg", "snippet": snippet}


def list_seals() -> list[dict]:
    return [{"seal_id": k, **v} for k, v in _load().items()]


# ── estado vivo (mira el último escaneo real del host) ──────────────
def _date_from_id(sid: str) -> datetime | None:
    try:
        return datetime.strptime(sid[:15], "%Y%m%d-%H%M%S").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _latest_for(host: str) -> dict | None:
    from urllib.parse import urlparse
    for h in store.list_history():
        hh = (urlparse(h.get("target", "")).hostname or "").lower().lstrip("www.")
        if hh == host:
            return h
    return None


def status(sid: str) -> dict | None:
    """Estado vivo del sello. None si el sello no existe."""
    seals = _load()
    if sid not in seals:
        return None
    host = seals[sid]["host"]
    latest = _latest_for(host)
    base = {"seal_id": sid, "host": host, "issued_at": seals[sid].get("issued_at", "")}

    if not latest:
        return {**base, "state": "pending", "last_audit": None, "grade": None,
                "score": None, "days_since": None, "counts": {}}

    dt = _date_from_id(latest["id"])
    days = (datetime.now(timezone.utc) - dt).days if dt else 0
    counts = latest.get("counts", {}) or {}
    crit_high = counts.get("critical", 0) + counts.get("high", 0)

    if crit_high > 0:
        state = "at_risk"
    elif days > FRESH_DAYS:
        state = "expired"
    else:
        state = "verified"

    return {**base, "state": state,
            "last_audit": dt.strftime("%b %d, %Y") if dt else None,
            "grade": latest.get("grade"), "score": latest.get("score"),
            "days_since": days, "counts": counts}


def status_for_url(url: str) -> dict | None:
    return status(seal_id(_host(url)))


# ── render: badge SVG (estilo shields, sin dependencias) ────────────
def badge_svg(state: str) -> str:
    txt, color, _ = _STATES.get(state, _STATES["pending"])
    left = "SECURED &amp; MONITORED"
    lw = 150          # ancho fijo de la etiqueta izquierda
    rw = 11 + len(txt) * 8 + 12
    w = lw + rw
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="38" role="img"
 aria-label="Secured and Monitored: {txt}">
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#fff" stop-opacity=".08"/>
  <stop offset="1" stop-opacity=".08"/></linearGradient>
  <rect rx="6" width="{w}" height="38" fill="#1b2330"/>
  <rect rx="6" x="{lw}" width="{rw}" height="38" fill="{color}"/>
  <rect x="{lw}" width="10" height="38" fill="{color}"/>
  <rect rx="6" width="{w}" height="38" fill="url(#s)"/>
  <g fill="#3fb950" transform="translate(13,11)">
    <path d="M8 0L1 3v5c0 4 3 7 7 8 4-1 7-4 7-8V3z" fill="{color if state!='verified' else '#3fb950'}"
     opacity=".95"/>
    <path d="M5 8l2 2 4-4" stroke="#0b0f16" stroke-width="1.6" fill="none"/>
  </g>
  <g font-family="Segoe UI,Verdana,Geneva,sans-serif" font-size="11" font-weight="700">
    <text x="38" y="17" fill="#aeb9c7">CENTINELA</text>
    <text x="38" y="29" fill="#e6edf3" font-size="9" font-weight="400">{left}</text>
    <text x="{lw + rw/2}" y="23" fill="#06140b" text-anchor="middle">{txt}</text>
  </g>
</svg>"""


# ── render: página pública de verificación (inglés) ─────────────────
def verify_page(st: dict) -> str:
    _, color, headline = _STATES.get(st["state"], _STATES["pending"])
    host = st["host"]
    verified = st["state"] == "verified"
    badge = badge_svg(st["state"])

    if st["state"] == "verified":
        msg = (f"This site is actively monitored by Centinela. The most recent "
               f"security audit found no critical or high-risk issues.")
    elif st["state"] == "at_risk":
        msg = ("The most recent audit found open security issues on this site. "
               "The owner has been notified.")
    elif st["state"] == "expired":
        msg = (f"This site has not been audited in over {FRESH_DAYS} days. "
               "Continuous monitoring is not currently active.")
    else:
        msg = "This site is registered with Centinela but has not been audited yet."

    rows = ""
    if st.get("last_audit"):
        rows += _row("Last security audit", st["last_audit"])
    if st.get("grade"):
        rows += _row("Security grade", f"{st['grade']} ({st['score']}/100)")
    if st.get("days_since") is not None:
        rows += _row("Days since last check", str(st["days_since"]))
    counts = st.get("counts") or {}
    if counts:
        rows += _row("Critical / High issues",
                     f"{counts.get('critical', 0)} / {counts.get('high', 0)}")

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Trust Seal — {host}</title>
<style>
:root{{color-scheme:dark}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0d12;color:#e6edf3;
margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}}
.card{{background:#11151c;border:1px solid #232a36;border-radius:18px;max-width:520px;
width:100%;padding:38px 34px;box-shadow:0 24px 60px rgba(0,0,0,.5)}}
.brand{{color:#3fb950;font-weight:800;letter-spacing:.16em;font-size:12px;margin-bottom:24px}}
.host{{font-size:24px;font-weight:700;margin:0 0 4px;word-break:break-all}}
.headline{{color:{color};font-weight:700;font-size:15px;margin:2px 0 20px;display:flex;
align-items:center;gap:8px}}
.dot{{width:10px;height:10px;border-radius:50%;background:{color};
box-shadow:0 0 12px {color}}}
.msg{{color:#aeb9c7;font-size:14px;line-height:1.6;margin:0 0 22px}}
.badge{{margin:6px 0 24px}}
table{{width:100%;border-collapse:collapse;font-size:14px}}
td{{padding:10px 0;border-top:1px solid #1c2330}}
td:last-child{{text-align:right;color:#fff;font-weight:600}}
td:first-child{{color:#8b949e}}
.foot{{margin-top:26px;font-size:12px;color:#5b6573;text-align:center;line-height:1.6}}
a{{color:#3fb950;text-decoration:none}}
</style></head><body>
<div class="card">
  <div class="brand">◣ CENTINELA · TRUST SEAL</div>
  <h1 class="host">{host}</h1>
  <div class="headline"><span class="dot"></span>{headline.replace('&amp;','&')}</div>
  <div class="badge">{badge}</div>
  <p class="msg">{msg}</p>
  <table>{rows}</table>
  <div class="foot">
    {'✓ Independently verifiable · ' if verified else ''}Continuous security monitoring by Centinela<br>
    Seal ID <code>{st['seal_id']}</code>
  </div>
</div></body></html>"""


def _row(label: str, value: str) -> str:
    return f"<tr><td>{label}</td><td>{value}</td></tr>"
