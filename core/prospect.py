"""Prospección — pipeline scan → compliance → email de outreach, en batch.

Le pasás una lista de tiendas y te deja, por cada una: el compliance report PCI
(HTML) y un email de outreach listo para mandar, con el hallazgo más grave a la
vista. Es la herramienta para salir a vender: convierte "1 sitio a mano" en
"20 prospectos con material listo".

IMPORTANTE (legal/ético): por defecto corre SCAN PASIVO — sólo lee la superficie
pública (headers, TLS, cookies, configuración), igual que securityheaders.com.
NO envía payloads de ataque. El pentest activo (inyección) requiere autorización
escrita del dueño y va aparte (--deep). Estos emails NO se envían solos: se
generan como archivos para que vos los mandes.
"""
from __future__ import annotations

import os
import re
from urllib.parse import urlparse

from . import compliance, scan, store
from .http import normalize

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _slug(host: str) -> str:
    return re.sub(r"[^a-z0-9.-]", "_", host.lower())


def _top_finding(report: dict) -> dict | None:
    """El hallazgo abierto más grave (para el gancho del email)."""
    openf = [f for f in report.get("findings", []) if not f.get("passed")]
    if not openf:
        return None
    return sorted(openf, key=lambda f: _SEV_RANK.get(f.get("severity"), 4))[0]


def _english_finding(f: dict) -> str:
    """Etiqueta en inglés del hallazgo (reusa el mapeo del compliance)."""
    return compliance._label(f)


def build_email(host: str, report: dict, a: dict, sender: str = "{YOUR NAME}") -> str:
    top = _top_finding(report)
    top_line = (f"  - {_english_finding(top)}" if top else
                "  - Minor configuration gaps")
    return f"""Subject: Quick security check on {host}

Hi,

I ran a quick, non-intrusive security check on {host} and noticed a few issues
that could expose your customers' data and put your PCI compliance at risk.
The most pressing one:

{top_line}

PCI DSS applies to any store that takes card payments. Right now {host} meets
{a['passing']} of {a['total']} of the key requirements I checked.

I put together a short report that shows exactly what's exposed and how to fix
it — happy to send it over at no charge. If it's useful, I can also set up
continuous monitoring so issues like this get caught automatically, plus a
verified security seal you can show at checkout.

Worth a quick look?

Best,
{sender}
"""


def run_one(url: str, outdir: str, sender: str = "{YOUR NAME}") -> dict:
    """Escanea (pasivo), evalúa PCI y deja report.html + email.txt. Devuelve resumen."""
    url = normalize(url)
    host = urlparse(url).hostname or url
    report, err = scan(url, crawl=False)
    if err:
        return {"host": host, "ok": False, "error": err}

    store.save_scan(report)
    a = compliance.assess(report, "pci")
    top = _top_finding(report)

    site_dir = os.path.join(outdir, _slug(host))
    os.makedirs(site_dir, exist_ok=True)
    with open(os.path.join(site_dir, "report.html"), "w", encoding="utf-8") as fh:
        fh.write(compliance.build_html(report, "pci"))
    with open(os.path.join(site_dir, "email.txt"), "w", encoding="utf-8") as fh:
        fh.write(build_email(host, report, a, sender))

    counts = report.get("counts", {})
    # score de venta: más gaps PCI + más severidad = prospecto más caliente
    sales = a["gaps"] * 10 + counts.get("critical", 0) * 5 + counts.get("high", 0) * 2
    return {"host": host, "ok": True, "grade": report.get("grade", "?"),
            "score": report.get("score", 0), "pci_pass": a["passing"],
            "pci_total": a["total"], "gaps": a["gaps"],
            "top": _english_finding(top) if top else "—",
            "sales_score": sales, "dir": site_dir}


def run_batch(urls: list[str], outdir: str = "outreach",
              sender: str = "{YOUR NAME}") -> list[dict]:
    os.makedirs(outdir, exist_ok=True)
    results = []
    for u in urls:
        if not u.strip():
            continue
        results.append(run_one(u.strip(), outdir, sender))
    # ordenar por temperatura de venta (más caliente primero)
    results.sort(key=lambda r: r.get("sales_score", -1), reverse=True)
    return results
