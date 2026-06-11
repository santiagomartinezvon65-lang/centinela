"""Centinela DNS/Email — auditoría de seguridad de dominio (SPF, DMARC).

Responde "¿se puede falsificar email desde este dominio?" — un control clásico de
auditoría. Implementa un mini-resolver DNS sobre UDP (stdlib struct+socket), sin
librerías. Los chequeos son determinísticos sobre los registros → alta precisión.
"""
from __future__ import annotations

import re
import socket
import struct
from datetime import datetime, timezone
from urllib.parse import urlparse

from .report import PENALTY, _grade

_RESOLVERS = ["8.8.8.8", "1.1.1.1"]


def _encode_name(domain: str) -> bytes:
    out = b""
    for label in domain.strip(".").split("."):
        out += bytes([len(label)]) + label.encode("idna" if not label.isascii() else "ascii")
    return out + b"\x00"


def _query(domain: str, qtype: int, timeout: float = 4.0) -> bytes | None:
    # arcount=1 → incluye un registro OPT (EDNS0) para pedir respuestas grandes
    # y evitar que el servidor trunque a 512 bytes (causa de falsos negativos).
    pkt = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 1)
    pkt += _encode_name(domain) + struct.pack(">HH", qtype, 1)
    pkt += b"\x00" + struct.pack(">HHIH", 41, 4096, 0, 0)  # OPT: UDP payload 4096
    for resolver in _RESOLVERS:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(pkt, (resolver, 53))
            return s.recvfrom(4096)[0]
        except OSError:
            continue
        finally:
            s.close()
    return None


def _skip_name(data: bytes, off: int) -> int:
    while off < len(data):
        ln = data[off]
        if ln == 0:
            return off + 1
        if ln & 0xC0 == 0xC0:
            return off + 2
        off += 1 + ln
    return off


def txt_records(domain: str) -> list[str] | None:
    """Devuelve los registros TXT, o None si la consulta DNS falló."""
    data = _query(domain, 16)
    if not data or len(data) < 12:
        return None
    qd, an = struct.unpack(">H", data[4:6])[0], struct.unpack(">H", data[6:8])[0]
    off = 12
    for _ in range(qd):
        off = _skip_name(data, off) + 4
    out: list[str] = []
    try:
        for _ in range(an):
            off = _skip_name(data, off)
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rdata = data[off:off + rdlen]
            off += rdlen
            if rtype == 16:
                i, s = 0, ""
                while i < len(rdata):
                    ln = rdata[i]
                    s += rdata[i + 1:i + 1 + ln].decode("latin-1", "replace")
                    i += 1 + ln
                out.append(s)
    except (struct.error, IndexError):
        pass
    return out


def _f(fid, title, sev, ev, fix):
    return {"id": fid, "title": title, "severity": sev, "category": "email",
            "evidence": ev, "remediation": fix, "confidence": "confirmed",
            "owasp": "A05:2021 Configuración de seguridad incorrecta", "passed": False, "page": ""}


def analyze(domain: str, spf_txt: list[str] | None, dmarc_txt: list[str] | None) -> list[dict]:
    """Lógica pura (testeable sin red): evalúa SPF y DMARC."""
    findings = []
    if spf_txt is not None:
        spf = next((t for t in spf_txt if t.lower().startswith("v=spf1")), None)
        if not spf:
            findings.append(_f("spf-missing",
                               "Sin registro SPF — el dominio puede ser falsificado para email",
                               "medium", f"no hay 'v=spf1' en los TXT de {domain}",
                               "Publicá un SPF que liste tus servidores de correo autorizados."))
        elif re.search(r"[+?]all\b", spf):
            findings.append(_f("spf-weak", "SPF permisivo (+all / ?all) — no protege", "high",
                              f"SPF: {spf[:90]}",
                              "Cambiá la política a '-all' (fail) para rechazar remitentes no autorizados."))
        elif "-all" not in spf and "~all" not in spf:
            findings.append(_f("spf-noall", "SPF sin política final (-all/~all)", "low",
                              f"SPF: {spf[:90]}",
                              "Terminá el registro con '-all' para que sea efectivo."))
    if dmarc_txt is not None:
        dmarc = next((t for t in dmarc_txt if t.lower().startswith("v=dmarc1")), None)
        if not dmarc:
            findings.append(_f("dmarc-missing",
                               "Sin política DMARC — facilita el spoofing/phishing", "medium",
                               f"no hay registro DMARC en _dmarc.{domain}",
                               "Publicá un DMARC (empezá con p=none para monitorear, luego p=reject)."))
        elif "p=none" in dmarc.lower():
            findings.append(_f("dmarc-none", "DMARC en modo monitoreo (p=none, no bloquea)", "low",
                              f"DMARC: {dmarc[:90]}",
                              "Pasá la política a 'p=quarantine' o 'p=reject' cuando estés listo."))
    return findings


def run(domain: str) -> dict:
    host = urlparse(domain).hostname or domain.strip("/")
    spf = txt_records(host)
    dmarc = txt_records("_dmarc." + host)
    reachable = not (spf is None and dmarc is None)
    findings = analyze(host, spf, dmarc) if reachable else []
    order = list(PENALTY)
    score, counts = 100, {s: 0 for s in PENALTY}
    for f in findings:
        score -= PENALTY.get(f["severity"], 0)
        counts[f["severity"]] += 1
    score = max(0, min(100, score))
    findings.sort(key=lambda f: order.index(f["severity"]))
    risk = next((s for s in order[:4] if counts[s]), "minimal")
    summary = (f"Auditoría de DNS/email de {host}: {len(findings)} hallazgo(s) en SPF/DMARC."
               if reachable else f"No se pudo consultar el DNS de {host}.")
    return {
        "kind": "dns", "provider": "dns", "model": "auditoría DNS/email",
        "target": host, "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "score": score, "grade": _grade(score), "counts": counts,
        "total_checks": len(findings), "passed": 0, "pages": [host], "profile": {},
        "http_status": 200, "reachable": reachable,
        "notice": None if reachable else "no se pudo resolver el DNS del dominio",
        "overall_risk": risk, "summary": summary,
        "usage": {"input_tokens": 0, "output_tokens": 0, "est_cost_usd": 0.0},
        "findings": findings,
    }
