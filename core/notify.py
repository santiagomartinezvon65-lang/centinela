"""Centinela Notify — manda las alertas del guardián a donde el equipo trabaja.

Canales: webhooks (Slack/Discord/Teams/genérico) y email (SMTP). Pensado para
integración tipo enterprise. Secretos (password SMTP) salen de variable de
entorno CENTINELA_SMTP_PASS, nunca se guardan en disco.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import urllib.request
from urllib.parse import urlparse

from . import store

CONFIG = os.path.join(store.DATA, "notify.json")
_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def load() -> dict:
    try:
        with open(CONFIG, encoding="utf-8") as fh:
            cfg = json.load(fh)
    except (FileNotFoundError, ValueError):
        cfg = {}
    cfg.setdefault("webhooks", [])
    cfg.setdefault("email", {})
    cfg.setdefault("min_severity", "medium")
    cfg.setdefault("desktop", True)
    return cfg


def save(cfg: dict) -> None:
    os.makedirs(store.DATA, exist_ok=True)
    with open(CONFIG, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, ensure_ascii=False, indent=2)


def _host(t: str) -> str:
    return urlparse(t).hostname or t


def _format(alerts: list[dict]) -> str:
    lines = [f"🛡 Centinela — {len(alerts)} alerta(s) de seguridad:"]
    for a in alerts[:15]:
        lines.append(f"• [{a['severity'].upper()}] {_host(a['target'])} — {a['title']}")
    if len(alerts) > 15:
        lines.append(f"… y {len(alerts) - 15} más")
    return "\n".join(lines)


# ── canales ─────────────────────────────────────────────────────────
def _post_webhook(url: str, alerts: list[dict]) -> int:
    text = _format(alerts)
    low = url.lower()
    if "hooks.slack.com" in low:
        payload = {"text": text}
    elif "discord" in low:
        payload = {"content": text[:1900]}
    elif "webhook.office" in low or "office.com" in low:
        payload = {"text": text}
    else:
        payload = {"text": text, "count": len(alerts), "alerts": alerts[:50]}
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "Centinela"},
        method="POST")
    with urllib.request.urlopen(req, timeout=12) as r:
        return r.status


def desktop(title: str, message: str) -> bool:
    """Notificación nativa de Windows (balloon tip vía PowerShell, sin deps)."""
    if not sys.platform.startswith("win"):
        return False
    ps = shutil.which("powershell") or "powershell"
    script = (
        "Add-Type -AssemblyName System.Windows.Forms;"
        "$n=New-Object System.Windows.Forms.NotifyIcon;"
        "$n.Icon=[System.Drawing.SystemIcons]::Warning;$n.Visible=$true;"
        f"$n.ShowBalloonTip(9000,{json.dumps(title)},{json.dumps(message)},"
        "[System.Windows.Forms.ToolTipIcon]::Warning);"
        "Start-Sleep -Seconds 9;$n.Dispose()")
    try:
        subprocess.Popen([ps, "-NoProfile", "-WindowStyle", "Hidden", "-Command", script],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:  # noqa: BLE001
        return False


def _send_email(cfg: dict, alerts: list[dict]) -> None:
    import smtplib
    import ssl
    from email.message import EmailMessage

    password = os.environ.get("CENTINELA_SMTP_PASS", "")
    msg = EmailMessage()
    msg["Subject"] = f"[Centinela] {len(alerts)} alerta(s) de seguridad"
    msg["From"] = cfg["from"]
    msg["To"] = ", ".join(cfg["to"])
    msg.set_content(_format(alerts))
    with smtplib.SMTP(cfg["host"], int(cfg.get("port", 587)), timeout=15) as s:
        if cfg.get("use_tls", True):
            s.starttls(context=ssl.create_default_context())
        if cfg.get("user") and password:
            s.login(cfg["user"], password)
        s.send_message(msg)


# ── API pública ─────────────────────────────────────────────────────
def notify(alerts: list[dict]) -> list[str]:
    """Envía las alertas (filtradas por min_severity) a todos los canales."""
    if not alerts:
        return []
    cfg = load()
    rank = _RANK.get(cfg.get("min_severity", "medium"), 2)
    alerts = [a for a in alerts if _RANK.get(a.get("severity", "info"), 4) <= rank]
    if not alerts:
        return []
    sent = []
    if cfg.get("desktop", True):
        top = alerts[0]
        extra = f" +{len(alerts) - 1} más" if len(alerts) > 1 else ""
        if desktop(f"🛡 Centinela — {len(alerts)} alerta(s)",
                   f"[{top['severity']}] {top['title']} ({_host(top['target'])}){extra}"):
            sent.append("escritorio")
    for url in cfg.get("webhooks", []):
        try:
            _post_webhook(url, alerts)
            sent.append(f"webhook:{_host(url)}")
        except Exception as e:  # noqa: BLE001
            sent.append(f"webhook ERROR ({_host(url)}): {e}")
    if cfg.get("email", {}).get("to"):
        try:
            _send_email(cfg["email"], alerts)
            sent.append("email")
        except Exception as e:  # noqa: BLE001
            sent.append(f"email ERROR: {e}")
    return sent


def add_webhook(url: str) -> None:
    cfg = load()
    if url not in cfg["webhooks"]:
        cfg["webhooks"].append(url)
    save(cfg)


def remove_webhook(url: str) -> bool:
    cfg = load()
    n = len(cfg["webhooks"])
    cfg["webhooks"] = [w for w in cfg["webhooks"] if w != url]
    save(cfg)
    return len(cfg["webhooks"]) < n


def set_email(host: str, port: int, user: str, sender: str, to: list[str],
              use_tls: bool = True) -> None:
    cfg = load()
    cfg["email"] = {"host": host, "port": port, "user": user, "from": sender,
                    "to": to, "use_tls": use_tls}
    save(cfg)


def set_min_severity(level: str) -> None:
    cfg = load()
    cfg["min_severity"] = level
    save(cfg)


def status() -> dict:
    cfg = load()
    return {"webhooks": [_host(w) for w in cfg["webhooks"]],
            "email_to": cfg.get("email", {}).get("to", []),
            "smtp_pass_env": bool(os.environ.get("CENTINELA_SMTP_PASS")),
            "desktop": cfg.get("desktop", True),
            "min_severity": cfg.get("min_severity", "medium")}


def test() -> list[str]:
    demo = [{"ts": "ahora", "target": "https://demo.centinela.test",
             "severity": "high", "kind": "nuevo",
             "title": "Prueba de notificación de Centinela", "detail": ""}]
    return notify(demo)
