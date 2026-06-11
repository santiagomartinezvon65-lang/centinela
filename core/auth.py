"""Centinela Auth — cuentas, roles, API-keys y sesiones, 100% stdlib (sin deps).

Contraseñas hasheadas con PBKDF2-HMAC-SHA256 (salt por usuario, 200k iteraciones).
API-keys y sesiones firmadas con HMAC. Todo en JSON, sin base de datos externa.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timezone

from . import store

USERS = os.path.join(store.DATA, "users.json")
SECRET = os.path.join(store.DATA, "secret.key")
ROLES = ("admin", "analyst", "viewer")
_PERMS = {
    "admin": {"read", "scan", "manage", "admin"},
    "analyst": {"read", "scan", "manage"},
    "viewer": {"read"},
}
_ITER = 200_000


# ── secreto del servidor (firma de sesiones) ────────────────────────
def _server_secret() -> bytes:
    try:
        with open(SECRET, "rb") as fh:
            return fh.read()
    except FileNotFoundError:
        os.makedirs(store.DATA, exist_ok=True)
        s = secrets.token_bytes(32)
        with open(SECRET, "wb") as fh:
            fh.write(s)
        try:
            os.chmod(SECRET, 0o600)
        except OSError:
            pass
        return s


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _load() -> dict:
    try:
        with open(USERS, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, ValueError):
        return {}


def _save(users: dict) -> None:
    os.makedirs(store.DATA, exist_ok=True)
    with open(USERS, "w", encoding="utf-8") as fh:
        json.dump(users, fh, ensure_ascii=False, indent=2)
    try:
        os.chmod(USERS, 0o600)
    except OSError:
        pass


def _hash(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                               bytes.fromhex(salt), _ITER).hex()


def _new_key() -> str:
    return "ck_" + secrets.token_urlsafe(24)


# ── usuarios ────────────────────────────────────────────────────────
def create_user(username: str, password: str, role: str = "viewer") -> dict:
    users = _load()
    if username in users:
        raise ValueError("el usuario ya existe")
    if role not in ROLES:
        raise ValueError(f"rol inválido (use: {', '.join(ROLES)})")
    salt = secrets.token_hex(16)
    users[username] = {"username": username, "role": role, "salt": salt,
                       "pwd": _hash(password, salt), "api_key": _new_key(),
                       "created_at": _now()}
    _save(users)
    return users[username]


def verify(username: str, password: str) -> bool:
    u = _load().get(username)
    return bool(u and hmac.compare_digest(u["pwd"], _hash(password, u["salt"])))


def get(username: str) -> dict | None:
    return _load().get(username)


def list_users() -> list[dict]:
    return list(_load().values())


def count() -> int:
    return len(_load())


def set_role(username: str, role: str) -> bool:
    if role not in ROLES:
        return False
    users = _load()
    if username not in users:
        return False
    users[username]["role"] = role
    _save(users)
    return True


def set_password(username: str, password: str) -> bool:
    users = _load()
    if username not in users:
        return False
    users[username]["salt"] = secrets.token_hex(16)
    users[username]["pwd"] = _hash(password, users[username]["salt"])
    _save(users)
    return True


def delete(username: str) -> bool:
    users = _load()
    if username not in users:
        return False
    del users[username]
    _save(users)
    return True


def regen_key(username: str) -> str | None:
    users = _load()
    if username not in users:
        return None
    users[username]["api_key"] = _new_key()
    _save(users)
    return users[username]["api_key"]


def by_api_key(key: str) -> dict | None:
    if not key:
        return None
    for u in _load().values():
        if hmac.compare_digest(u["api_key"], key):
            return u
    return None


def can(role: str, action: str) -> bool:
    return action in _PERMS.get(role, set())


# ── sesiones firmadas (stateless, para login del dashboard) ─────────
def make_session(username: str, hours: int = 12) -> str:
    exp = int(time.time()) + hours * 3600
    msg = f"{username}|{exp}"
    sig = hmac.new(_server_secret(), msg.encode(), hashlib.sha256).hexdigest()[:32]
    return base64.urlsafe_b64encode(f"{msg}|{sig}".encode()).decode()


def read_session(token: str) -> str | None:
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        username, exp, sig = raw.rsplit("|", 2)
    except Exception:  # noqa: BLE001
        return None
    good = hmac.new(_server_secret(), f"{username}|{exp}".encode(),
                    hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(sig, good):
        return None
    if int(exp) < time.time():
        return None
    return username
