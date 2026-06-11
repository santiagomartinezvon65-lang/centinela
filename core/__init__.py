"""Centinela — escáner de vulnerabilidades web (defensivo, stdlib only)."""
from .http import fetch
from .checks import run_all
from .report import build, write
from .scanner import scan

__all__ = ["fetch", "run_all", "build", "write", "scan"]
