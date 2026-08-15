"""Aegis Security — App Updater (Avast-style "Update apps").

Updates third-party installed applications via Windows Package Manager (winget),
and checks for an Aegis self-update from the GitHub release feed.

winget output is localised and table-formatted, so parsing is best-effort: we
extract the package Id (the stable reverse-domain token, e.g. "7zip.7zip") and
the available version. If parsing yields nothing we report an honest empty list
rather than failing. Upgrade commands use the Id, which is locale-independent.
"""
from __future__ import annotations

import json
import re
import subprocess
import urllib.request
import ssl
import threading
import time

from . import store

GITHUB_RELEASES = "https://api.github.com/repos/Mikeykorby/aegis-av/releases/latest"
CREATE_NO_WINDOW = 0x08000000
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AegisSecurity/2.2.1.5"

_self_version = "2.2.1.5"


def _run(cmd: str, timeout: int = 120) -> str:
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout, creationflags=CREATE_NO_WINDOW,
                           errors="ignore")
        return (p.stdout or "") + (p.stderr or "")
    except Exception as e:  # pragma: no cover
        return f"__ERR__{e}"


def winget_present() -> bool:
    out = _run("winget --version", timeout=20)
    return not out.startswith("__ERR__") and bool(out.strip())


def status() -> dict:
    return {
        "enabled": bool(store.get("apps.auto_update", False)),
        "winget": winget_present(),
        "last_run": store.get("apps.last_update", 0),
        "self_version": _self_version,
        "self_latest": store.get("apps.self_latest", ""),
        "self_update_available": _self_update_available(),
    }


def _self_update_available() -> bool:
    latest = store.get("apps.self_latest", "")
    if not latest:
        return False
    def norm(v): return tuple(int(x) for x in re.findall(r"\d+", v)[:3])
    try:
        return norm(latest) > norm(_self_version)
    except Exception:
        return False


def list_apps() -> list[dict]:
    """Return upgradable installed apps (best-effort parse of `winget upgrade`)."""
    if not winget_present():
        return []
    out = _run("winget upgrade --disable-interactivity", timeout=90)
    if out.startswith("__ERR__"):
        return []
    apps = []
    for line in out.splitlines():
        # The Id is a reverse-domain token without spaces; the line ends with a
        # Source word and contains an available version after a name. Heuristic:
        # grab tokens that look like Vendor.Product and a "X -> Y" or two versions.
        m = re.search(r"\b([A-Za-z0-9_.-]+\.[A-Za-z0-9_.-]+)\b", line)
        if not m:
            continue
        pid = m.group(1)
        # avoid matching the header/footer lines
        if pid.lower() in ("name", "id", "version", "available", "source", "winget"):
            continue
        # require an available version pattern: a version-like token after the id
        avail = re.findall(r"\b\d+\.\d+(?:\.\d+)*\b", line)
        if len(avail) < 2:
            continue
        apps.append({"id": pid, "name": pid, "current": avail[0],
                     "available": avail[-1]})
    # de-dup by id
    seen = {}
    for a in apps:
        seen[a["id"]] = a
    return list(seen.values())


def update_app(pid: str) -> dict:
    if not winget_present():
        return {"ok": False, "error": "winget not available"}
    out = _run(f'winget upgrade --id "{pid}" --disable-interactivity --accept-package-agreements '
               f"--accept-source-agreements", timeout=180)
    ok = ("successfully" in out.lower() or "updated" in out.lower()) \
        and "failed" not in out.lower()[:0] and not out.startswith("__ERR__")
    return {"ok": ok, "id": pid, "detail": out.strip()[:400]}


def update_all() -> dict:
    if not winget_present():
        return {"ok": False, "error": "winget not available", "updated": 0}
    out = _run("winget upgrade --all --disable-interactivity --accept-package-agreements "
               "--accept-source-agreements", timeout=600)
    updated = out.lower().count("successfully")
    store.set("apps.last_update", int(time.time()))
    return {"ok": not out.startswith("__ERR__"), "detail": out.strip()[:400],
            "updated": updated}


def check_self_update() -> dict:
    """Read-only check of the latest Aegis GitHub release tag."""
    try:
        req = urllib.request.Request(GITHUB_RELEASES, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=25,
                                    context=ssl.create_default_context()) as r:
            data = json.loads(r.read().decode("utf-8", "ignore"))
        tag = (data.get("tag_name") or "").lstrip("vV")
        store.set("apps.self_latest", tag)
        store.set("apps.self_url", data.get("html_url", ""))
        return {"ok": True, "latest": tag,
                "available": _self_update_available(),
                "url": data.get("html_url", "")}
    except Exception as e:
        return {"ok": False, "latest": "", "error": str(e)[:200],
                "available": False}


def set_auto_update(on: bool) -> dict:
    store.set("apps.auto_update", bool(on))
    return {"ok": True, "enabled": bool(on)}


# Periodic self-update check (called from the scheduler in api.py).
def maybe_self_check():
    last = store.get("apps.self_checked", 0)
    if time.time() - last > 86400:
        store.set("apps.self_checked", int(time.time()))
        try:
            check_self_update()
        except Exception:
            pass
