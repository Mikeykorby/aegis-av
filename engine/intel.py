"""Aegis Security — threat intelligence updater (abuse.ch + YARA Forge)."""
from __future__ import annotations

import os
import shutil
import ssl
import threading
import time
import urllib.request
import zipfile

from . import store

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AegisSecurity/2.1"

FEEDS = [
    ("md5.txt", "https://bazaar.abuse.ch/export/txt/md5/recent/",
     "MalwareBazaar MD5 signatures"),
    ("sha256.txt", "https://bazaar.abuse.ch/export/txt/sha256/recent/",
     "MalwareBazaar SHA-256 signatures"),
    ("urlhaus.txt", "https://urlhaus.abuse.ch/downloads/text_online/",
     "URLhaus malicious URL feed"),
]

YARA_URL = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"


def _fetch(url: str, dest: str, timeout: int = 90) -> int:
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    tmp = dest + ".part"
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r, open(tmp, "wb") as fh:
        shutil.copyfileobj(r, fh, 1024 * 128)
    n = os.path.getsize(tmp)
    if n < 128:
        os.remove(tmp)
        raise IOError("response too small")
    os.replace(tmp, dest)
    return n


class Updater:
    def __init__(self, engine=None, on_event=None):
        self.engine = engine
        self.on_event = on_event or (lambda *_: None)
        self.state = "idle"
        self.progress = 0
        self.message = ""
        self.last_error = ""
        self._lock = threading.Lock()

    def status(self) -> dict:
        last = store.get("intel.last_update", 0)
        return {
            "state": self.state, "progress": self.progress, "message": self.message,
            "last_update": last,
            "last_update_h": _ago(last),
            "error": self.last_error,
            "signatures": (len(self.engine.md5_set) + len(self.engine.sha_set))
            if self.engine else 0,
            "urls": len(self.engine.url_hosts) if self.engine else 0,
            "rules": self.engine.rule_count if self.engine else 0,
            "stale": (time.time() - last) > 86400 if last else True,
        }

    def update(self, include_rules: bool = True) -> dict:
        with self._lock:
            if self.state == "running":
                return {"ok": False, "error": "Update already running"}
            self.state = "running"
            self.progress = 0
            self.last_error = ""
        t = threading.Thread(target=self._run, args=(include_rules,), daemon=True)
        t.start()
        return {"ok": True}

    def _run(self, include_rules: bool) -> None:
        got, failed = 0, []
        steps = len(FEEDS) + (1 if include_rules else 0)
        step = 0
        try:
            for fn, url, label in FEEDS:
                self.message = f"Downloading {label}…"
                self.progress = int(step / steps * 100)
                try:
                    n = _fetch(url, os.path.join(store.DATA_DIR, fn))
                    got += 1
                    self.on_event("update_progress",
                                  {"message": f"{label}: {n // 1024} KB", "percent": self.progress})
                except Exception as e:
                    failed.append(f"{label}: {e}")
                step += 1

            if include_rules:
                self.message = "Downloading YARA rule package…"
                self.progress = int(step / steps * 100)
                try:
                    zp = os.path.join(store.DATA_DIR, "rules.zip")
                    _fetch(YARA_URL, zp, timeout=180)
                    self.message = "Compiling detection rules…"
                    with zipfile.ZipFile(zp) as z:
                        member = next(n for n in z.namelist() if n.endswith(".yar"))
                        with z.open(member) as src, \
                                open(os.path.join(store.DATA_DIR, "core.yar"), "wb") as dst:
                            shutil.copyfileobj(src, dst)
                    os.remove(zp)
                    src_path = os.path.join(store.DATA_DIR, "core.yar")
                    count = sum(1 for line in open(src_path, encoding="utf-8", errors="ignore")
                                if line.lstrip().startswith("rule "))
                    import yara
                    rules = yara.compile(src_path)
                    rules.save(os.path.join(store.DATA_DIR, "core.yarc"))
                    with open(os.path.join(store.DATA_DIR, "rules.meta"), "w") as fh:
                        fh.write(str(count))
                    got += 1
                except Exception as e:
                    failed.append(f"YARA rules: {e}")
                step += 1

            self.progress = 100
            if self.engine:
                self.message = "Reloading engine…"
                self.engine.load()
            store.set("intel.last_update", time.time())
            self.state = "done"
            self.message = f"Definitions updated ({got}/{steps} sources)"
            if failed:
                self.last_error = "; ".join(failed)[:300]
            store.log("update", "info", "Threat intelligence updated",
                      self.message + (f" — issues: {self.last_error}" if failed else ""))
            self.on_event("update_done", self.status())
        except Exception as e:
            self.state = "error"
            self.last_error = str(e)
            store.log("update", "medium", "Definition update failed", str(e))
            self.on_event("update_done", self.status())


def _ago(ts: float) -> str:
    if not ts:
        return "never"
    d = time.time() - ts
    if d < 90:
        return "just now"
    if d < 3600:
        return f"{int(d // 60)} min ago"
    if d < 172800:
        return f"{int(d // 3600)} hours ago"
    return f"{int(d // 86400)} days ago"
