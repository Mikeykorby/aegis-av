"""Aegis Security — scan orchestration, quarantine chest, threat resolution."""
from __future__ import annotations

import io
import os
import shutil
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import store
from .detect import Engine, Verdict, SEV_ORDER

# Chest obfuscation key — quarantined files are XOR'd so they cannot execute
# and won't be re-detected by other scanners while stored.
_CHEST_KEY = b"AEGIS-CHEST-v1\x00\x91"

SMART_TARGETS = [
    os.environ.get("TEMP", ""),
    os.path.join(os.path.expanduser("~"), "Downloads"),
    os.path.join(os.path.expanduser("~"), "Desktop"),
    os.path.join(os.path.expanduser("~"), "Documents"),
    os.path.join(os.path.expanduser("~"), "AppData", "Roaming"),
    os.path.join(os.path.expanduser("~"), "AppData", "Local", "Temp"),
    os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows",
                 "Start Menu", "Programs", "Startup"),
    os.path.join(os.environ.get("PROGRAMDATA", ""), "Microsoft", "Windows",
                 "Start Menu", "Programs", "StartUp"),
    "C:\\Windows\\Temp",
]

SKIP_DIRS = {
    "$recycle.bin", "system volume information", "windowsapps", "winsxs",
    "servicing", "assembly", "driverstore", "installer", "sxs",
    "node_modules", ".git", "__pycache__", "aegis",
}


def _xor(data: bytes) -> bytes:
    k = _CHEST_KEY
    kl = len(k)
    return bytes(b ^ k[i % kl] for i, b in enumerate(data))


class ScanJob:
    """A cancellable, pausable scan with live progress."""

    def __init__(self, engine: Engine, kind: str, roots: list[str],
                 deep: bool = False, on_event=None):
        self.engine = engine
        self.kind = kind
        self.roots = roots
        self.deep = deep
        self.on_event = on_event or (lambda *_: None)

        self.id = uuid.uuid4().hex[:8]
        self.state = "idle"          # idle|enumerating|running|paused|done|cancelled|error
        self.total = 0
        self.done = 0
        self.current = ""
        self.started = 0.0
        self.finished = 0.0
        self.threats: list[dict] = []
        self.errors = 0
        self.skipped = 0
        self._cancel = threading.Event()
        self._pause = threading.Event()
        self._pause.set()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------ controls
    def start(self) -> "ScanJob":
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def cancel(self) -> None:
        self._cancel.set()
        self._pause.set()

    def pause(self) -> None:
        if self.state == "running":
            self._pause.clear()
            self.state = "paused"

    def resume(self) -> None:
        if self.state == "paused":
            self._pause.set()
            self.state = "running"

    # ------------------------------------------------------------ progress
    def snapshot(self) -> dict:
        el = (self.finished or time.time()) - (self.started or time.time())
        pct = (self.done / self.total * 100) if self.total else 0.0
        rate = self.done / el if el > 0.5 else 0.0
        eta = (self.total - self.done) / rate if rate > 0.2 else 0
        return {
            "id": self.id, "kind": self.kind, "state": self.state,
            "total": self.total, "done": self.done, "percent": round(pct, 1),
            "current": self.current, "elapsed": round(el, 1),
            "eta": int(eta), "rate": round(rate, 1),
            "threats": self.threats, "threat_count": len(self.threats),
            "errors": self.errors, "skipped": self.skipped,
        }

    # ----------------------------------------------------------- execution
    def _enumerate(self) -> list[str]:
        files: list[str] = []
        maxmb = int(store.get("scan.max_file_mb", 64))
        excl = [os.path.normcase(e["path"]) for e in store.exclusions()]
        for root in self.roots:
            if not root or not os.path.exists(root):
                continue
            if os.path.isfile(root):
                files.append(root)
                continue
            for dirpath, dirnames, filenames in os.walk(root, topdown=True):
                if self._cancel.is_set():
                    return files
                dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS
                               and not d.startswith("$")]
                nc = os.path.normcase(dirpath)
                if any(nc.startswith(e) for e in excl) or store.CHEST_DIR.lower() in nc.lower():
                    dirnames[:] = []
                    continue
                for fn in filenames:
                    p = os.path.join(dirpath, fn)
                    if not self.deep and not Engine.should_scan(p):
                        continue
                    files.append(p)
                    if len(files) % 4000 == 0:
                        self.current = f"Enumerating… {len(files):,} files"
        return files

    def _run(self) -> None:
        self.started = time.time()
        self.state = "enumerating"
        self.current = "Building file list…"
        try:
            files = self._enumerate()
            self.total = len(files)
            if self._cancel.is_set():
                self._finish("cancelled")
                return
            self.state = "running"
            pup = bool(store.get("scan.pup", True))
            maxmb = int(store.get("scan.max_file_mb", 64))
            workers = max(2, min(16, int(store.get("scan.threads", 4))))

            def work(p: str):
                self._pause.wait()
                if self._cancel.is_set():
                    return None
                return self.engine.scan_file(p, deep=self.deep, pup=pup, max_mb=maxmb)

            with ThreadPoolExecutor(max_workers=workers) as ex:
                futs = {ex.submit(work, p): p for p in files}
                for fut in as_completed(futs):
                    if self._cancel.is_set():
                        for f in futs:
                            f.cancel()
                        break
                    p = futs[fut]
                    with self._lock:
                        self.done += 1
                        self.current = p
                    try:
                        v = fut.result()
                    except Exception:
                        self.errors += 1
                        continue
                    if v is None:
                        continue
                    if v.error:
                        self.skipped += 1
                        continue
                    if not v.clean:
                        d = v.to_dict()
                        d["resolved"] = False
                        with self._lock:
                            self.threats.append(d)
                        self.on_event("threat", d)
                        store.log("detection", v.severity,
                                  f"{v.name} detected", d["detections"][0]["reason"]
                                  if d["detections"] else "", v.path)
            self._finish("cancelled" if self._cancel.is_set() else "done")
        except Exception as e:                                    # pragma: no cover
            self.state = "error"
            self.current = str(e)
            self.finished = time.time()
            store.log("error", "medium", "Scan failed", str(e))

    def _finish(self, state: str) -> None:
        self.state = state
        self.finished = time.time()
        self.current = ""
        dur = self.finished - self.started
        store.scan_add(self.kind, dur, self.done, len(self.threats), 0,
                       f"{self.kind} scan: {self.done:,} files in {dur:.0f}s")
        sev = "high" if self.threats else "info"
        store.log("scan", sev,
                  f"{self.kind.title()} scan {state}",
                  f"{self.done:,} files scanned · {len(self.threats)} threats found")
        self.on_event("scan_done", self.snapshot())


# ============================================================== quarantine
def quarantine(path: str, threat: str, sha: str = "", engine_name: str = "") -> dict:
    """Move a file into the encrypted chest. Returns {ok, id|error}."""
    if not os.path.exists(path):
        return {"ok": False, "error": "File no longer exists"}
    try:
        size = os.path.getsize(path)
        token = uuid.uuid4().hex
        stored = os.path.join(store.CHEST_DIR, token + ".aegis")
        with open(path, "rb") as src, open(stored, "wb") as dst:
            while True:
                chunk = src.read(1024 * 512)
                if not chunk:
                    break
                dst.write(_xor(chunk))
        # metadata sidecar so the chest survives DB loss
        with open(stored + ".meta", "w", encoding="utf-8") as mf:
            mf.write(f"{path}\n{threat}\n{sha}\n{size}\n")
        try:
            os.remove(path)
        except PermissionError:
            os.remove(stored)
            os.remove(stored + ".meta")
            return {"ok": False, "error": "File is locked by another process"}
        qid = store.q_add(path, stored, threat, sha, size, engine_name)
        store.log("quarantine", "high", "Moved to Virus Chest", threat, path)
        return {"ok": True, "id": qid}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def restore(qid: int) -> dict:
    rec = store.q_get(qid)
    if not rec:
        return {"ok": False, "error": "Not found"}
    dest = rec["orig_path"]
    try:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if os.path.exists(dest):
            base, ext = os.path.splitext(dest)
            dest = f"{base}.restored{ext}"
        with open(rec["stored"], "rb") as src, open(dest, "wb") as dst:
            while True:
                chunk = src.read(1024 * 512)
                if not chunk:
                    break
                dst.write(_xor(chunk))
        os.remove(rec["stored"])
        try:
            os.remove(rec["stored"] + ".meta")
        except OSError:
            pass
        store.q_mark(qid, 1)
        store.exclusion_add(dest, "Restored from Virus Chest")
        store.log("quarantine", "medium", "Restored from chest",
                  rec["threat"] + " — path added to exclusions", dest)
        return {"ok": True, "path": dest}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def delete_forever(qid: int) -> dict:
    rec = store.q_get(qid)
    if not rec:
        return {"ok": False, "error": "Not found"}
    try:
        if os.path.exists(rec["stored"]):
            # overwrite before unlink
            n = os.path.getsize(rec["stored"])
            with open(rec["stored"], "r+b") as fh:
                fh.write(os.urandom(min(n, 1024 * 256)))
            os.remove(rec["stored"])
        try:
            os.remove(rec["stored"] + ".meta")
        except OSError:
            pass
        store.q_delete(qid)
        store.log("quarantine", "info", "Permanently deleted", rec["threat"],
                  rec["orig_path"])
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def empty_chest() -> dict:
    n = 0
    for rec in store.q_list():
        if delete_forever(rec["id"]).get("ok"):
            n += 1
    return {"ok": True, "deleted": n}


def resolve(path: str, threat: str, action: str, sha: str = "") -> dict:
    """action: quarantine | delete | ignore"""
    if action == "quarantine":
        return quarantine(path, threat, sha)
    if action == "delete":
        try:
            if os.path.exists(path):
                n = os.path.getsize(path)
                with open(path, "r+b") as fh:
                    fh.write(os.urandom(min(n, 1024 * 256)))
                os.remove(path)
            store.log("threat", "high", "Threat deleted", threat, path)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    if action == "ignore":
        store.exclusion_add(path, f"Ignored: {threat}")
        store.log("threat", "low", "Threat ignored (excluded)", threat, path)
        return {"ok": True}
    return {"ok": False, "error": "Unknown action"}
