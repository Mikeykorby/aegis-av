"""Aegis Security — real-time protection shields.

File Shield      : watchdog observer on hot paths, scans new/modified files.
Ransomware Shield: canary/honeypot files + mass-modification rate detection.
Behaviour Shield : psutil process poller flagging LOLBin abuse & suspicious trees.
Web Shield       : hosts-file / URLhaus lookup surface for the UI.
"""
from __future__ import annotations

import os
import re
import sys
import threading
import time
from collections import deque

from . import store
from .detect import Engine

try:
    import psutil
except Exception:                                                # pragma: no cover
    psutil = None

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except Exception:                                                # pragma: no cover
    Observer = None
    FileSystemEventHandler = object

# On Windows, when pywebview's .NET runtime (pythonnet/clr) is active, the
# WindowsApiObserver's ReadDirectoryChangesW can silently fail to deliver
# notifications — the .NET STA message loop on the main thread interferes
# with the kernel's I/O completion delivery.  PollingObserver uses stat()
# polling instead and is immune to this.  We pick the right one at import
# time based on whether we're running under pywebview.
try:
    import clr  # noqa: F401
    _HAS_NET = True
except Exception:
    _HAS_NET = False

if Observer is not None and _HAS_NET and sys.platform == "win32":
    # pywebview + .NET runtime active: use polling to sidestep the
    # ReadDirectoryChangesW delivery issue.
    from watchdog.observers.polling import PollingObserver as _ObserverImpl
    Observer = _ObserverImpl
elif Observer is None and sys.platform == "win32":
    # Fallback to polling if winapi observer import failed
    try:
        from watchdog.observers.polling import PollingObserver as _ObserverImpl
        Observer = _ObserverImpl
    except Exception:
        pass


HOT_PATHS = [
    os.path.join(os.path.expanduser("~"), "Downloads"),
    os.path.join(os.path.expanduser("~"), "Desktop"),
    os.path.join(os.path.expanduser("~"), "Documents"),
    os.environ.get("TEMP", ""),
    os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows",
                 "Start Menu", "Programs", "Startup"),
]

# Command lines that are almost always malicious in combination.
BEHAVIOUR_RULES: list[tuple[str, str, str]] = [
    (r"(?i)vssadmin(\.exe)?\s+delete\s+shadows", "Shadow copy deletion", "critical"),
    (r"(?i)wbadmin(\.exe)?\s+delete\s+catalog", "Backup catalog deletion", "critical"),
    (r"(?i)bcdedit.*recoveryenabled\s+no", "Recovery disabled", "critical"),
    (r"(?i)powershell.*-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}",
     "Encoded PowerShell command", "high"),
    (r"(?i)powershell.*(downloadstring|downloadfile|invoke-webrequest).*http",
     "PowerShell remote download", "high"),
    (r"(?i)certutil.*(-urlcache|-decode)", "certutil LOLBin abuse", "high"),
    (r"(?i)mshta.*(http|javascript:)", "mshta remote payload", "high"),
    (r"(?i)rundll32.*javascript:", "rundll32 script execution", "critical"),
    (r"(?i)regsvr32.*\/i:http", "regsvr32 remote scriptlet", "critical"),
    (r"(?i)netsh\s+advfirewall\s+set\s+.*state\s+off", "Firewall disabled", "high"),
    (r"(?i)set-mppreference\s+-disablerealtimemonitoring", "Defender disabled", "critical"),
    (r"(?i)schtasks.*\/create.*\/ru\s+system", "SYSTEM task persistence", "high"),
    (r"(?i)wmic.*process\s+call\s+create", "WMI process creation", "medium"),
    (r"(?i)reg(\.exe)?\s+add.*\\currentversion\\run", "Run-key persistence", "medium"),
    (r"(?i)cipher(\.exe)?\s+\/w", "Free-space wipe", "medium"),
]

CANARY_NAMES = [
    "0_aegis_do_not_delete.docx",
    "~$aegis_protected.xlsx",
    "zz_aegis_readme.txt",
]
CANARY_BODY = (b"Aegis Security canary file. Do not modify or delete.\r\n"
               b"Any process altering this file is treated as ransomware.\r\n")


class _FileHandler(FileSystemEventHandler):
    def __init__(self, shield: "ShieldManager"):
        self.shield = shield
        self._recent: dict[str, float] = {}

    def _handle(self, path: str):
        if not path or os.path.isdir(path):
            return
        now = time.time()
        last = self._recent.get(path, 0)
        if now - last < 3:
            return
        self._recent[path] = now
        if len(self._recent) > 500:
            for k in [k for k, v in self._recent.items() if now - v > 60]:
                self._recent.pop(k, None)
        self.shield._queue_scan(path)

    def on_created(self, event):
        self._handle(getattr(event, "dest_path", None) or event.src_path)

    def on_modified(self, event):
        self._handle(event.src_path)

    def on_moved(self, event):
        self._handle(getattr(event, "dest_path", event.src_path))


class ShieldManager:
    def __init__(self, engine: Engine, on_event=None):
        self.engine = engine
        self.on_event = on_event or (lambda *_: None)
        self.running = False
        self._observer = None
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self._scan_q: deque[str] = deque(maxlen=400)
        self._q_lock = threading.Lock()
        self.stats = {
            "files_checked": 0, "threats_blocked": 0, "procs_checked": 0,
            "behaviour_alerts": 0, "canary_alerts": 0, "web_blocked": 0,
            "started": 0.0,
        }
        self._seen_pids: set[int] = set()
        self._mod_window: deque[float] = deque(maxlen=300)
        self._canaries: list[tuple[str, float]] = []
        # Cache ransomware-protected folders at start time so the watchdog
        # emitter thread (on_created → _handle → _queue_scan) never blocks
        # on a SQLite call — that was the root cause of "Not Responding".
        self._ransom_folders: list[str] = []

    # ---------------------------------------------------------- lifecycle
    def start(self) -> dict:
        if self.running:
            return {"ok": True, "already": True}
        self._stop.clear()
        self.running = True
        self.stats["started"] = time.time()

        if store.get("shield.file", True) and Observer is not None:
            try:
                self._observer = Observer()
                h = _FileHandler(self)
                added = 0
                watched = []
                for p in HOT_PATHS:
                    if p and os.path.isdir(p):
                        self._observer.schedule(h, p, recursive=True)
                        added += 1
                        watched.append(p)
                self._observer.start()
                store.log("shield", "info", "File Shield active",
                          f"Monitoring {added} high-risk locations: {watched}")
            except Exception as e:
                store.log("shield", "medium", "File Shield failed to start", str(e))
                self._observer = None

        self._spawn(self._scan_worker)
        if store.get("shield.behavior", True):
            self._spawn(self._behaviour_worker)
        # Cache the protected folder list so the watchdog emitter path
        # (_queue_scan) stays DB-free and never deadlocks.
        self._ransom_folders = [f for f in store.get("ransom.folders", [])
                                if os.path.isdir(f)]
        if store.get("shield.ransomware", True):
            self._plant_canaries()
            self._spawn(self._canary_worker)
        store.log("shield", "info", "Real-time protection enabled", "")
        # Readiness marker for tooling/tests: shields are fully armed.
        try:
            store.set_counter("shield_ready_at", int(time.time()))
        except Exception:
            pass
        return {"ok": True}

    def stop(self) -> dict:
        self.running = False
        self._stop.set()
        if self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=3)
            except Exception:
                pass
            self._observer = None
        self._threads.clear()
        store.log("shield", "medium", "Real-time protection disabled",
                  "Your PC is no longer actively protected")
        return {"ok": True}

    def _spawn(self, fn):
        t = threading.Thread(target=fn, daemon=True)
        t.start()
        self._threads.append(t)

    # -------------------------------------------------------- file shield
    def _queue_scan(self, path: str):
        with self._q_lock:
            self._scan_q.append(path)
        # Ransomware burst detection — use the cached folder list so the
        # watchdog emitter thread never blocks on SQLite.
        try:
            p = os.path.normcase(path)
            for folder in self._ransom_folders:
                if p.startswith(os.path.normcase(folder)):
                    self._mod_window.append(time.time())
                    break
        except Exception:
            pass

    def _scan_worker(self):
        while not self._stop.is_set():
            path = None
            with self._q_lock:
                if self._scan_q:
                    path = self._scan_q.popleft()
            if path is None:
                self._stop.wait(0.35)
                continue
            try:
                if store.is_excluded(path) or not os.path.exists(path):
                    continue
                if not Engine.should_scan(path):
                    continue
                time.sleep(0.25)                       # let the writer finish
                v = self.engine.scan_file(path, pup=bool(store.get("scan.pup", True)),
                                          max_mb=int(store.get("scan.max_file_mb", 64)))
                self.stats["files_checked"] += 1
                if not v.clean and v.severity in ("medium", "high", "critical", "pup"):
                    self.stats["threats_blocked"] += 1
                    from . import scanner
                    res = {"ok": False}
                    if store.get("action.default", "quarantine") == "quarantine" \
                            and v.severity != "pup":
                        res = scanner.quarantine(v.path, v.name, v.sha256, "realtime")
                    store.log("blocked", v.severity, f"{v.name} blocked in real time",
                              (v.detections[0].reason if v.detections else ""), v.path)
                    self.on_event("realtime_block", {
                        "path": v.path, "threat": v.name, "severity": v.severity,
                        "quarantined": bool(res.get("ok")),
                        "reason": v.detections[0].reason if v.detections else "",
                    })
            except Exception:
                pass

    # --------------------------------------------------- behaviour shield
    def _behaviour_worker(self):
        if psutil is None:
            return
        while not self._stop.is_set():
            try:
                for p in psutil.process_iter(["pid", "name", "cmdline", "ppid",
                                              "create_time", "exe"]):
                    pid = p.info["pid"]
                    if pid in self._seen_pids:
                        continue
                    self._seen_pids.add(pid)
                    if len(self._seen_pids) > 4000:
                        self._seen_pids = set(list(self._seen_pids)[-2000:])
                    if time.time() - (p.info.get("create_time") or 0) > 60:
                        continue
                    cl = " ".join(p.info.get("cmdline") or [])
                    if not cl:
                        continue
                    self.stats["procs_checked"] += 1
                    for pat, desc, sev in BEHAVIOUR_RULES:
                        if re.search(pat, cl):
                            self.stats["behaviour_alerts"] += 1
                            store.log("behaviour", sev, f"Behaviour alert: {desc}",
                                      cl[:400], p.info.get("exe") or p.info.get("name") or "")
                            self.on_event("behaviour", {
                                "pid": pid, "name": p.info.get("name"),
                                "desc": desc, "severity": sev, "cmdline": cl[:400],
                            })
                            break
            except Exception:
                pass
            self._stop.wait(2.5)

    # -------------------------------------------------- ransomware shield
    def _plant_canaries(self):
        self._canaries = []
        for folder in self._ransom_folders:
            if not os.path.isdir(folder):
                continue
            for nm in CANARY_NAMES:
                p = os.path.join(folder, nm)
                try:
                    if not os.path.exists(p):
                        with open(p, "wb") as fh:
                            fh.write(CANARY_BODY)
                        try:
                            os.system(f'attrib +h "{p}" >nul 2>&1')
                        except Exception:
                            pass
                    self._canaries.append((p, os.path.getmtime(p)))
                except Exception:
                    pass
        if self._canaries:
            store.log("shield", "info", "Ransomware Shield active",
                      f"{len(self._canaries)} canary files protecting "
                      f"{len(self._ransom_folders)} folders")

    def _canary_worker(self):
        while not self._stop.is_set():
            for i, (p, mt) in enumerate(list(self._canaries)):
                try:
                    if not os.path.exists(p):
                        self._alert_ransom(p, "Canary file was deleted")
                        try:
                            with open(p, "wb") as fh:
                                fh.write(CANARY_BODY)
                            self._canaries[i] = (p, os.path.getmtime(p))
                        except Exception:
                            pass
                        continue
                    cur = os.path.getmtime(p)
                    if abs(cur - mt) > 1:
                        self._alert_ransom(p, "Canary file was modified/encrypted")
                        self._canaries[i] = (p, cur)
                except Exception:
                    pass
            # mass-modification burst detection
            now = time.time()
            recent = [t for t in self._mod_window if now - t < 12]
            if len(recent) >= 120:
                self._mod_window.clear()
                self.stats["canary_alerts"] += 1
                store.log("ransomware", "critical", "Mass file modification detected",
                          f"{len(recent)} file changes in 12 seconds across protected folders")
                self.on_event("ransomware", {
                    "desc": f"{len(recent)} rapid file modifications detected",
                    "severity": "critical"})
            self._stop.wait(3.0)

    def _alert_ransom(self, path: str, why: str):
        self.stats["canary_alerts"] += 1
        culprit = self._find_culprit()
        store.log("ransomware", "critical", "Ransomware Shield triggered",
                  f"{why}. Suspect process: {culprit}", path)
        self.on_event("ransomware", {"desc": why, "path": path,
                                     "process": culprit, "severity": "critical"})

    @staticmethod
    def _find_culprit() -> str:
        if psutil is None:
            return "unknown"
        best, score = "unknown", 0.0
        try:
            for p in psutil.process_iter(["pid", "name", "cpu_percent", "create_time"]):
                nm = (p.info.get("name") or "").lower()
                if nm in ("system", "idle", "svchost.exe", "explorer.exe", "python.exe"):
                    continue
                age = time.time() - (p.info.get("create_time") or 0)
                s = (p.info.get("cpu_percent") or 0) + (50 if age < 300 else 0)
                if s > score:
                    best, score = f"{p.info.get('name')} (PID {p.info['pid']})", s
        except Exception:
            pass
        return best

    # ---------------------------------------------------------- reporting
    def status(self) -> dict:
        up = time.time() - self.stats["started"] if self.running else 0
        return {
            "running": self.running,
            "file": bool(self._observer) and self.running,
            "web": bool(store.get("shield.web", True)),
            "behavior": bool(store.get("shield.behavior", True)) and self.running,
            "ransomware": bool(store.get("shield.ransomware", True)) and self.running,
            "email": bool(store.get("shield.email", False)),
            "uptime": int(up),
            "canaries": len(self._canaries),
            **self.stats,
        }
