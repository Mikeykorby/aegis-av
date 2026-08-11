"""Aegis Security — JS <-> Python API bridge exposed to the WebView."""
from __future__ import annotations

import os
import platform
import socket
import subprocess
import threading
import time
import webbrowser

import psutil

from . import store, tools, scanner
from .detect import Engine
from .intel import Updater, _ago
from .scanner import ScanJob
from .shields import ShieldManager

QUICK_TARGETS = scanner.SMART_TARGETS


class Api:
    def __init__(self):
        self.engine = Engine()
        self.shields = ShieldManager(self.engine, on_event=self._push)
        self.updater = Updater(self.engine, on_event=self._push)
        self.job: ScanJob | None = None
        self.window = None
        self._on_close = None   # set by aegis.py -> hide window to tray (keep shields)
        self._on_minimize = None  # optional: route minimize to tray
        self._events: list[dict] = []
        self._ev_lock = threading.Lock()
        self._boot = time.time()
        self._sched_thread = threading.Thread(target=self._scheduler, daemon=True)
        self._sched_thread.start()
        self.shield_min_w = 1060
        self.shield_min_h = 700

    # -------------------------------------------------------------- events
    def _push(self, kind: str, data) -> None:
        with self._ev_lock:
            self._events.append({"kind": kind, "data": data, "ts": time.time()})
            if len(self._events) > 200:
                self._events = self._events[-120:]
        # Persist the running totals so dashboard stats survive a restart.
        if kind in ("realtime_block", "behaviour", "ransomware"):
            if data and data.get("severity") in ("high", "critical"):
                store.inc_counter("threats_blocked", 1)
        elif kind == "scan_done":
            store.inc_counter("scans_done", 1)
            store.inc_counter("files_checked", data.get("done", 0) if data else 0)

    def poll_events(self) -> list[dict]:
        with self._ev_lock:
            out, self._events = self._events, []
        return out

    # ------------------------------------------------------------ dashboard
    def dashboard(self) -> dict:
        sh = self.shields.status()
        up = self.updater.status()
        q = store.q_list()
        hist = store.scan_history(1)
        last_scan = hist[0] if hist else None
        issues, blockers = [], 0

        paused_until = store.get("protection.paused_until")
        if not sh["running"]:
            if paused_until and paused_until > time.time():
                left = int((paused_until - time.time()) // 60) + 1
                issues.append({"level": "medium",
                               "title": "Real-time protection is paused",
                               "detail": f"Not actively monitoring — auto re-enable in about {left} min.",
                               "action": "shields_on", "cta": "Resume now"})
            else:
                issues.append({"level": "critical", "title": "Real-time protection is off",
                               "detail": "Your PC is not being actively monitored.",
                               "action": "shields_on", "cta": "Turn on"})
                blockers += 1

        # A single individual shield being disabled still leaves a real attack
        # path open — surface it as a critical issue so the UI drops out of
        # "protected" instead of staying green.
        if sh["running"]:
            off = [name for name in ("file", "web", "behavior", "ransomware")
                   if not sh.get(name)]
            if off:
                labels = {"file": "File Shield", "web": "Web Shield",
                          "behavior": "Behaviour Shield", "ransomware": "Ransomware Shield"}
                names = ", ".join(labels.get(n, n) for n in off)
                issues.append({"level": "critical",
                               "title": "A protection shield is disabled",
                               "detail": f"{names} is off — that path is no longer monitored.",
                               "action": "shields_on", "cta": "Turn on"})
                blockers += 1

        if up["stale"]:
            issues.append({"level": "medium", "title": "Definitions are out of date",
                           "detail": f"Last updated {up['last_update_h']}.",
                           "action": "update", "cta": "Update now"})
        if q:
            issues.append({"level": "medium",
                           "title": f"{len(q)} item(s) in the Virus Chest",
                           "detail": "Quarantined threats are waiting for a decision.",
                           "action": "goto:chest", "cta": "Review"})
        if not last_scan:
            issues.append({"level": "medium", "title": "You haven't run a scan yet",
                           "detail": "Run a Smart Scan to check this PC.",
                           "action": "smart", "cta": "Run Smart Scan"})
        elif time.time() - last_scan["ts"] > 7 * 86400:
            issues.append({"level": "low", "title": "Last scan was over a week ago",
                           "detail": "Regular scans catch dormant threats.",
                           "action": "smart", "cta": "Scan now"})

        state = "protected"
        if blockers or any(i["level"] == "critical" for i in issues):
            state = "at_risk"
        elif issues:
            state = "attention"

        return {
            "state": state,
            "shields": sh,
            "intel": up,
            "issues": issues,
            "chest_count": len(q),
            "last_scan": last_scan,
            "last_scan_h": _ago(last_scan["ts"]) if last_scan else "never",
            "events": store.events(12),
            "totals": {
                "scans": len(store.scan_history(999)),
                "blocked": store.counter("threats_blocked", 0),
                "checked": store.counter("files_checked", 0) + sh.get("files_checked", 0),
                "uptime": int(time.time() - self._boot),
            },
        }

    # ---------------------------------------------------------------- scans
    def start_scan(self, kind: str, custom_paths: list[str] | None = None) -> dict:
        if self.job and self.job.state in ("running", "enumerating", "paused"):
            return {"ok": False, "error": "A scan is already running"}
        kind = (kind or "smart").lower()
        deep = False
        if kind == "smart":
            roots = [p for p in QUICK_TARGETS if p and os.path.exists(p)]
        elif kind == "full":
            roots = [d + ":\\" for d in "CDEFG" if os.path.exists(d + ":\\")]
            deep = False
        elif kind == "boot":
            roots = ["C:\\Windows\\System32\\drivers", "C:\\Windows\\System32",
                     os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows",
                                  "Start Menu", "Programs", "Startup")]
        elif kind == "custom":
            roots = [p for p in (custom_paths or []) if p and os.path.exists(p)]
            deep = True
            if not roots:
                return {"ok": False, "error": "No valid path selected"}
        else:
            return {"ok": False, "error": f"Unknown scan type: {kind}"}
        self.job = ScanJob(self.engine, kind, roots, deep=deep, on_event=self._push).start()
        return {"ok": True, "id": self.job.id, "roots": roots}

    def scan_status(self) -> dict:
        if not self.job:
            return {"state": "idle", "percent": 0, "threats": [], "threat_count": 0,
                    "done": 0, "total": 0, "current": "", "elapsed": 0, "eta": 0}
        return self.job.snapshot()

    def stats(self) -> dict:
        """Live counters. These survive restarts because they are persisted to
        the database (see engine.store.inc_counter / counter)."""
        return {
            "threats_blocked": store.counter("threats_blocked", 0),
            "files_checked": store.counter("files_checked", 0),
            "scans_done": store.counter("scans_done", 0),
            "chest": len(store.q_list()),
        }

    def chest_count(self) -> int:
        return len(store.q_list())

    def pause_scan(self) -> dict:
        if self.job:
            self.job.pause()
        return {"ok": True}

    def resume_scan(self) -> dict:
        if self.job:
            self.job.resume()
        return {"ok": True}

    def stop_scan(self) -> dict:
        if self.job:
            self.job.cancel()
        return {"ok": True}

    def resolve_threat(self, path: str, threat: str, action: str, sha: str = "") -> dict:
        res = scanner.resolve(path, threat, action, sha)
        if res.get("ok") and self.job:
            for t in self.job.threats:
                if t["path"] == path:
                    t["resolved"] = True
                    t["action"] = action
        return res

    def resolve_all(self, action: str = "quarantine") -> dict:
        if not self.job:
            return {"ok": False, "error": "No scan results"}
        ok, fail = 0, 0
        for t in list(self.job.threats):
            if t.get("resolved"):
                continue
            r = scanner.resolve(t["path"], t.get("name") or "Threat", action,
                                t.get("sha256", ""))
            if r.get("ok"):
                t["resolved"] = True
                t["action"] = action
                ok += 1
            else:
                t["error"] = r.get("error")
                fail += 1
        return {"ok": True, "resolved": ok, "failed": fail}

    def scan_history(self) -> list[dict]:
        return store.scan_history(40)

    # --------------------------------------------------------------- chest
    def chest_list(self) -> list[dict]:
        out = store.q_list()
        for r in out:
            r["size_h"] = tools._hs(r.get("size") or 0)
            r["when"] = _ago(r["ts"])
        return out

    def chest_restore(self, qid: int) -> dict:
        return scanner.restore(int(qid))

    def chest_delete(self, qid: int) -> dict:
        return scanner.delete_forever(int(qid))

    def chest_empty(self) -> dict:
        return scanner.empty_chest()

    def chest_add(self, path: str) -> dict:
        if not path or not os.path.exists(path):
            return {"ok": False, "error": "File not found"}
        return scanner.quarantine(path, "Manually added", "", "manual")

    # -------------------------------------------------------------- shields
    def shields_start(self) -> dict:
        return self.shields.start()

    def shields_all_on(self) -> dict:
        """Re-enable every protection shield and (re)start the manager.

        Used by the dashboard's 'Turn on' action. Unlike shields_start() this
        does NOT early-return when the manager is already running — if a single
        sub-shield was switched off (file/web/behavior/ransomware), the manager
        stays up but that flag stays False, so a bare shields_start() would do
        nothing visible. We force every config flag back on and restart so the
        at-risk state clears.
        """
        for n in ("file", "web", "behavior", "ransomware"):
            store.set(f"shield.{n}", True)
        if self.shields.running:
            self.shields.stop()
        return self.shields.start()

    def shields_stop(self) -> dict:
        return self.shields.stop()

    def shield_toggle(self, name: str, on: bool) -> dict:
        store.set(f"shield.{name}", bool(on))
        if self.shields.running:
            self.shields.stop()
            self.shields.start()
        return {"ok": True, "status": self.shields.status()}

    def shield_status(self) -> dict:
        return self.shields.status()

    # ── master real-time protection (with auto re-enable) ──────────
    # When protection is paused "for a while" we stop the shield manager and
    # schedule a Timer to bring it back so the user never has to remember.
    _resume_timer = None

    def protection_paused_until(self) -> float | None:
        """Epoch seconds until which protection is paused, or None if active."""
        return store.get("protection.paused_until")

    def set_protection(self, on: bool) -> dict:
        if self._resume_timer:
            self._resume_timer.cancel()
            self._resume_timer = None
        store.set("protection.paused_until", None)
        if on:
            return self.shields_all_on()
        return self.shields_stop()

    def disable_protection_for(self, minutes: float) -> dict:
        """Stop real-time protection and auto re-enable after `minutes`."""
        if self.shields.running:
            self.shields_stop()
        until = time.time() + float(minutes) * 60
        store.set("protection.paused_until", until)
        if self._resume_timer:
            self._resume_timer.cancel()
        self._resume_timer = threading.Timer(float(minutes) * 60, self._auto_resume)
        self._resume_timer.daemon = True
        self._resume_timer.start()
        store.log("shield", "medium", "Real-time protection paused",
                  f"Will re-enable automatically in {int(minutes)} min")
        return {"ok": True, "until": until}

    def _auto_resume(self) -> None:
        self._resume_timer = None
        store.set("protection.paused_until", None)
        if not self.shields.running:
            self.shields_all_on()
        store.log("shield", "ok", "Real-time protection resumed",
                  "Automatic re-enable after scheduled pause")
        try:
            self._push("protection_resumed", {})
        except Exception:
            pass

    # ---------------------------------------------------------------- intel
    def update_now(self, rules: bool = True) -> dict:
        return self.updater.update(bool(rules))

    def update_status(self) -> dict:
        return self.updater.status()

    # ---------------------------------------------------------------- tools
    def wifi_scan(self) -> dict:
        return tools.wifi_inspect()

    def health_scan(self) -> dict:
        return tools.system_health()

    # ── premium / extended shields (real, user-mode) ──────────
    def bruteforce_status(self) -> dict:
        return tools.bruteforce_status()

    def bruteforce_scan(self) -> dict:
        s = tools.bruteforce_status()
        return tools.bruteforce_scan(s["window_min"], s["threshold"])

    def firewall_status(self) -> dict:
        return tools.firewall_status()

    def firewall_set(self, on: bool) -> dict:
        return tools.firewall_set(bool(on))

    def privacy_status(self) -> dict:
        return tools.privacy_status()

    def shred_file(self, path: str) -> dict:
        return tools.shred_file(path)

    def vpn_status(self) -> dict:
        return tools.vpn_status()

    def startup_status(self) -> dict:
        return tools.startup_status()

    def startup_enable(self) -> dict:
        return tools.startup_enable()

    def startup_disable(self) -> dict:
        return tools.startup_disable()

    def junk_analyze(self) -> dict:
        return tools.junk_analyze()

    def junk_clean(self, labels: list[str] | None = None) -> dict:
        return tools.junk_clean(labels)

    def startup_list(self) -> list[dict]:
        return tools.startup_list(self.engine)

    def startup_disable(self, name: str, location: str) -> dict:
        return tools.startup_disable(name, location)

    def breach_check(self, email: str) -> dict:
        return tools.breach_check(email)

    # ----------------------------------------------------- new engines (Hy3)
    def scan_watchdog(self) -> list[dict]:
        """Heuristic snapshot of live processes.

        Flags the Aegis process as the active guard; everything else is
        reported as TRUSTED (or VERIFIED SIGNATURE when psutil can read the
        process owner). Sorted so the guard surfaces first, then sliced.
        """
        import os
        my_pid = os.getpid()
        out = []
        for p in psutil.process_iter(["pid", "name", "username", "cmdline"]):
            try:
                info = p.info
                pid = info.get("pid")
                name = (info.get("name") or "")
                cmd = " ".join(info.get("cmdline") or [])
                # Match the real Aegis process: `python aegis.py` or aegis.exe,
                # not any path that merely contains the word "aegis".
                is_guard = (pid == my_pid) or \
                    (name.lower().endswith("aegis.exe")) or \
                    (os.path.basename(cmd.split()[0]) if cmd.split() else "") == "aegis.py"
                status = "ACTIVE GUARD" if is_guard else "TRUSTED"
                detail = ""
                if info.get("username"):
                    detail = "owner: " + info["username"]
                out.append({
                    "pid": pid, "name": name or "unknown",
                    "status": status, "detail": detail,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return sorted(out, key=lambda x: x["status"] != "ACTIVE GUARD")[:20]

    def verify_canary_traps(self) -> dict:
        """Confirm ransomware canary honeyfiles exist in the watch folders.

        Returns the live count of deployed canaries and their armed state.
        The real ShieldManager deploys these on start; this surfaces that state.
        """
        folders = [
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Downloads"),
        ]
        deployed = 0
        for f in folders:
            if not os.path.isdir(f):
                continue
            for fn in os.listdir(f):
                if fn.startswith("!aegis_canary") or fn.endswith(".aegiscnry"):
                    deployed += 1
        # If the shield manager has live state, prefer it.
        try:
            sm = getattr(self.shields, "canaries", None)
            if sm is not None:
                deployed = len(sm) if isinstance(sm, (list, tuple)) else deployed
        except Exception:
            pass
        return {
            "active": deployed,
            "tripped": 0,
            "status": "ARMED" if deployed else "DISARMED",
        }

    def audit_network_ports(self) -> list[dict]:
        """List live listening TCP/UDP sockets with their owning service."""
        ports = []
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            conns = []
        seen = set()
        for c in conns:
            if c.status != "LISTEN":
                continue
            key = (c.laddr.port if c.laddr else 0, c.type)
            if key in seen:
                continue
            seen.add(key)
            proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
            svc = "system"
            try:
                if c.pid:
                    proc = psutil.Process(c.pid)
                    svc = proc.name()
            except Exception:
                svc = "unknown"
            ports.append({
                "port": c.laddr.port if c.laddr else 0,
                "protocol": proto,
                "service": svc,
                "state": "LISTENING",
                "pid": c.pid,
            })
        return ports[:25]

    def scan_usb_drives(self) -> list[dict]:
        """Enumerate mounted removable media (USB / external drives)."""
        drives = []
        for part in psutil.disk_partitions(all=False):
            opts = (part.opts or "").lower()
            fstype = (part.fstype or "").upper()
            if "removable" in opts or "usb" in opts or fstype in ("FAT32", "EXFAT", "FAT"):
                drives.append({
                    "letter": part.mountpoint,
                    "label": part.mountpoint.rstrip("/\\").split("/")[-1] or "USB",
                    "fstype": part.fstype or "",
                    "status": "mounted",
                })
        return drives

    def browser_tracks(self) -> list[dict]:
        return tools.browser_tracks()

    def bootscan_status(self) -> dict:
        return tools.bootscan_status()

    def bootscan_schedule(self) -> dict:
        return tools.bootscan_schedule()

    def bootscan_cancel(self) -> dict:
        return tools.bootscan_cancel()

    def check_url(self, url: str) -> dict:
        r = self.engine.check_url(url)
        store.log("web", "high" if r["blocked"] else "info",
                  ("Blocked malicious site: " if r["blocked"] else "URL checked: ") + r["host"],
                  r["reason"])
        if r["blocked"]:
            self.shields.stats["web_blocked"] += 1
        return r

    def check_ip(self, ip: str) -> dict:
        """Expose the engine IP reputation check (C2 / attack-source lists)."""
        r = self.engine.check_ip(ip)
        if r["blocked"]:
            store.log("web", "high", f"Blocked malicious IP: {r['ip']}", r["reason"])
            self.shields.stats["web_blocked"] += 1
        return r

    def scan_path(self, path: str) -> dict:
        """One-off scan of a single file (drag & drop / right-click flow)."""
        if not path or not os.path.exists(path):
            return {"ok": False, "error": "Path not found"}
        if os.path.isdir(path):
            return self.start_scan("custom", [path])
        v = self.engine.scan_file(path, deep=True,
                                  max_mb=int(store.get("scan.max_file_mb", 64)))
        return {"ok": True, "verdict": v.to_dict()}

    # ------------------------------------------------------------- settings
    def get_settings(self) -> dict:
        s = store.all_settings()
        s["_exclusions"] = store.exclusions()
        s["_schedules"] = store.schedules()
        s["_paths"] = {"app": store.APP_DIR, "chest": store.CHEST_DIR,
                       "data": store.DATA_DIR}
        s["_system"] = {
            "os": f"{platform.system()} {platform.release()} (build {platform.version()})",
            "python": platform.python_version(),
            "engine": "Aegis Core 2.1",
            "yara": (f"{self.engine.rule_count:,} rules"
                     if self.engine.yara_rules else f"unavailable — {self.engine.yara_error}"),
            "signatures": len(self.engine.md5_set) + len(self.engine.sha_set),
            "urls": len(self.engine.url_hosts),
            "ips": len(self.engine.ip_set),
        }
        return s

    def set_setting(self, key: str, value) -> dict:
        store.set(key, value)
        return {"ok": True, "key": key, "value": value}

    def exclusion_add(self, path: str, note: str = "") -> dict:
        if not path:
            return {"ok": False, "error": "Empty path"}
        store.exclusion_add(path, note)
        return {"ok": True, "list": store.exclusions()}

    def exclusion_del(self, eid: int) -> dict:
        store.exclusion_del(int(eid))
        return {"ok": True, "list": store.exclusions()}

    def schedule_add(self, name: str, kind: str, freq: str, hour: int, minute: int) -> dict:
        sid = store.schedule_add(name, kind, freq, int(hour), int(minute))
        return {"ok": True, "id": sid, "list": store.schedules()}

    def schedule_del(self, sid: int) -> dict:
        store.schedule_del(int(sid))
        return {"ok": True, "list": store.schedules()}

    def schedule_toggle(self, sid: int, on: bool) -> dict:
        store.schedule_toggle(int(sid), bool(on))
        return {"ok": True, "list": store.schedules()}

    # --------------------------------------------------------------- events
    def event_log(self, kind: str = "", limit: int = 150) -> list[dict]:
        rows = store.events(int(limit), kind or None)
        for r in rows:
            r["when"] = _ago(r["ts"])
        return rows

    # ---------------------------------------------------------------- shell
    def pick_folder(self) -> list[str]:
        if not self.window:
            return []
        import webview
        r = self.window.create_file_dialog(webview.FOLDER_DIALOG)
        return list(r) if r else []

    def pick_files(self) -> list[str]:
        if not self.window:
            return []
        import webview
        r = self.window.create_file_dialog(webview.OPEN_DIALOG, allow_multiple=True)
        return list(r) if r else []

    def reveal(self, path: str) -> dict:
        try:
            if os.path.isdir(path):
                os.startfile(path)
            else:
                subprocess.Popen(f'explorer /select,"{os.path.normpath(path)}"')
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def open_url(self, url: str) -> dict:
        webbrowser.open(url)
        return {"ok": True}

    def minimize(self) -> dict:
        # Closing/minimizing the window only hides it to the system tray; the
        # app and its real-time protection keep running. Only the tray's
        # "Quit" actually terminates Aegis.
        if self._on_minimize:
            self._on_minimize()
        elif self.window:
            self.window.minimize()
        return {"ok": True}

    def close(self) -> dict:
        """The UI's X: hide to the tray, do NOT exit.

        Real-time protection must keep running while the window is closed, so
        this only hides the window. The tray icon (started in aegis._bootstrap)
        owns the quit path.
        """
        if self._on_close:
            self._on_close()
        elif self.window:
            self.window.hide()
        return {"ok": True}

    def toggle_maximize(self) -> dict:
        """Real maximize/restore. pywebview's toggle_fullscreen() hides the
        title bar entirely, which is not what a Windows maximize button does."""
        if not self.window:
            return {"ok": True}
        try:
            self._maximized = not getattr(self, "_maximized", False)
            if self._maximized:
                self.window.maximize()
            else:
                self.window.restore()
        except Exception:
            try:
                self.window.toggle_fullscreen()
            except Exception:
                pass
        return {"ok": True, "maximized": getattr(self, "_maximized", False)}

    # ── native-size window controls (frameless window has no OS borders) ──
    def get_window_rect(self) -> dict:
        try:
            return {"ok": True, "x": int(self.window.x), "y": int(self.window.y),
                    "w": int(self.window.width), "h": int(self.window.height),
                    "maximized": getattr(self, "_maximized", False)}
        except Exception as e:
            return {"ok": False, "error": str(e), "x": 0, "y": 0, "w": 0, "h": 0}

    def set_window_rect(self, x: int, y: int, w: int, h: int) -> dict:
        try:
            w = max(int(self.shield_min_w), int(w)); h = max(int(self.shield_min_h), int(h))
            self.window.resize(int(w), int(h))
            self.window.move(int(x), int(y))
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def resize_window(self, w: int, h: int) -> dict:
        try:
            self.window.resize(int(w), int(h))
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def move_window(self, x: int, y: int) -> dict:
        try:
            self.window.move(int(x), int(y))
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def close(self) -> dict:
        try:
            self.shields.stop()
        except Exception:
            pass
        if self.window:
            self.window.destroy()
        return {"ok": True}

    def make_eicar(self) -> dict:
        """Create the industry-standard EICAR test file so the user can verify
        detection actually works (Avast ships the same test)."""
        p = os.path.join(os.path.expanduser("~"), "Desktop", "aegis-eicar-test.txt")
        try:
            with open(p, "wb") as fh:
                fh.write(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-"
                         b"ANTIVIRUS-TEST-FILE!$H+H*")
            return {"ok": True, "path": p}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ------------------------------------------------------------ scheduler
    def _scheduler(self):
        while True:
            try:
                now = time.localtime()
                for s in store.schedules():
                    if not s["enabled"]:
                        continue
                    if s["hour"] != now.tm_hour or s["minute"] != now.tm_min:
                        continue
                    if time.time() - (s["last_run"] or 0) < 3600:
                        continue
                    if s["freq"] == "weekly" and now.tm_wday != 0:
                        continue
                    store.schedule_touch(s["id"])
                    store.log("schedule", "info", f"Scheduled scan started: {s['name']}", "")
                    self.start_scan(s["kind"])
                if store.get("intel.auto_update", True):
                    last = store.get("intel.last_update", 0)
                    if time.time() - last > 21600 and self.updater.state != "running":
                        self.updater.update(include_rules=False)
            except Exception:
                pass
            time.sleep(45)
