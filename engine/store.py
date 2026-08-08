"""Aegis Security — persistence layer (settings, events, quarantine, history)."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any

APP_NAME = "Aegis Security"
APP_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "Aegis")
DATA_DIR = os.path.join(APP_DIR, "data")
CHEST_DIR = os.path.join(APP_DIR, "chest")
LOG_DIR = os.path.join(APP_DIR, "logs")
DB_PATH = os.path.join(APP_DIR, "aegis.db")

for _d in (APP_DIR, DATA_DIR, CHEST_DIR, LOG_DIR):
    os.makedirs(_d, exist_ok=True)

_LOCK = threading.RLock()
_CONN: sqlite3.Connection | None = None


def _get_conn() -> sqlite3.Connection:
    global _CONN
    if _CONN is not None:
        return _CONN
    _CONN = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    _CONN.row_factory = sqlite3.Row
    try:
        _CONN.execute("PRAGMA journal_mode=WAL")
        _CONN.execute("PRAGMA synchronous=NORMAL")
        _CONN.execute("PRAGMA busy_timeout=30000")
    except Exception:
        pass
    return _CONN


def _conn() -> sqlite3.Connection:
    """Back-compat shim — returns the cached connection."""
    return _get_conn()

DEFAULTS: dict[str, Any] = {
    "shield.file": True,
    "shield.web": True,
    "shield.behavior": True,
    "shield.ransomware": True,
    "shield.email": False,
    "scan.pup": True,
    "scan.archives": True,
    "scan.heuristics": "balanced",     # relaxed | balanced | aggressive
    "scan.max_file_mb": 64,
    "scan.threads": max(2, (os.cpu_count() or 4) - 1),
    "action.default": "quarantine",    # quarantine | report
    "ui.dnd": False,
    "ui.notifications": True,
    "intel.auto_update": True,
    "intel.last_update": 0,
    "ransom.folders": [
        os.path.join(os.path.expanduser("~"), "Documents"),
        os.path.join(os.path.expanduser("~"), "Pictures"),
        os.path.join(os.path.expanduser("~"), "Desktop"),
    ],
    "onboard.done": False,
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL, kind TEXT NOT NULL, severity TEXT NOT NULL,
    title TEXT NOT NULL, detail TEXT, path TEXT
);
CREATE TABLE IF NOT EXISTS quarantine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL, orig_path TEXT NOT NULL, stored TEXT NOT NULL,
    threat TEXT NOT NULL, sha256 TEXT, size INTEGER, engine TEXT, restored INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL, kind TEXT NOT NULL, duration REAL,
    files INTEGER, threats INTEGER, resolved INTEGER, summary TEXT
);
CREATE TABLE IF NOT EXISTS exclusions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT UNIQUE NOT NULL, note TEXT, ts REAL
);
CREATE TABLE IF NOT EXISTS counters (
    key TEXT PRIMARY KEY, value INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, kind TEXT, freq TEXT,
    hour INTEGER, minute INTEGER, enabled INTEGER DEFAULT 1, last_run REAL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
"""


with _LOCK:
    _c = _get_conn()
    _c.executescript(SCHEMA)
    _c.commit()


# ---------------------------------------------------------------- settings
def get(key: str, default: Any = None) -> Any:
    with _LOCK:
        c = _get_conn()
        row = c.execute("SELECT v FROM settings WHERE k=?", (key,)).fetchone()
    if row is None:
        return DEFAULTS.get(key, default)
    try:
        return json.loads(row["v"])
    except Exception:
        return default


def set(key: str, value: Any) -> Any:  # noqa: A001
    with _LOCK:
        c = _get_conn()
        c.execute(
            "INSERT INTO settings(k,v) VALUES(?,?) "
            "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (key, json.dumps(value)),
        )
        c.commit()
    return value


def all_settings() -> dict:
    out = dict(DEFAULTS)
    with _LOCK:
        c = _get_conn()
        for r in c.execute("SELECT k,v FROM settings"):
            try:
                out[r["k"]] = json.loads(r["v"])
            except Exception:
                pass
    return out


# ------------------------------------------------------------------ events
def log(kind: str, severity: str, title: str, detail: str = "", path: str = "") -> None:
    with _LOCK:
        c = _get_conn()
        c.execute(
            "INSERT INTO events(ts,kind,severity,title,detail,path) VALUES(?,?,?,?,?,?)",
            (time.time(), kind, severity, title, detail, path),
        )
        c.commit()


def events(limit: int = 120, kind: str | None = None) -> list[dict]:
    q = "SELECT * FROM events"
    a: tuple = ()
    if kind:
        q += " WHERE kind=?"
        a = (kind,)
    q += " ORDER BY ts DESC LIMIT ?"
    a = a + (limit,)
    with _LOCK:
        c = _get_conn()
        return [dict(r) for r in c.execute(q, a)]


# ---------------------------------------------------------- persisted counters
def inc_counter(key: str, by: int = 1) -> int:
    with _LOCK:
        c = _get_conn()
        c.execute("INSERT INTO counters(key, value) VALUES(?, ?) "
                  "ON CONFLICT(key) DO UPDATE SET value = value + ?",
                  (key, by, by))
        c.commit()
        row = c.execute("SELECT value FROM counters WHERE key=?", (key,)).fetchone()
        return row[0]


def set_counter(key: str, value: int) -> int:
    with _LOCK:
        c = _get_conn()
        c.execute("INSERT INTO counters(key, value) VALUES(?, ?) "
                  "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                  (key, value))
        c.commit()
    return value


def counter(key: str, default: int = 0) -> int:
    with _LOCK:
        c = _get_conn()
        row = c.execute("SELECT value FROM counters WHERE key=?", (key,)).fetchone()
        return row[0] if row else default


# -------------------------------------------------------------- quarantine
def q_add(orig: str, stored: str, threat: str, sha: str, size: int, eng: str) -> int:
    with _LOCK:
        c = _get_conn()
        cur = c.execute(
            "INSERT INTO quarantine(ts,orig_path,stored,threat,sha256,size,engine) "
            "VALUES(?,?,?,?,?,?,?)",
            (time.time(), orig, stored, threat, sha, size, eng),
        )
        c.commit()
        return cur.lastrowid


def q_list(include_restored: bool = False) -> list[dict]:
    q = "SELECT * FROM quarantine"
    if not include_restored:
        q += " WHERE restored=0"
    q += " ORDER BY ts DESC"
    with _LOCK:
        c = _get_conn()
        return [dict(r) for r in c.execute(q)]


def q_get(qid: int) -> dict | None:
    with _LOCK:
        c = _get_conn()
        r = c.execute("SELECT * FROM quarantine WHERE id=?", (qid,)).fetchone()
        return dict(r) if r else None


def q_mark(qid: int, restored: int = 1) -> None:
    with _LOCK:
        c = _get_conn()
        c.execute("UPDATE quarantine SET restored=? WHERE id=?", (restored, qid))
        c.commit()


def q_delete(qid: int) -> None:
    with _LOCK:
        c = _get_conn()
        c.execute("DELETE FROM quarantine WHERE id=?", (qid,))
        c.commit()


# ------------------------------------------------------------------- scans
def scan_add(kind: str, duration: float, files: int, threats: int,
             resolved: int, summary: str) -> None:
    with _LOCK:
        c = _get_conn()
        c.execute(
            "INSERT INTO scans(ts,kind,duration,files,threats,resolved,summary) "
            "VALUES(?,?,?,?,?,?,?)",
            (time.time(), kind, duration, files, threats, resolved, summary),
        )
        c.commit()


def scan_history(limit: int = 40) -> list[dict]:
    with _LOCK:
        c = _get_conn()
        return [dict(r) for r in c.execute(
            "SELECT * FROM scans ORDER BY ts DESC LIMIT ?", (limit,))]


# -------------------------------------------------------------- exclusions
def exclusions() -> list[dict]:
    with _LOCK:
        c = _get_conn()
        return [dict(r) for r in c.execute("SELECT * FROM exclusions ORDER BY id DESC")]


def exclusion_add(path: str, note: str = "") -> None:
    with _LOCK:
        c = _get_conn()
        c.execute("INSERT OR IGNORE INTO exclusions(path,note,ts) VALUES(?,?,?)",
                  (os.path.normpath(path), note, time.time()))
        c.commit()


def exclusion_del(eid: int) -> None:
    with _LOCK:
        c = _get_conn()
        c.execute("DELETE FROM exclusions WHERE id=?", (eid,))
        c.commit()


def is_excluded(path: str) -> bool:
    p = os.path.normcase(os.path.normpath(path))
    for e in exclusions():
        if p.startswith(os.path.normcase(e["path"])):
            return True
    return False


# --------------------------------------------------------------- schedules
def schedules() -> list[dict]:
    with _LOCK:
        c = _get_conn()
        return [dict(r) for r in c.execute("SELECT * FROM schedules ORDER BY id")]


def schedule_add(name: str, kind: str, freq: str, hour: int, minute: int) -> int:
    with _LOCK:
        c = _get_conn()
        cur = c.execute(
            "INSERT INTO schedules(name,kind,freq,hour,minute) VALUES(?,?,?,?,?)",
            (name, kind, freq, hour, minute))
        c.commit()
        return cur.lastrowid


def schedule_del(sid: int) -> None:
    with _LOCK:
        c = _get_conn()
        c.execute("DELETE FROM schedules WHERE id=?", (sid,))
        c.commit()


def schedule_touch(sid: int) -> None:
    with _LOCK:
        c = _get_conn()
        c.execute("UPDATE schedules SET last_run=? WHERE id=?", (time.time(), sid))
        c.commit()


def schedule_toggle(sid: int, enabled: bool) -> None:
    with _LOCK:
        c = _get_conn()
        c.execute("UPDATE schedules SET enabled=? WHERE id=?", (1 if enabled else 0, sid))
        c.commit()
