"""Aegis Security — system tools: Wi-Fi Inspector, Boot-Time check, Junk Cleaner,
Startup Manager, Breach Monitor, Browser Cleanup, System Health."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
import winreg

from . import store

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AegisSecurity/2.1"
CREATE_NO_WINDOW = 0x08000000


def _run(cmd: str, timeout: int = 25) -> str:
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout, creationflags=CREATE_NO_WINDOW,
                           errors="ignore")
        return (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return f"__ERR__{e}"


# ====================================================== Wi-Fi Inspector
def wifi_inspect() -> dict:
    """Audit the local network: encryption, router exposure, connected devices."""
    findings: list[dict] = []
    info: dict = {"ssid": "", "auth": "", "cipher": "", "signal": "",
                  "gateway": "", "local_ip": "", "dns": [], "devices": []}

    out = _run("netsh wlan show interfaces")
    for key, field in (("SSID", "ssid"), ("Authentication", "auth"),
                       ("Cipher", "cipher"), ("Signal", "signal")):
        m = re.search(rf"^\s*{key}\s*:\s*(.+)$", out, re.M)
        if m and not info.get(field):
            info[field] = m.group(1).strip()
    if info["ssid"].lower().startswith("bssid"):
        info["ssid"] = ""

    ipc = _run("ipconfig /all")
    m = re.search(r"Default Gateway[ .]*:\s*([\d.]+)", ipc)
    info["gateway"] = m.group(1) if m else ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info["local_ip"] = s.getsockname()[0]
        s.close()
    except Exception:
        pass
    info["dns"] = re.findall(r"DNS Servers[ .]*:\s*([\d.]+)", ipc)[:3]

    # --- encryption assessment
    auth = info["auth"].lower()
    if not info["ssid"]:
        findings.append(_f("info", "No Wi-Fi connection detected",
                           "You appear to be on a wired connection — wireless risks don't apply."))
    elif "open" in auth or auth in ("", "none"):
        findings.append(_f("critical", "Network is unencrypted",
                           "Anyone nearby can read your traffic. Avoid banking or logins here."))
    elif "wep" in auth:
        findings.append(_f("critical", "WEP encryption is broken",
                           "WEP can be cracked in minutes. Change your router to WPA2/WPA3."))
    elif "wpa2-personal" in auth or "wpa2" in auth:
        findings.append(_f("low", "WPA2 encryption in use",
                           "Acceptable, but WPA3 is stronger if your router supports it."))
    elif "wpa3" in auth:
        findings.append(_f("ok", "WPA3 encryption in use",
                           "Your wireless traffic uses the strongest available standard."))
    else:
        findings.append(_f("low", f"Encryption: {info['auth']}",
                           "Unrecognised authentication mode."))

    # --- router admin exposure
    gw = info["gateway"]
    if gw:
        open_ports = []
        for port in (80, 443, 23, 22, 8080, 21):
            try:
                s = socket.socket()
                s.settimeout(0.35)
                if s.connect_ex((gw, port)) == 0:
                    open_ports.append(port)
                s.close()
            except Exception:
                pass
        info["router_ports"] = open_ports
        if 23 in open_ports:
            findings.append(_f("critical", "Router Telnet port is open",
                               f"Port 23 on {gw} accepts connections. Telnet is unencrypted — "
                               "disable it in your router settings."))
        if 21 in open_ports:
            findings.append(_f("high", "Router FTP port is open",
                               f"Port 21 on {gw} is reachable and sends credentials in clear text."))
        if 80 in open_ports and 443 not in open_ports:
            findings.append(_f("medium", "Router admin page is HTTP-only",
                               f"http://{gw} has no TLS — admin passwords travel unencrypted "
                               "across your LAN."))
        elif open_ports:
            findings.append(_f("info", "Router management reachable",
                               f"Open ports on {gw}: "
                               + ", ".join(str(p) for p in open_ports)))

    # --- DNS hygiene
    bad_dns = [d for d in info["dns"] if d.startswith(("10.", "192.168.", "172."))
               and d != gw]
    if bad_dns:
        findings.append(_f("medium", "Unexpected local DNS server",
                           f"DNS points at {', '.join(bad_dns)} rather than your gateway — "
                           "this can indicate DNS hijacking."))

    # --- ARP device sweep
    arp = _run("arp -a")
    devs = []
    for line in arp.splitlines():
        m = re.match(r"\s*([\d.]+)\s+([0-9a-f-]{17})\s+(\w+)", line, re.I)
        if m and not m.group(1).startswith(("224.", "239.", "255.")):
            ip, mac, kind = m.group(1), m.group(2), m.group(3)
            devs.append({"ip": ip, "mac": mac.upper(), "type": kind,
                         "vendor": _oui(mac),
                         "is_gateway": ip == gw,
                         "is_self": ip == info["local_ip"]})
    info["devices"] = devs[:60]
    findings.append(_f("info", f"{len(devs)} devices on this network",
                       "Review the list below — unknown devices may be unauthorised."))

    # --- firewall
    fw = _run("netsh advfirewall show allprofiles state")
    if re.search(r"State\s+OFF", fw, re.I):
        findings.append(_f("high", "Windows Firewall is disabled on a profile",
                           "At least one network profile has the firewall turned off."))

    # --- SMBv1
    smb = _run('powershell -NoProfile -Command "'
               '(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'
               ' -ErrorAction SilentlyContinue).State"', timeout=40)
    if "Enabled" in smb:
        findings.append(_f("high", "SMBv1 is enabled",
                           "The protocol exploited by WannaCry is still active. Disable it."))

    score = _score(findings)
    store.log("wifi", "info", "Wi-Fi Inspector scan complete",
              f"{len(findings)} findings · score {score}")
    return {"info": info, "findings": findings, "score": score,
            "issues": len([f for f in findings
                           if f["level"] in ("critical", "high", "medium")])}


_OUI = {
    # Apple
    "AC:DE:48": "Apple", "F0:18:98": "Apple", "3C:22:FB": "Apple", "A4:83:E7": "Apple",
    "04:F4:D8": "Apple", "78:80:38": "Apple", "F8:E9:4E": "Apple", "90:B0:ED": "Apple",
    "BC:D0:74": "Apple", "D0:81:7A": "Apple", "E0:B5:5F": "Apple", "8C:85:90": "Apple",
    "6C:19:C0": "Apple", "A8:66:7F": "Apple", "DC:2B:2A": "Apple", "F0:99:BF": "Apple",
    # Google / Nest
    "00:1A:11": "Google", "3C:5A:B4": "Google", "F4:F5:D8": "Google", "F4:F5:E8": "Google",
    "94:EB:2C": "Google", "18:B4:30": "Nest (Google)", "64:16:66": "Nest (Google)",
    "D8:6C:63": "Google", "6C:AD:F8": "Google Chromecast",
    # Amazon
    "44:65:0D": "Amazon", "FC:65:DE": "Amazon", "68:37:E9": "Amazon", "F0:27:2D": "Amazon",
    "50:DC:E7": "Amazon", "A0:02:DC": "Amazon", "74:C2:46": "Amazon",
    # Samsung
    "78:1F:DB": "Samsung", "5C:F6:DC": "Samsung", "8C:71:F8": "Samsung",
    "B0:5C:DA": "Samsung", "E8:50:8B": "Samsung", "C0:BD:D1": "Samsung",
    # Microsoft
    "00:1D:D8": "Microsoft", "7C:1E:52": "Microsoft", "50:1A:C5": "Microsoft",
    "28:18:78": "Microsoft", "C0:33:5E": "Microsoft",
    # Intel / Lenovo / Dell / HP
    "3C:62:F0": "Intel", "94:E6:F7": "Intel", "A0:C5:89": "Intel", "8C:16:45": "Intel",
    "E4:A7:A0": "Intel", "48:2A:E3": "Lenovo", "54:E1:AD": "Lenovo",
    "F8:B1:56": "Dell", "18:DB:F2": "Dell", "B0:83:FE": "Dell",
    "3C:D9:2B": "HP", "80:CE:62": "HP", "94:57:A5": "HP",
    # Routers / networking
    "B0:4E:26": "TP-Link", "50:C7:BF": "TP-Link", "A4:2B:B0": "TP-Link",
    "00:1F:3F": "Netgear", "A0:63:91": "Netgear", "2C:30:33": "Netgear",
    "C0:56:27": "Belkin", "F8:D0:0E": "Arris / CommScope", "9C:34:26": "Arris",
    "00:25:9C": "Cisco-Linksys", "C4:41:1E": "Belkin", "D8:47:32": "TP-Link",
    "84:1B:5E": "Netgear", "2C:B0:5D": "Netgear", "44:94:FC": "Netgear",
    "70:3A:CB": "Google Fiber", "E8:9F:80": "Belkin", "10:86:8C": "Arris",
    "44:E1:37": "Arris", "5C:8F:E0": "Technicolor", "40:0D:10": "Technicolor",
    # IoT / misc
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "2C:CF:67": "Raspberry Pi", "00:17:88": "Philips Hue", "EC:B5:FA": "Philips",
    "00:0C:29": "VMware", "00:50:56": "VMware", "08:00:27": "VirtualBox",
    "00:15:5D": "Hyper-V", "26:B9:13": "Locally administered (randomised)",
    "AC:63:BE": "Amazon", "24:F5:A2": "Belkin", "B8:9A:2A": "Roku",
    "D8:31:34": "Roku", "CC:6D:A0": "Roku", "00:24:E4": "Withings",
    "48:D6:D5": "Google", "1C:53:F9": "Samsung", "34:2E:B7": "LG",
}


def _oui(mac: str) -> str:
    m = mac.upper().replace("-", ":")
    p = m[:8]
    hit = _OUI.get(p)
    if hit:
        return hit
    # Locally administered addresses have bit 1 of the first octet set — these
    # are randomised privacy MACs (iOS/Android), not a real vendor.
    try:
        first = int(m[:2], 16)
        if first & 0x02:
            return "Randomised MAC (privacy)"
    except ValueError:
        pass
    return "Unknown vendor (" + p + ")"


def _f(level: str, title: str, detail: str) -> dict:
    return {"level": level, "title": title, "detail": detail}


def _score(findings: list[dict]) -> int:
    s = 100
    for f in findings:
        s -= {"critical": 30, "high": 18, "medium": 9, "low": 3}.get(f["level"], 0)
    return max(0, min(100, s))


# ====================================================== System Health
def system_health() -> dict:
    findings, info = [], {}
    try:
        import psutil
        info["cpu"] = psutil.cpu_percent(interval=0.4)
        vm = psutil.virtual_memory()
        info["ram_pct"] = vm.percent
        info["ram_used"] = round(vm.used / 1024**3, 1)
        info["ram_total"] = round(vm.total / 1024**3, 1)
        du = psutil.disk_usage("C:\\")
        info["disk_pct"] = du.percent
        info["disk_free"] = round(du.free / 1024**3, 1)
        info["disk_total"] = round(du.total / 1024**3, 1)
        info["procs"] = len(psutil.pids())
        info["uptime"] = int(time.time() - psutil.boot_time())
        if du.percent > 90:
            findings.append(_f("high", "System drive almost full",
                               f"Only {info['disk_free']} GB free. Run Junk Cleanup."))
        elif du.percent > 80:
            findings.append(_f("medium", "System drive is filling up",
                               f"{info['disk_free']} GB free of {info['disk_total']} GB."))
        if vm.percent > 88:
            findings.append(_f("medium", "Memory pressure is high",
                               f"{vm.percent}% of RAM in use."))
    except Exception as e:
        findings.append(_f("info", "Performance metrics unavailable", str(e)))

    # Defender status (are we the only AV?)
    dv = _run('powershell -NoProfile -Command "'
              '$s=Get-MpComputerStatus -ErrorAction SilentlyContinue;'
              '\'{0}|{1}|{2}\' -f $s.RealTimeProtectionEnabled,'
              '$s.AntivirusSignatureAge,$s.AMServiceEnabled"', timeout=35)
    info["defender"] = dv.strip().splitlines()[-1] if dv.strip() else "unknown"

    # pending Windows updates / restart
    try:
        winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                       r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
                       r"\RebootRequired")
        findings.append(_f("medium", "Restart required for security updates",
                           "Windows has staged updates that only apply after a reboot."))
    except OSError:
        pass

    # UAC
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                           r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
        v, _ = winreg.QueryValueEx(k, "EnableLUA")
        if v == 0:
            findings.append(_f("critical", "User Account Control is disabled",
                               "UAC is your last line of defence against silent privilege "
                               "escalation. Re-enable it."))
    except OSError:
        pass

    # BitLocker
    bl = _run("manage-bde -status C: -protectors", timeout=25)
    if "Protection Off" in bl:
        findings.append(_f("low", "Drive encryption is off",
                           "BitLocker is not protecting C:. Data is readable if the disk "
                           "is removed."))

    # Remote Desktop exposure
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                           r"SYSTEM\CurrentControlSet\Control\Terminal Server")
        v, _ = winreg.QueryValueEx(k, "fDenyTSConnections")
        if v == 0:
            findings.append(_f("medium", "Remote Desktop is enabled",
                               "RDP is a common brute-force target. Disable it if unused."))
    except OSError:
        pass

    if not findings:
        findings.append(_f("ok", "No system issues detected",
                           "Security posture and resource usage look healthy."))
    return {"info": info, "findings": findings, "score": _score(findings)}


# ====================================================== Junk Cleaner
JUNK_TARGETS = [
    ("Windows temporary files", os.environ.get("TEMP", ""), ("*",)),
    ("System temp", "C:\\Windows\\Temp", ("*",)),
    ("Windows Update cache", "C:\\Windows\\SoftwareDistribution\\Download", ("*",)),
    ("Thumbnail cache", os.path.join(os.environ.get("LOCALAPPDATA", ""),
                                     "Microsoft", "Windows", "Explorer"), ("thumbcache_*.db",)),
    ("Crash dumps", os.path.join(os.environ.get("LOCALAPPDATA", ""),
                                 "CrashDumps"), ("*",)),
    ("Chrome cache", os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome",
                                  "User Data", "Default", "Cache"), ("*",)),
    ("Edge cache", os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Edge",
                                "User Data", "Default", "Cache"), ("*",)),
    ("Firefox cache", os.path.join(os.environ.get("LOCALAPPDATA", ""), "Mozilla",
                                   "Firefox", "Profiles"), ("cache2",)),
    ("Delivery Optimization", "C:\\Windows\\ServiceProfiles\\NetworkService\\AppData"
                              "\\Local\\Microsoft\\Windows\\DeliveryOptimization", ("*",)),
    ("Error reporting queue", os.path.join(os.environ.get("PROGRAMDATA", ""),
                                           "Microsoft", "Windows", "WER"), ("*",)),
]


def junk_analyze() -> dict:
    groups, total = [], 0
    for label, root, pats in JUNK_TARGETS:
        if not root or not os.path.isdir(root):
            continue
        size, count = 0, 0
        try:
            for dp, dn, fn in os.walk(root):
                for f in fn:
                    try:
                        size += os.path.getsize(os.path.join(dp, f))
                        count += 1
                    except OSError:
                        pass
                if count > 30000:
                    break
        except Exception:
            continue
        if count:
            groups.append({"label": label, "path": root, "bytes": size,
                           "size": _hs(size), "files": count, "selected": True})
            total += size
    # Recycle Bin
    rb = 0
    try:
        import ctypes
        from ctypes import wintypes

        class SHQUERYRBINFO(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.DWORD), ("i64Size", ctypes.c_int64),
                        ("i64NumItems", ctypes.c_int64)]
        q = SHQUERYRBINFO()
        q.cbSize = ctypes.sizeof(q)
        if ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(q)) == 0 and q.i64Size:
            rb = q.i64Size
            groups.append({"label": "Recycle Bin", "path": "shell:RecycleBinFolder",
                           "bytes": rb, "size": _hs(rb),
                           "files": int(q.i64NumItems), "selected": True})
            total += rb
    except Exception:
        pass
    groups.sort(key=lambda g: -g["bytes"])
    return {"groups": groups, "total_bytes": total, "total": _hs(total)}


def junk_clean(labels: list[str] | None = None) -> dict:
    freed, removed, failed = 0, 0, 0
    sel = set(labels) if labels else None
    for label, root, pats in JUNK_TARGETS:
        if sel and label not in sel:
            continue
        if not root or not os.path.isdir(root):
            continue
        for dp, dn, fn in os.walk(root, topdown=False):
            for f in fn:
                p = os.path.join(dp, f)
                try:
                    n = os.path.getsize(p)
                    os.remove(p)
                    freed += n
                    removed += 1
                except Exception:
                    failed += 1
            for d in dn:
                try:
                    os.rmdir(os.path.join(dp, d))
                except Exception:
                    pass
    if not sel or "Recycle Bin" in sel:
        try:
            import ctypes
            ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 0x07)
        except Exception:
            pass
    store.log("cleanup", "info", "Junk cleanup complete",
              f"{_hs(freed)} reclaimed · {removed:,} files removed · {failed} locked")
    return {"ok": True, "freed": freed, "freed_h": _hs(freed),
            "removed": removed, "failed": failed}


def _hs(n: float) -> str:
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {u}" if u != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} PB"


# ====================================================== Startup Manager
RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM32"),
]


def startup_list(engine=None) -> list[dict]:
    items = []
    for hive, sub, tag in RUN_KEYS:
        try:
            k = winreg.OpenKey(hive, sub)
        except OSError:
            continue
        i = 0
        while True:
            try:
                name, val, _ = winreg.EnumValue(k, i)
            except OSError:
                break
            i += 1
            exe = _exe_of(str(val))
            items.append({
                "name": name, "command": str(val), "location": tag,
                "exists": bool(exe and os.path.exists(exe)), "path": exe,
                "impact": _impact(exe), "verdict": _startup_verdict(name, str(val), exe, engine),
            })
        winreg.CloseKey(k)

    for folder, tag in (
        (os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows",
                      "Start Menu", "Programs", "Startup"), "Startup folder"),
        (os.path.join(os.environ.get("PROGRAMDATA", ""), "Microsoft", "Windows",
                      "Start Menu", "Programs", "StartUp"), "Startup folder (all users)"),
    ):
        if os.path.isdir(folder):
            for f in os.listdir(folder):
                if f.lower() == "desktop.ini":
                    continue
                p = os.path.join(folder, f)
                items.append({"name": f, "command": p, "location": tag, "exists": True,
                              "path": p, "impact": _impact(p),
                              "verdict": _startup_verdict(f, p, p, engine)})
    return items


def _exe_of(cmd: str) -> str:
    cmd = cmd.strip()
    if cmd.startswith('"'):
        return cmd.split('"')[1]
    m = re.match(r"([A-Za-z]:\\[^\s]+\.(?:exe|bat|cmd|vbs|js|lnk))", cmd, re.I)
    return m.group(1) if m else cmd.split(" ")[0]


def _impact(exe: str) -> str:
    try:
        n = os.path.getsize(exe)
    except Exception:
        return "unknown"
    return "high" if n > 40 * 1024**2 else "medium" if n > 8 * 1024**2 else "low"


def _startup_verdict(name: str, cmd: str, exe: str, engine) -> dict:
    low = (name + " " + cmd).lower()
    for pat, why in (
        (r"(powershell|cmd\.exe).*-(enc|w hidden|nop)", "Hidden shell command at logon"),
        (r"\\appdata\\(local|roaming)\\temp\\", "Runs from a temporary folder"),
        (r"(mshta|rundll32 javascript|regsvr32.*http)", "LOLBin execution at logon"),
        (r"(keygen|crack|patcher|miner|rat)", "Risk-tool naming pattern"),
    ):
        if re.search(pat, low):
            return {"level": "high", "reason": why}
    if exe and os.path.exists(exe) and engine is not None:
        try:
            v = engine.scan_file(exe, max_mb=48)
            if not v.clean:
                return {"level": v.severity, "reason": v.name}
        except Exception:
            pass
    if exe and not os.path.exists(exe):
        return {"level": "low", "reason": "Target file is missing (orphaned entry)"}
    return {"level": "ok", "reason": "No issues detected"}


def startup_disable(name: str, location: str) -> dict:
    for hive, sub, tag in RUN_KEYS:
        if tag != location:
            continue
        try:
            k = winreg.OpenKey(hive, sub, 0, winreg.KEY_ALL_ACCESS)
            val, typ = winreg.QueryValueEx(k, name)
            bk = winreg.CreateKey(hive, sub + r"\AegisDisabled")
            winreg.SetValueEx(bk, name, 0, typ, val)
            winreg.CloseKey(bk)
            winreg.DeleteValue(k, name)
            winreg.CloseKey(k)
            store.log("startup", "info", "Startup item disabled", f"{name} ({location})")
            return {"ok": True}
        except PermissionError:
            return {"ok": False, "error": "Administrator rights required for this key"}
        except OSError as e:
            return {"ok": False, "error": str(e)}
    if "folder" in location.lower():
        try:
            base = (os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows",
                                 "Start Menu", "Programs", "Startup")
                    if "all users" not in location.lower() else
                    os.path.join(os.environ.get("PROGRAMDATA", ""), "Microsoft", "Windows",
                                 "Start Menu", "Programs", "StartUp"))
            src = os.path.join(base, name)
            dis = os.path.join(base, "AegisDisabled")
            os.makedirs(dis, exist_ok=True)
            shutil.move(src, os.path.join(dis, name))
            store.log("startup", "info", "Startup item disabled", name)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    return {"ok": False, "error": "Unsupported location"}


# ====================================================== Breach Monitor
def breach_check(email: str) -> dict:
    """Password-safe breach lookup. Uses XposedOrNot's public API (no key)."""
    email = (email or "").strip()
    if "@" not in email:
        return {"ok": False, "error": "Enter a valid email address"}
    url = f"https://api.xposedornot.com/v1/check-email/{urllib.parse.quote(email)}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=25,
                                    context=ssl.create_default_context()) as r:
            data = json.loads(r.read().decode("utf-8", "ignore"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            store.log("breach", "info", "Breach check clean", email)
            return {"ok": True, "email": email, "breaches": [], "count": 0}
        return {"ok": False, "error": f"Lookup failed (HTTP {e.code})"}
    except Exception as e:
        return {"ok": False, "error": f"Lookup failed: {e}"}

    names = []
    if isinstance(data, dict):
        b = data.get("breaches")
        if isinstance(b, list) and b:
            names = b[0] if isinstance(b[0], list) else b
    names = [str(n) for n in names]
    sev = "critical" if len(names) >= 5 else "high" if names else "info"
    store.log("breach", sev, f"Breach check: {email}",
              f"{len(names)} breaches" if names else "No breaches found")
    return {"ok": True, "email": email, "count": len(names),
            "breaches": [{"name": n} for n in names]}


import urllib.parse  # noqa: E402  (used by breach_check)


# ====================================================== Boot-time scan
def bootscan_schedule(engine_hint: str = "") -> dict:
    """Register a run-once boot task that scans before most malware loads."""
    py = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "boot_scan.py")
    exe = shutil.which("pythonw") or shutil.which("python") or "python"
    cmd = f'"{exe}" "{py}"'
    out = _run(f'schtasks /Create /TN "Aegis Boot-Time Scan" /TR {json.dumps(cmd)} '
               f'/SC ONSTART /RL HIGHEST /F', timeout=30)
    ok = "SUCCESS" in out.upper()
    if not ok and "Access is denied" in out:
        return {"ok": False, "error": "Administrator rights required to schedule a boot scan"}
    store.log("bootscan", "info" if ok else "medium",
              "Boot-time scan scheduled" if ok else "Boot-time scan scheduling failed",
              out.strip()[:300])
    return {"ok": ok, "detail": out.strip()[:300]}


def bootscan_status() -> dict:
    out = _run('schtasks /Query /TN "Aegis Boot-Time Scan" /FO LIST', timeout=20)
    return {"scheduled": "Aegis Boot-Time Scan" in out, "detail": out.strip()[:400]}


def bootscan_cancel() -> dict:
    out = _run('schtasks /Delete /TN "Aegis Boot-Time Scan" /F', timeout=20)
    return {"ok": "SUCCESS" in out.upper(), "detail": out.strip()[:200]}


# ====================================================== Browser cleanup
def browser_tracks() -> list[dict]:
    out = []
    profiles = [
        ("Google Chrome", os.path.join(os.environ.get("LOCALAPPDATA", ""),
                                       "Google", "Chrome", "User Data", "Default")),
        ("Microsoft Edge", os.path.join(os.environ.get("LOCALAPPDATA", ""),
                                        "Microsoft", "Edge", "User Data", "Default")),
        ("Brave", os.path.join(os.environ.get("LOCALAPPDATA", ""), "BraveSoftware",
                               "Brave-Browser", "User Data", "Default")),
    ]
    for label, prof in profiles:
        if not os.path.isdir(prof):
            continue
        entry = {"browser": label, "items": []}
        for nm, rel in (("Cache", "Cache"), ("Cookies", "Network/Cookies"),
                        ("History", "History"), ("Session storage", "Session Storage"),
                        ("Download log", "History-journal")):
            p = os.path.join(prof, rel.replace("/", os.sep))
            if os.path.exists(p):
                sz = 0
                if os.path.isdir(p):
                    for dp, _, fn in os.walk(p):
                        for f in fn:
                            try:
                                sz += os.path.getsize(os.path.join(dp, f))
                            except OSError:
                                pass
                else:
                    sz = os.path.getsize(p)
                entry["items"].append({"name": nm, "path": p, "bytes": sz, "size": _hs(sz)})
        if entry["items"]:
            out.append(entry)
    return out


# ====================================================== Brute-Force Shield
# Watches the Windows Security Event Log for failed logon attempts (4625).
# User-mode only: we cannot block the auth at the kernel, but we detect a
# password-guessing sweep the moment it happens and surface the source IPs.
def bruteforce_status() -> dict:
    enabled = bool(store.get("shield.bruteforce", True))
    return {"enabled": enabled, "window_min": int(store.get("bf.window_min", 10)),
            "threshold": int(store.get("bf.threshold", 5))}


def bruteforce_scan(window_min: int = 10, threshold: int = 5) -> dict:
    """Return recent failed-logon bursts grouped by source, via wevtutil."""
    q = (f"*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] "
         f"and EventID=4625 and TimeCreated[timediff(@SystemTime) <= {window_min * 60000}]]]")
    out = _run(f'wevtutil qe Security /q:"{q}" /f:text /c:200', timeout=30)
    if out.startswith("__ERR__"):
        return {"ok": False, "error": out[7:], "hits": 0, "top": []}
    by_ip = {}
    for blk in out.split("\n\n"):
        ip = None
        for line in blk.splitlines():
            if "Network Address:" in line:
                ip = line.split(":", 1)[1].strip().strip("'\"")
            elif "Source Network Address:" in line:
                ip = line.split(":", 1)[1].strip().strip("'\"")
        if ip and ip not in ("-", "::1", "127.0.0.1"):
            by_ip[ip] = by_ip.get(ip, 0) + 1
    top = sorted(by_ip.items(), key=lambda kv: kv[1], reverse=True)[:10]
    hits = sum(by_ip.values())
    flagged = [{"ip": ip, "count": c} for ip, c in top if c >= threshold]
    return {"ok": True, "hits": hits, "top": [{"ip": ip, "count": c} for ip, c in top],
            "flagged": flagged}


# ====================================================== Firewall control
def firewall_status() -> dict:
    out = _run("netsh advfirewall show allprofiles state", timeout=20)
    on = sum(1 for ln in out.splitlines() if "ON" in ln.upper())
    return {"ok": not out.startswith("__ERR__"), "profiles_on": on,
            "raw": out.strip()[:600]}


def firewall_set(on: bool) -> dict:
    mode = "on" if on else "off"
    out = _run(f"netsh advfirewall set allprofiles state {mode}", timeout=25)
    return {"ok": not out.startswith("__ERR__"), "detail": out.strip()[:200]}


# ====================================================== Webcam / Mic privacy
# We cannot hook the camera driver in user mode, but we report the OS privacy
# posture and warn if common capture apps are running with the mic/cam open.
def privacy_status() -> dict:
    cam = mic = "unknown"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager"
            r"\ConsentStore\webcam") as k:
            cam = winreg.QueryValueEx(k, "Value")[0]
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager"
            r"\ConsentStore\microphone") as k:
            mic = winreg.QueryValueEx(k, "Value")[0]
    except Exception:
        pass
    return {"ok": True, "webcam_consent": cam, "mic_consent": mic,
            "note": "Privacy consent state read from Windows; Aegis cannot block "
                    "a device at the kernel without a driver."}


# ====================================================== File Shredder
def shred_file(path: str) -> dict:
    if not os.path.exists(path):
        return {"ok": False, "error": "not found"}
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.seek(0)
            f.write(os.urandom(min(size, 1024 * 1024)))   # one pass of random
        os.remove(path)
        return {"ok": True, "path": path, "bytes": size}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}


# ====================================================== Secure VPN (premium)
# Aegis has no cloud backend, so this is an honest status surface, not a live
# tunnel. We report the Windows VPN profile state if one is configured.
def vpn_status() -> dict:
    out = _run("powershell -NoProfile -Command \"Get-VpnConnection -AllUserConnection "
               "2>$null | Select-Object Name, ConnectionStatus | ConvertTo-Json\"",
               timeout=25)
    profiles = []
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        profiles = data
    except Exception:
        pass
    return {"ok": True, "available": bool(profiles),
            "profiles": profiles,
            "note": "Aegis does not operate its own VPN servers. Connect through "
                    "your provider; this panel shows the OS VPN state."}


# ====================================================== Windows startup
# Use a scheduled task (logon trigger, highest run level) so Aegis launches
# elevated at boot WITHOUT a per-boot UAC prompt. A plain HKCU Run entry can't
# elevate, and a shortcut in the Startup folder likewise runs non-elevated.
STARTUP_TASK = "AegisSecurityStartup"

def _aegis_exe_pair():
    """Return (python_exe, script_path) for the running Aegis process."""
    here = os.path.dirname(os.path.abspath(__file__))
    # engine/tools.py -> project root is two levels up
    root = os.path.dirname(os.path.dirname(here))
    script = os.path.join(root, "aegis.py")
    exe = sys.executable
    return exe, script

def _startup_reg_key():
    return r"Software\Microsoft\Windows\CurrentVersion\Run"


def startup_status() -> dict:
    # Task Scheduler path
    out = _run(f'schtasks /Query /TN "{STARTUP_TASK}" /FO LIST 2>&1', timeout=20)
    if "READY" in out.upper() or "RUNNING" in out.upper():
        return {"ok": True, "enabled": True, "method": "task"}
    # Registry Run-key fallback
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _startup_reg_key()) as k:
            try:
                winreg.QueryValueEx(k, "AegisSecurity")
                return {"ok": True, "enabled": True, "method": "registry"}
            except FileNotFoundError:
                pass
    except Exception:
        pass
    return {"ok": True, "enabled": False}


def _startup_via_registry(exe, script) -> dict:
    try:
        cmd = '"{0}" "{1}"'.format(exe, script)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _startup_reg_key(),
                           0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "AegisSecurity", 0, winreg.REG_SZ, cmd)
        return {"ok": True, "detail": "registry Run key set"}
    except Exception as e:
        return {"ok": False, "detail": str(e)}


def startup_enable() -> dict:
    exe, script = _aegis_exe_pair()
    # Preferred: scheduled task at logon, highest run level (auto-elevated, no UAC).
    # Some locked-down/eval environments block task creation, so fall back to the
    # HKCU Run key, which survives logon and needs no scheduler.
    tr = r'"\"{0}\" \"{1}\""'.format(exe, script)
    cmd = ('schtasks /Create /TN "{0}" /TR {1} /SC ONLOGON /RL HIGHEST /F'
           .format(STARTUP_TASK, tr))
    out = _run(cmd, timeout=30)
    if "SUCCESS" in out.upper() or startup_status().get("method") == "task":
        return {"ok": True, "detail": (out.strip() or "task created")[:300],
                "method": "task"}
    reg = _startup_via_registry(exe, script)
    if reg.get("ok"):
        return {"ok": True, "detail": reg.get("detail"), "method": "registry"}
    return {"ok": False, "detail": (out.strip() or reg.get("detail", ""))[:300]}


def startup_disable() -> dict:
    _run(f'schtasks /Delete /TN "{STARTUP_TASK}" /F', timeout=20)
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _startup_reg_key(),
                           0, winreg.KEY_SET_VALUE) as k:
            try:
                winreg.DeleteValue(k, "AegisSecurity")
            except FileNotFoundError:
                pass
    except Exception:
        pass
    return {"ok": True, "detail": "startup disabled"}
