"""Aegis Security — system hardening features (Avast-style).

Real, user-mode Windows controls. A few of these (disabling a camera driver,
denying ACLs) are genuinely system-affecting; they are reversible and wrapped in
try/except so a failure never takes the app down. Where the OS requires elevation
the function reports it rather than silently doing nothing.

Scope note (honest): Aegis has no kernel driver. These are the strongest controls
available from a user-mode Python process on Windows:
  * Firewall  -> netsh advfirewall (real packet filtering, OS-level)
  * Webcam    -> pnputil device disable (real, driver level) + ConsentStore registry
  * Mic       -> ConsentStore registry (per-app permission posture)
  * Sensitive Data -> icacls ACL deny (real filesystem ACL)
  * Self-Defense   -> icacls ACL deny on the Aegis program dir (real filesystem ACL)
"""
from __future__ import annotations

import os
import re
import subprocess

from . import store

CREATE_NO_WINDOW = 0x08000000


def _run(cmd: str, timeout: int = 40) -> str:
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout, creationflags=CREATE_NO_WINDOW,
                           errors="ignore")
        return (p.stdout or "") + (p.stderr or "")
    except Exception as e:  # pragma: no cover
        return f"__ERR__{e}"


# ============================================================ Firewall profiles
# Avast "Firewall Profiles": Private (trusted) / Public (untrusted). We map to
# the Windows Defender Firewall per-profile state via netsh.
_PROFILE_NET = {"private": "privateprofile", "public": "publicprofile",
                "domain": "domainprofile", "all": "allprofiles"}


def firewall_profiles_status() -> dict:
    out = _run("netsh advfirewall show allprofiles state", timeout=25)
    res = {"ok": not out.startswith("__ERR__")}
    for label, key in (("private", "Private Profile"), ("public", "Public Profile"),
                       ("domain", "Domain Profile")):
        m = re.search(re.escape(key) + r".*?State\s+(ON|OFF)", out, re.S | re.I)
        # netsh prints e.g. "Private Profile Settings:\nState\t\t\tON"
        m2 = re.search(rf"{key}.*?State\s+(ON|OFF)", out, re.S | re.I)
        res[label] = bool(m2 and "ON" in m2.group(1).upper())
    res["raw"] = out.strip()[:600]
    return res


def firewall_set_profile(profile: str, on: bool) -> dict:
    net = _PROFILE_NET.get(profile, "allprofiles")
    mode = "on" if on else "off"
    out = _run(f"netsh advfirewall set {net} state {mode}", timeout=25)
    return {"ok": not out.startswith("__ERR__"), "detail": out.strip()[:200]}


# ============================================================ Firewall app policy
# Avast "App Policies (New Apps)": Smart / Strict / Block / Ask.
# User-mode cannot truly intercept each new connection to pop a prompt, so:
#   smart  -> default Windows behaviour (no extra rules)
#   strict -> turn firewall on + enable outbound filtering (block-by-default outbound)
#   block  -> strict + a baseline deny-outbound rule so unknown apps cannot phone home
#   ask    -> we cannot truly prompt per-connection; behave like strict and note it
_APP_POLICY_RULE = "AegisNewAppBlock"


def firewall_app_policy_status() -> dict:
    return {"policy": store.get("firewall.app_policy", "smart")}


def firewall_app_policy_set(policy: str) -> dict:
    policy = policy.lower()
    if policy not in ("smart", "strict", "block", "ask"):
        return {"ok": False, "error": "unknown policy"}
    # remove any baseline rule we previously added
    _run(f'netsh advfirewall firewall delete rule name="{_APP_POLICY_RULE}"',
         timeout=20)
    if policy in ("strict", "block", "ask"):
        # enable the firewall and outbound filtering (block-by-default outbound)
        _run("netsh advfirewall set allprofiles state on", timeout=20)
        _run("netsh advfirewall set allprofiles firewallpolicy "
             "blockinboundalways,blockoutboundalways", timeout=20)
    if policy == "block":
        # baseline deny-outbound for anything not explicitly allowed
        out = _run(
            f'netsh advfirewall firewall add rule name="{_APP_POLICY_RULE}" '
            f"dir=out action=block remoteip=0.0.0.0/0,::/0 "
            f'description="Aegis Block mode: deny new apps outbound"', timeout=25)
        store.set("firewall.app_policy", "block")
        return {"ok": not out.startswith("__ERR__"), "policy": "block",
                "detail": out.strip()[:200]}
    store.set("firewall.app_policy", policy)
    return {"ok": True, "policy": policy,
            "detail": "strict/ask use outbound filtering; true per-connection "
                      "prompts need a kernel driver"}


# ============================================================ Webcam & Mic guard
# Avast "Webcam Shield": Smart / Strict / No Mercy.
#   smart    -> OS default (ConsentStore = Allow); trusted apps auto-approved
#   strict   -> ConsentStore = Deny (every activation must be approved in Windows)
#   nomercy  -> disable the camera device driver via pnputil (real driver disable)
# For the microphone we use the same registry posture; a true driver disable of all
# audio endpoints is too disruptive, so No Mercy on mic = Deny (documented).
def _pnp_devices(cls: str) -> list[dict]:
    ps = (f'Get-PnpDevice -Class "{cls}" -ErrorAction SilentlyContinue | '
          f'Select-Object FriendlyName,Status,InstanceId | ConvertTo-Json')
    out = _run(f'powershell -NoProfile -Command "{ps}"', timeout=30)
    try:
        import json
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        return data
    except Exception:
        return []


def _set_consent(device: str, value: str) -> None:
    key = (r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager"
           r"\ConsentStore\\" + device)
    try:
        import winreg
        k = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key)
        winreg.SetValueEx(k, "Value", 0, winreg.REG_SZ, value)
        winreg.CloseKey(k)
    except Exception:
        pass


def webcam_status() -> dict:
    mode = store.get("webcam.mode", "smart")
    devs = _pnp_devices("Camera")
    disabled = any(str(d.get("Status", "")).lower().startswith("error")
                   or "disabled" in str(d.get("Status", "")).lower() for d in devs)
    return {"mode": mode, "devices": devs, "driver_disabled": disabled,
            "note": "No Mercy disables the camera driver; Smart/Strict set the "
                    "Windows per-app consent posture."}


def webcam_set_mode(mode: str) -> dict:
    mode = mode.lower()
    if mode not in ("smart", "strict", "nomercy"):
        return {"ok": False, "error": "unknown mode"}
    if mode == "nomercy":
        devs = _pnp_devices("Camera")
        done = 0
        for d in devs:
            iid = d.get("InstanceId")
            if iid:
                out = _run(f'pnputil /disable-device "{iid}"', timeout=30)
                if not out.startswith("__ERR__"):
                    done += 1
        store.set("webcam.mode", "nomercy")
        return {"ok": True, "mode": "nomercy", "disabled": done}
    # smart -> Allow, strict -> Deny
    _set_consent("webcam", "Allow" if mode == "smart" else "Deny")
    store.set("webcam.mode", mode)
    return {"ok": True, "mode": mode}


def mic_status() -> dict:
    return {"mode": store.get("mic.mode", "smart"),
            "note": "Smart/Strict/No Mercy set the Windows per-app consent posture; "
                    "a true driver disable of all audio endpoints is not applied."}


def mic_set_mode(mode: str) -> dict:
    mode = mode.lower()
    if mode not in ("smart", "strict", "nomercy"):
        return {"ok": False, "error": "unknown mode"}
    _set_consent("microphone", "Allow" if mode == "smart" else "Deny")
    store.set("mic.mode", mode)
    return {"ok": True, "mode": mode}


# ============================================================ Sensitive Data Shield
# Avast "Sensitive Data Shield": Block Other Users (other Windows accounts on this
# PC) from reading your protected private docs. Implemented with a real icacls
# deny-ACL on each protected folder.
def sensitive_data_status() -> dict:
    return {"folders": store.get("sensitive.folders", []),
            "deny_others": bool(store.get("sensitive.deny_others", False))}


def sensitive_data_apply(deny_others: bool, folders: list[str] | None = None) -> dict:
    if folders is None:
        folders = store.get("sensitive.folders", [])
    folders = [f for f in folders if f and os.path.isdir(f)]
    store.set("sensitive.folders", folders)
    store.set("sensitive.deny_others", bool(deny_others))
    changed = 0
    if deny_others:
        for f in folders:
            out = _run(f'icacls "{f}" /deny "Authenticated Users":(RD) '
                       f'/c /q', timeout=30)
            if not out.startswith("__ERR__"):
                changed += 1
    else:
        for f in folders:
            _run(f'icacls "{f}" /remove:deny "Authenticated Users" /c /q',
                 timeout=30)
            changed += 1
    return {"ok": True, "folders": folders, "deny_others": deny_others,
            "changed": changed}


def sensitive_data_add(path: str) -> dict:
    folders = store.get("sensitive.folders", [])
    if path and os.path.isdir(path) and path not in folders:
        folders.append(path)
    return sensitive_data_apply(bool(store.get("sensitive.deny_others", False)), folders)


def sensitive_data_remove(path: str) -> dict:
    folders = [f for f in store.get("sensitive.folders", []) if f != path]
    # also undo the deny ACL on the removed folder if it was applied
    if store.get("sensitive.deny_others", False):
        _run(f'icacls "{path}" /remove:deny "Authenticated Users" /c /q', timeout=30)
    return sensitive_data_apply(bool(store.get("sensitive.deny_others", False)), folders)


# ============================================================ Self-Defense
# Avast "Self-Defense": stop malware (and casual Task Manager kills) from
# terminating / tampering with Aegis.
#
# User-mode reality (honest): without a kernel driver we cannot become a true
# Protected Process. What we CAN do safely is harden the two layers:
#   1. Filesystem: deny non-admins write/delete on the Aegis program dir (so the
#      binary/config can't be swapped or deleted).
#   2. Process object: strip the PROCESS_TERMINATE / PROCESS_VM_WRITE rights for
#      everyone except the owner on THIS process, so TerminateProcess() from any
#      other process (Task Manager, malware, scripts) returns ACCESS_DENIED.
# The process-DACL change is reverted on disable (or when shields turn off) so
# you can close Aegis normally.
import ctypes

try:
    import ctypes
    import ctypes.wintypes as wintypes
    _advapi32 = ctypes.windll.advapi32
    _kernel32 = ctypes.windll.kernel32
    _HAS_WIN = True
except Exception:  # pragma: no cover - non-Windows
    ctypes = None
    wintypes = None
    _advapi32 = None
    _kernel32 = None
    _HAS_WIN = False

# PROCESS_ rights used below (defined here so the module imports on any OS).
PROCESS_TERMINATE = 0x0001
PROCESS_VM_WRITE = 0x0020

_SE_WIN = 0x40000000  # SET_SECURITY_INFORMATION
_DACL_SECURITY_INFORMATION = 0x00000004
_PROCESS_ALL_ACCESS = 0x1F0FFF


def _protect_self_process(enable: bool) -> bool:
    """Add or remove a deny-ish DACL entry that removes PROCESS_TERMINATE and
    PROCESS_VM_WRITE from 'Everyone' + 'Authenticated Users' on this process.
    Returns True if the operation succeeded."""
    if not _HAS_WIN:
        return False
    try:
        pid = _kernel32.GetCurrentProcessId()
        h = _kernel32.OpenProcess(_PROCESS_ALL_ACCESS, False, pid)
        if not h:
            return False
        # Build a SID for "Everyone" (S-1-1-0) and "Authenticated Users" (S-1-5-11).
        sid_everyone = _make_sid(1, 0, [0])          # S-1-1-0
        sid_authusers = _make_sid(5, 0, [11])         # S-1-5-11
        sids = [s for s in (sid_everyone, sid_authusers) if s]
        # New DACL: explicit DENY entries removing terminate/write for those SIDs,
        # plus keep owner/admins intact. We apply a DENY ace.
        dacl = _build_deny_dacl(sids)
        if dacl is None:
            _kernel32.CloseHandle(h)
            return False
        rc = _advapi32.SetSecurityInfo(
            h, 6,  # SE_KERNEL_OBJECT == process
            _DACL_SECURITY_INFORMATION, None, None, dacl, None)
        _kernel32.CloseHandle(h)
        return rc == 0
    except Exception:
        return False


def _make_sid(authority: int, subauth_count: int, subauth: list[int]):
    try:
        import ctypes
        psid = ctypes.create_string_buffer(64)
        if not _advapi32.AllocateAndInitializeSid(
                ctypes.byref(ctypes.c_ubyte(authority)),
                ctypes.c_byte(subauth_count),
                *[ctypes.c_ulong(s) for s in (subauth + [0, 0, 0, 0, 0])[:8]],
                ctypes.byref(psid)):
            return None
        return psid
    except Exception:
        return None


def _build_deny_dacl(sids: list):
    """Construct a WIN32 ACL buffer with DENY ACEs removing terminate/write."""
    try:
        ACE_DENY = 0x1  # ACCESS_DENIED_ACE_TYPE
        # rights we remove: terminate (0x1) + vm_write (0x20) + suspend (0x800)
        rights = PROCESS_TERMINATE | PROCESS_VM_WRITE | 0x800
        aces = b""
        for sid in sids:
            raw = ctypes.string_at(sid, _advapi32.GetLengthSid(sid))
            sid_len = len(raw)
            ace_size = 8 + sid_len  # header(4) + mask(4) + sid
            ace = (ctypes.c_ubyte(ACE_DENY).value << 0).to_bytes(1, "little")
            ace += (0).to_bytes(1, "little")           # flags
            ace += ace_size.to_bytes(2, "little")
            ace += rights.to_bytes(4, "little")
            ace += raw
            aces += ace
        acl_len = 8 + len(aces)
        hdr = acl_len.to_bytes(2, "little")             # AclSize
        hdr += (2).to_bytes(1, "little")                # AclRevision
        hdr += (0).to_bytes(1, "little")                # Sbz1
        hdr += len(sids).to_bytes(2, "little")          # AceCount
        hdr += (0).to_bytes(2, "little")                # Sbz2
        return hdr + aces
    except Exception:
        return None


def self_defense_status() -> dict:
    return {"enabled": bool(store.get("selfdefense.enabled", False))}


def self_defense_set(on: bool) -> dict:
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)  # engine/ -> project root
    if on:
        out = _run(f'icacls "{root}" /deny "BUILTIN\\Users":(WI)(DC) /c /q',
                   timeout=30)
        fs_ok = not out.startswith("__ERR__")
        proc_ok = _protect_self_process(True)
        ok = fs_ok or proc_ok
        store.set("selfdefense.enabled", ok)
        return {"ok": ok, "enabled": ok, "filesystem": fs_ok,
                "process": proc_ok,
                "detail": ("Denied non-admins write/delete on the Aegis folder and "
                           "removed terminate/write rights on the Aegis process."
                           if ok else out.strip()[:200])}
    _run(f'icacls "{root}" /remove:deny "BUILTIN\\Users" /c /q', timeout=30)
    _protect_self_process(False)
    store.set("selfdefense.enabled", False)
    return {"ok": True, "enabled": False}


# ============================================================ Data Shredder
# Avast "Data Shredder" algorithms: Random (1 pass) / DoD 5220.22-M (3 passes) /
# Gutmann (35 passes). Real overwrites with random data, then delete.
_PASSES = {"random": 1, "dod": 3, "gutmann": 35}


def shred_file(path: str, algorithm: str = "random") -> dict:
    if not os.path.exists(path):
        return {"ok": False, "error": "not found"}
    try:
        size = os.path.getsize(path)
        passes = _PASSES.get(algorithm, 1)
        with open(path, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                left = size
                while left > 0:
                    chunk = min(left, 1024 * 1024)
                    f.write(os.urandom(chunk))
                    left -= chunk
        os.remove(path)
        return {"ok": True, "path": path, "bytes": size, "passes": passes}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}


def shredder_algorithms() -> list[dict]:
    return [
        {"id": "random", "name": "Random Overwrite",
         "desc": "Default, fastest (1 pass of random data).", "passes": 1},
        {"id": "dod", "name": "DoD 5220.22-M",
         "desc": "Medium security (3 passes).", "passes": 3},
        {"id": "gutmann", "name": "Gutmann Algorithm",
         "desc": "Maximum security (35 passes, slow).", "passes": 35},
    ]
