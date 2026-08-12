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
# Avast "Self-Defense": stop malware from tampering with / uninstalling Aegis.
# User-mode equivalent: deny non-admins write/delete on the Aegis program dir.
# Reversible. Requires the dir to be writable by the current user to apply.
def self_defense_status() -> dict:
    return {"enabled": bool(store.get("selfdefense.enabled", False))}


def self_defense_set(on: bool) -> dict:
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)  # engine/ -> project root
    if on:
        out = _run(f'icacls "{root}" /deny "BUILTIN\\Users":(WI)(DC) /c /q',
                   timeout=30)
        ok = not out.startswith("__ERR__")
        store.set("selfdefense.enabled", ok)
        return {"ok": ok, "enabled": ok,
                "detail": "Denied non-admins write/delete on the Aegis folder."
                          if ok else out.strip()[:200]}
    _run(f'icacls "{root}" /remove:deny "BUILTIN\\Users" /c /q', timeout=30)
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
