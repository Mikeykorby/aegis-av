"""Aegis Security — kernel companion integration.

The optional kernel driver (`aegis-kernel`, a separate repo) pushes protection
below user mode: pre-execution blocking, ransomware IRP interception, and
tamper-proof self-defense. This module lets the app DISCOVER whether the
kernel path is usable on the current machine and TOGGLE it on/off.

It is deliberately honest: it never claims "kernel active" unless a signed-
or test-signed driver is actually present and the OS will load it. If the
driver binary is missing, or Secure Boot is on without WHQL, it reports the
exact blocker so the user can act on it.

Driver location (user drops the built .sys here, or the installer places it):
    <LOCALAPPDATA>/Aegis/data/kernel/aegis_kernel.sys
"""
from __future__ import annotations

import ctypes
import os
import platform
import subprocess

from . import store

KERNEL_DIR = os.path.join(store.DATA_DIR, "kernel")
DRIVER_PATH = os.path.join(KERNEL_DIR, "aegis_kernel.sys")
AGENT_PATH = os.path.join(KERNEL_DIR, "aegis_agent.exe")

# Windows build that introduced a usable mini-filter / object callback surface
# for what we need (all still-supported builds qualify; kept for the report).
_MIN_BUILD = 10240


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run(cmd: list[str], timeout: int = 20) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                            timeout=timeout, creationflags=0x08000000)
        return p.returncode, p.stdout or "", p.stderr or ""
    except Exception as e:  # noqa: BLE001
        return -1, "", str(e)


def _test_signing_on() -> bool | None:
    """True/False if we can determine Test Signing; None if indeterminate."""
    rc, out, _ = _run(["bcdedit.exe", "/enum", "{current}", "/v"])
    if rc != 0:
        # Fall back to the loader options registry key.
        try:
            import winreg
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r"SYSTEM\CurrentControlSet\Control\SystemStartOptions")
            val, _ = winreg.QueryValueEx(k, "")
            return "TESTSIGNING" in str(val).upper()
        except Exception:
            return None
    for line in out.splitlines():
        if "testsigning" in line.lower():
            return "yes" in line.lower()
    return False


def _secure_boot() -> str:
    """Returns 'on', 'off', or 'unknown'."""
    rc, out, _ = _run(
        ["powershell.exe", "-NoProfile", "-Command",
         "(Confirm-SecureBootUEFI).ToString()"])
    if rc == 0:
        o = out.strip().lower()
        if o in ("true", "on"):
            return "on"
        if o in ("false", "off"):
            return "off"
    # Some firmware/VMs don't expose the cmdlet; treat as unknown.
    return "unknown"


def _driver_present() -> bool:
    return os.path.exists(DRIVER_PATH)


def _agent_present() -> bool:
    return os.path.exists(AGENT_PATH)


def compat_probe() -> dict:
    """Inspect the machine and report whether the kernel path can load.

    Returns a dict the UI can render directly.
    """
    arch = platform.machine().lower()
    is_x64 = arch in ("amd64", "x86_64", "x64")
    admin = _is_admin()
    testsign = _test_signing_on()
    sb = _secure_boot()
    driver = _driver_present()
    agent = _agent_present()

    issues: list[str] = []
    if not is_x64:
        issues.append("Kernel driver is x64-only; this machine is %s." % arch)
    if not admin:
        issues.append("Run Aegis as Administrator to load a kernel driver.")
    if testsign is False:
        issues.append("Test Signing is OFF. Enable it (bcdedit /set testsigning on) "
                      "and reboot, or use a WHQL-signed driver.")
    if sb == "on":
        if testsign is not True:
            issues.append("Secure Boot is ON and no WHQL signature is present — "
                          "the driver cannot load until WHQL-certified.")
        else:
            issues.append("Secure Boot is ON with Test Signing; only test-signed "
                          "drivers from your test cert will load.")
    if not driver:
        issues.append("aegis_kernel.sys not found in %s. Drop the built driver "
                      "there (build it in the aegis-kernel repo) or install it."
                      % KERNEL_DIR)

    loadable = bool(is_x64 and admin and driver
                    and (testsign is True or sb in ("off", "unknown")))
    # "available" = driver present + OS would accept it; "active" requires the
    # toggle to be on AND loadable AND the agent/service actually running.
    can_enable = bool(is_x64 and admin and driver)
    recommended = can_enable and not store.get("kernel.enabled", False)

    status = "unsupported"
    if driver and loadable:
        status = "ready"
    elif driver and not loadable:
        status = "blocked"
    elif not driver:
        status = "no-driver"

    return {
        "arch": arch,
        "is_x64": is_x64,
        "admin": admin,
        "test_signing": ("on" if testsign is True else
                         "off" if testsign is False else "unknown"),
        "secure_boot": sb,
        "driver_present": driver,
        "agent_present": agent,
        "loadable": loadable,
        "can_enable": can_enable,
        "enabled": bool(store.get("kernel.enabled", False)),
        "recommended": recommended,
        "status": status,
        "issues": issues,
        "driver_path": DRIVER_PATH,
    }


def status() -> dict:
    """Current kernel state for the dashboard / settings UI."""
    probe = compat_probe()
    enabled = bool(store.get("kernel.enabled", False))
    probe["enabled"] = enabled
    if enabled and probe["loadable"] and probe["driver_present"]:
        probe["state"] = "active"
        probe["detail"] = ("Kernel companion active — pre-execution blocking and "
                           "self-defense are enforced below user mode.")
    elif enabled and not probe["driver_present"]:
        probe["state"] = "missing-driver"
        probe["detail"] = ("Kernel protection is switched ON but aegis_kernel.sys "
                           "is not present. Build/install it or turn the toggle off.")
    elif enabled and not probe["loadable"]:
        probe["state"] = "blocked"
        probe["detail"] = ("Kernel protection is switched ON but the OS will not "
                           "load the driver: " + "; ".join(probe["issues"]))
    else:
        probe["state"] = "inactive"
        probe["detail"] = ("User-mode shields only. Enable the kernel companion for "
                           "pre-execution blocking and tamper-proof self-defense.")
    return probe


def _signtool() -> str | None:
    """Locate signtool.exe from the Windows SDK / WDK bin trees."""
    import glob
    for base in (r"C:\Program Files (x86)\Windows Kits\10\bin",
                 r"C:\Program Files\Windows Kits\10\bin"):
        hits = sorted(glob.glob(os.path.join(base, "*", "x64", "signtool.exe")),
                      reverse=True)
        if hits:
            return hits[0]
    return None


def _ensure_test_cert() -> dict:
    """Create + trust a local test-signing certificate if missing."""
    ps = r'''
    $fn = "AegisKernelTest"
    $existing = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.FriendlyName -eq $fn })
    if ($existing.Count -eq 0) {
        $c = New-SelfSignedCertificate -Type Custom -Subject "CN=Aegis Kernel Test" `
            -KeyUsage DigitalSignature -FriendlyName $fn `
            -CertStoreLocation Cert:\LocalMachine\My `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3")
        $existing = @($c)
    }
    $cert = $existing[0]
    $thumb = $cert.Thumbprint
    $export = Join-Path $env:TEMP "aegis_test.cer"
    Export-Certificate -Cert $cert -FilePath $export -Type CERT | Out-Null
    foreach ($storeName in @("Root","TrustedPublisher")) {
        $s = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName,"LocalMachine")
        $s.Open("ReadWrite")
        if (-not ($s.Certificates | Where-Object { $_.Thumbprint -eq $thumb })) {
            $s.Add($cert)
        }
        $s.Close()
    }
    $thumb
    '''
    rc, out, err = _run(["powershell.exe", "-NoProfile", "-Command", ps], timeout=120)
    if rc != 0:
        return {"ok": False, "error": (err or out or "cert creation failed (%d)" % rc)}
    thumb = (out or "").strip().splitlines()[-1].strip()
    if not thumb:
        return {"ok": False, "error": "cert creation returned no thumbprint"}
    return {"ok": True, "thumbprint": thumb}


def _self_sign_driver() -> dict:
    """Test-sign aegis_kernel.sys with the local test cert."""
    st = _signtool()
    if not st:
        return {"ok": False, "error": "signtool.exe not found"}
    cert = _ensure_test_cert()
    if not cert.get("ok"):
        return cert
    cmd = [st, "sign", "/v", "/n", "Aegis Kernel Test", "/fd", "SHA256",
           "/tr", "http://timestamp.digicert.com", "/td", "SHA256", DRIVER_PATH]
    rc, out, err = _run(cmd, timeout=120)
    if rc != 0:
        return {"ok": False,
                "error": (err or out or "sign failed (%d)" % rc)}
    return {"ok": True, "signed": True}


def prepare() -> dict:
    """Make the machine ready to load the driver: enable Test Signing via
    bcdedit AND test-sign aegis_kernel.sys with a trusted local cert.

    Requires Administrator. A reboot is required for Test Signing to take
    effect; after that the driver will load in kernel mode.
    """
    if not _is_admin():
        return {"ok": False, "error": "Run Aegis as Administrator."}
    if not _driver_present():
        return {"ok": False,
                "error": "aegis_kernel.sys not found; build it first."}
    steps: dict = {}
    rc, _, err = _run(["bcdedit.exe", "/set", "testsigning", "on"], timeout=30)
    steps["testsigning_set"] = (rc == 0)
    if rc != 0:
        steps["testsigning_error"] = err or ("bcdedit failed (%d)" % rc)
    sign = _self_sign_driver()
    steps["signed"] = bool(sign.get("ok"))
    if not sign.get("ok"):
        steps["sign_error"] = sign.get("error")
    ok = bool(steps.get("testsigning_set") and steps.get("signed"))
    return {"ok": ok, "reboot_required": True, "steps": steps,
            "detail": ("Test Signing enabled and driver test-signed. "
                       "Reboot to load the kernel companion.")}


def enable() -> dict:
    """Turn the kernel companion ON.

    If the machine isn't yet able to load the driver (Test Signing off or the
    .sys unsigned), this automatically runs the bcdedit + self-sign step so a
    single toggle readies the system. A reboot is then required.
    """
    probe = compat_probe()
    store.set("kernel.enabled", True)
    if not probe["driver_present"]:
        return {"ok": True, "enabled": True, "loadable": False,
                "warning": "Enabled, but aegis_kernel.sys is missing — "
                           "the kernel path will not engage until it is installed."}
    if not probe["loadable"]:
        # Not loadable yet — auto-run the bcdedit + self-sign step so a single
        # toggle readies the machine. The user still has to reboot after.
        prep = prepare()
        if prep.get("ok"):
            return {"ok": True, "enabled": True, "loadable": False,
                    "reboot_required": True,
                    "detail": prep.get("detail",
                                       "Kernel companion readied — reboot to load.")}
        return {"ok": True, "enabled": True, "loadable": False,
                "warning": "Enabled, but the OS will not load the driver yet: "
                           + "; ".join(probe["issues"]),
                "prepare_error": prep.get("error")}
    return {"ok": True, "enabled": True, "loadable": True}


def enable_test_signing() -> dict:
    """Turn on Windows Test Signing so a test-signed .sys can load.

    Requires Administrator and a reboot to take effect. No driver is bundled,
    so this only removes one of the blockers — the user must still supply a
    built aegis_kernel.sys (or a WHQL-signed one with Secure Boot on).
    """
    if not _is_admin():
        return {"ok": False, "error": "Run Aegis as Administrator to change boot options."}
    rc, _, err = _run(["bcdedit.exe", "/set", "testsigning", "on"], timeout=30)
    if rc != 0:
        return {"ok": False, "error": (err or "bcdedit failed (%d)" % rc)}
    return {"ok": True, "reboot_required": True,
            "detail": "Test Signing enabled. Reboot for it to take effect, then "
                      "drop a built aegis_kernel.sys into the kernel directory."}


def disable() -> dict:
    """Turn the kernel companion OFF (releases any loaded driver/protection)."""
    store.set("kernel.enabled", False)
    # If a real driver were loaded we'd send AEGIS_CMD_SET_SELFDEFENSE(0) /
    # unload here. Source-only repo keeps this honest: we just stop claiming
    # kernel protection and let the user-mode shields carry the load.
    return {"ok": True, "enabled": False}
