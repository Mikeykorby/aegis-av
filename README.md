# Aegis Security

A Windows antivirus I built because the free options either nag you into a paid
tier or quietly ship your data. Aegis does the layered scanning, real-time
shields, quarantine, and the network/health tools — and it keeps the features
Avast puts behind Premium (kernel-level blocking) instead of
hiding them behind a paywall. It does not operate a VPN — it surfaces your
existing OS VPN connection state, honestly, with no servers of its own.

## Building and running

```bat
"Aegis Security.bat"     :: elevates, launches
python aegis.py          :: or run it directly
```

Needs Python 3.11+ and the WebView2 runtime (standard on Windows 10/11).

```bat
pip install pywebview yara-python watchdog pefile psutil
```

## How detection works

Five layers run per file, cheapest first. Highest severity wins; several medium
hits stack into a high verdict.

| Layer | What it actually checks |
|---|---|
| Authenticode gate | `WinVerifyTrust` + `CryptCATAdmin*` resolves **catalog** signatures, not just embedded ones. Validly signed binaries skip PE heuristics entirely. |
| Signature | EICAR + MD5/SHA-256 from abuse.ch MalwareBazaar. |
| Filename | RTL-override spoofing, `invoice.pdf.exe` double extensions, risk-tool names. |
| PE structural | Section entropy, packer IDs (UPX/Themida/VMProtect), RWX sections, suspicious import sets, TLS callbacks, revoked/tampered certs. |
| Script & macro | ~20 weighted patterns: encoded PowerShell, `IEX`, `certutil -urlcache`, `vssadmin delete shadows`, Defender tampering, auto-open VBA. |
| YARA | YARA Forge core package, ~5,000 community rules. |

Measured on this machine: 0 false positives across 200 signed System32
binaries (it was 60% before the catalog-signature fix), ~27 files/sec.

## Real-time shields

- **File Shield** — watchdog on Downloads, Desktop, Documents, TEMP, Startup; scans on create/modify, auto-quarantines.
- **Ransomware Shield** — hidden canary files in protected folders plus mass-modification burst detection (60 changes / 12s), and it names the suspect process.
- **Behaviour Shield** — polls new processes against 15 command-line rules (shadow-copy deletion, LOLBin abuse, firewall/Defender disable, SYSTEM-task persistence).
- **Web Shield** — URLhaus host lookup with parent-domain matching.
- **Mail Shield** — attachment hashing + archive unpacking + AMSI macro scan.
- **VPN status** — surfaces your OS VPN connection state (Aegis runs no VPN servers; it reports the Windows VPN profile so you can confirm you're protected).

## Kernel companion (`aegis-kernel`)

User-mode can only react *after* a file hits disk. The companion repo ships a
C mini-filter driver + C++ agent that blocks deny-listed hashes **before** a
process starts, stops ransomware at the IRP level, and protects the Aegis PID
via `ObRegisterCallbacks`. The app probes for a working driver and switches
between the kernel path and the user-mode fallback automatically.

Load it free with Windows Test Signing (`bcdedit /set testsigning on`).
Shipping on a machine with Secure Boot on needs an EV-cert + WHQL signature —
that's a Microsoft requirement, not a choice I made.

## Tools

Wi-Fi Inspector (encryption grade, router port exposure, DNS hijack, SMBv1, ARP
sweep with OUI vendor lookup) · System Health (UAC, BitLocker, RDP, pending
updates, resources) · Junk Cleanup (10 targets + Recycle Bin) · Startup Manager
(Run keys + Startup folders, each entry scanned) · Breach Monitor · Boot-Time
Scan · Virus Chest (XOR-obfuscated; restore adds an exclusion, delete
overwrites first) · scheduled scans · exclusions · activity log.

## Layout

```
aegis.py              entry point (DPI awareness, window)
engine/
  detect.py           5-layer scanning engine
  trust.py            Authenticode + catalog verification
  scanner.py          threaded scan jobs, quarantine chest
  shields.py          real-time protection + kernel probe/switch
  tools.py            Wi-Fi, health, junk, startup, breach
  intel.py            abuse.ch + YARA Forge updater
  store.py            SQLite persistence
  api.py              JS bridge
site/                 marketing site (deployed to aegis-av.pages.dev)
ui/                   app UI: index.html + app.css + JS modules
```

Data lives in `%LOCALAPPDATA%\Aegis` (db, chest, definitions).

## Tests

```bat
python t_engine.py    :: detection + System32 false-positive sweep
python t_api.py       :: 36 API checks incl. quarantine round-trip
python t_render.py    :: headless render of all 12 pages (Playwright)
```

## Threat intel sources

abuse.ch MalwareBazaar (hashes) · abuse.ch URLhaus (hosts) · YARA Forge /
YARA-HQ (rules) · XposedOrNot (breach lookups).

## License and liability

Licensed under MIT (see `LICENSE`). The kernel driver is a power tool: a bug in
a kernel-mode filter can blue-screen the machine or, in a worst case, corrupt
data. It is provided as-is, with no warranty. The test-signing path is a
Microsoft-supported developer workflow — not a circumvention — and commercial
deployment still requires WHQL. Don't run untested driver builds on a machine
with data you care about.
