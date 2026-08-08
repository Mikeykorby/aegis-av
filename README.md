# Aegis Security

A working Windows antivirus with a WebView2 front end, built to match what
Avast Free/Premium actually ships: layered detection, real-time shields, a
quarantine chest, and the network/performance tools that sit alongside the
scanner.

## Run it

```
"Aegis Security.bat"        # elevates, then launches
python aegis.py             # unprivileged
```

Requires Python 3.11+ and the WebView2 runtime (present on Windows 10/11 by
default).

```
pip install pywebview yara-python watchdog pefile psutil
```

## Detection engine

Five layers run per file, cheapest first. The highest severity wins, and
several medium hints aggregate into a high verdict.

| Layer | What it does |
|---|---|
| **Authenticode gate** | `WinVerifyTrust` + `CryptCATAdmin*` — resolves **catalog** signatures, not just embedded ones. Validly signed binaries skip PE heuristics entirely. |
| **Signature** | EICAR + MD5/SHA-256 hashes from abuse.ch MalwareBazaar. |
| **Filename heuristics** | RTL-override spoofing, `invoice.pdf.exe` double extensions, risk-tool naming. |
| **PE structural** | Section entropy, packer detection (UPX/Themida/VMProtect/…), RWX sections, injection-capable import sets, TLS callbacks, tampered/revoked certs. |
| **Script & macro** | 20 weighted patterns — encoded PowerShell, IEX, `certutil -urlcache`, `vssadmin delete shadows`, Defender tampering, auto-open VBA macros. |
| **YARA** | YARA Forge core package, ~5,000 community rules. |

**Measured on this machine:** 0 false positives across 200 signed System32
binaries (was 60% before the catalog-signature fix), ~27 files/sec.

## Real-time shields

- **File Shield** — watchdog observers on Downloads, Desktop, Documents, TEMP and Startup; scans on create/modify, auto-quarantines.
- **Ransomware Shield** — hidden canary files in protected folders plus mass-modification burst detection (60 changes / 12s), and it names the suspect process.
- **Behaviour Shield** — polls new processes against 15 command-line rules (shadow-copy deletion, LOLBin abuse, firewall/Defender disable, SYSTEM task persistence).
- **Web Shield** — URLhaus host lookup with parent-domain matching.

## Tools

Wi-Fi Inspector (encryption grade, router port exposure, DNS hijack check,
SMBv1, ARP device sweep with OUI vendor lookup) · System Health (UAC,
BitLocker, RDP, pending updates, resources) · Junk Cleanup (10 targets +
Recycle Bin via `SHQueryRecycleBin`) · Startup Manager (Run keys + Startup
folders, each entry scanned) · Breach Monitor · Boot-Time Scan · Virus Chest
(XOR-obfuscated, restore adds an exclusion, delete overwrites first) ·
scheduled scans · exclusions · activity log.

## Layout

```
aegis.py              entry point (DPI awareness, window)
engine/
  detect.py           5-layer scanning engine
  trust.py            Authenticode + catalog signature verification
  scanner.py          threaded scan jobs, quarantine chest
  shields.py          real-time protection
  tools.py            Wi-Fi, health, junk, startup, breach
  intel.py            abuse.ch + YARA Forge updater
  store.py            SQLite persistence
  api.py              JS bridge
ui/                   index.html + app.css + 5 JS modules
```

Data lives in `%LOCALAPPDATA%\Aegis` (db, chest, definitions).

## Tests

```
python t_engine.py    # detection + System32 false-positive sweep
python t_api.py       # 36 API checks incl. quarantine round-trip
python t_render.py    # headless render of all 12 pages via Playwright
```

## Intelligence sources

abuse.ch MalwareBazaar (hashes) · abuse.ch URLhaus (malicious hosts) ·
YARA Forge / YARA-HQ (rules) · XposedOrNot (breach lookups).

## Honest limitations

No kernel driver, so this is user-mode only: it cannot block a write the way a
minifilter can — it reacts immediately after. Real-time interception depends on
watchdog events. It is not a replacement for a certified AV on a production
machine; it is a genuinely functional one built from open sources.
