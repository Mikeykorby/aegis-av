"""Aegis Security — multi-layer detection core.

Layers, in order of cost:
  0. Exclusions / size gate
  1. EICAR + known-hash blocklist (MD5/SHA256 from abuse.ch MalwareBazaar)
  2. Static heuristics (extension spoofing, script obfuscation, macro docs)
  3. PE structural analysis (entropy, packers, suspicious imports, no signature)
  4. YARA (YARA Forge core package, ~5k community rules)
Each layer yields Detections; the highest severity wins.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import struct
import zipfile
from dataclasses import dataclass, field, asdict

from . import store
from . import trust

# ------------------------------------------------------------------ tables
# Standard EICAR anti-malware test string (68 bytes). Exactly ONE backslash
# after the '4'. Built from a single b"\\" so there is no escaping ambiguity
# (a literal b"\\" in source is one byte; doubling it made EICAR unmatchable).
EICAR = b"X5O!P%@AP[4" + b"\\" + b"PZX54(P^)7)}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

SEV_ORDER = {"clean": 0, "low": 1, "pup": 2, "medium": 3, "high": 4, "critical": 5}

EXECUTABLE_EXT = {".exe", ".dll", ".sys", ".scr", ".com", ".ocx", ".cpl", ".drv", ".efi"}
SCRIPT_EXT = {".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta",
              ".bat", ".cmd", ".sh", ".py", ".jar", ".lnk", ".reg"}
DOC_EXT = {".doc", ".docm", ".xls", ".xlsm", ".xlsb", ".ppt", ".pptm", ".docx", ".xlsx", ".pptx"}
ARCHIVE_EXT = {".zip", ".7z", ".rar", ".gz", ".tar", ".cab", ".iso", ".vhd"}
SCANNABLE = EXECUTABLE_EXT | SCRIPT_EXT | DOC_EXT | ARCHIVE_EXT | {
    ".msi", ".pdf", ".rtf", ".swf", ".chm", ".apk", ".pif", ".msc", ".gadget", ".inf", ".job"}

# Imports commonly abused by injectors / droppers / RATs.
SUSPECT_IMPORTS = {
    "virtualallocex": ("Remote memory allocation", 3),
    "writeprocessmemory": ("Remote process write", 4),
    "createremotethread": ("Remote thread injection", 5),
    "ntunmapviewofsection": ("Process hollowing primitive", 5),
    "setwindowshookexa": ("Global hook (keylogging)", 3),
    "setwindowshookexw": ("Global hook (keylogging)", 3),
    "getasynckeystate": ("Keystroke polling", 3),
    "urldownloadtofilea": ("Downloader behaviour", 4),
    "urldownloadtofilew": ("Downloader behaviour", 4),
    "winexec": ("Direct process launch", 2),
    "shellexecutea": ("Shell execution", 1),
    "isdebuggerpresent": ("Anti-debug check", 2),
    "checkremotedebuggerpresent": ("Anti-debug check", 2),
    "ntsetinformationthread": ("Debugger evasion", 3),
    "cryptencrypt": ("Bulk encryption (ransomware)", 3),
    "cryptgenrandom": ("Key generation", 1),
    "findfirstfilew": ("Filesystem enumeration", 1),
    "adjusttokenprivileges": ("Privilege escalation", 2),
    "openscmanagerа": ("Service manager access", 2),
    "createservicew": ("Service persistence", 3),
    "regsetvalueexw": ("Registry persistence", 2),
    "wnetaddconnection2w": ("Network share access", 2),
    "getprocaddress": ("Dynamic API resolution", 1),
    "loadlibrarya": ("Dynamic library load", 1),
    "internetopena": ("Network connection (wininet)", 2),
    "internetopenurla": ("Network fetch (wininet)", 3),
    "internetreadfile": ("Network read (wininet)", 2),
    "urlopen": ("Network fetch (winhttp)", 3),
    "createprocessa": ("Process spawn", 2),
    "createprocessw": ("Process spawn", 2),
    "system": ("Shell command execution", 2),
    "regsvr32": ("COM surrogate loading", 2),
    "bitstransfer": ("BITS downloader", 3),
    "coinfilterstartup": ("IE/Edge exec vector", 4),
}

PACKER_SECTIONS = {
    ".aspack": "ASPack", ".adata": "ASPack", "upx0": "UPX", "upx1": "UPX", "upx2": "UPX",
    ".upx": "UPX", "fsg!": "FSG", ".mpress1": "MPRESS", ".mpress2": "MPRESS",
    ".themida": "Themida", ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    "petite": "Petite", ".nsp0": "NsPack", ".packed": "Generic packer", "pebundle": "PEBundle",
    ".enigma1": "Enigma", ".enigma2": "Enigma", ".boom": "Boomerang", "kkrunchy": "kkrunchy",
}

SCRIPT_PATTERNS: list[tuple[str, str, int]] = [
    (r"(?i)frombase64string\s*\(", "Base64 payload decode", 3),
    (r"(?i)\[system\.convert\]::frombase64", "Base64 payload decode", 3),
    (r"(?i)invoke-expression|(?<![\\w-])iex(?![\\w-])", "Dynamic code execution (IEX)", 3),
    (r"(?i)downloadstring|downloadfile|invoke-webrequest|start-bitstransfer",
     "Remote payload download", 4),
    (r"(?i)-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{40,}", "Encoded PowerShell command", 5),
    (r"(?i)-w(?:indowstyle)?\s+hidden|-nop(?:rofile)?\b", "Hidden/no-profile execution", 2),
    (r"(?i)wscript\.shell|shell\.application", "WSH shell object", 2),
    (r"(?i)set-mppreference\s+-disable|add-mppreference\s+-exclusionpath",
     "Defender tampering", 5),
    (r"(?i)vssadmin\s+delete\s+shadows|wbadmin\s+delete|bcdedit.+recoveryenabled\s+no",
     "Shadow copy destruction (ransomware)", 5),
    (r"(?i)cipher\s*/w|\bformat\s+[c-z]:", "Destructive disk operation", 4),
    (r"(?i)reflection\.assembly\]::load|\[appdomain\]::currentdomain", "In-memory .NET load", 4),
    (r"(?i)certutil(\.exe)?\s+.*-decode|-urlcache", "LOLBin certutil abuse", 4),
    (r"(?i)mshta\s+(http|javascript:)", "LOLBin mshta abuse", 4),
    (r"(?i)rundll32\s+javascript:", "LOLBin rundll32 abuse", 5),
    (r"(?i)schtasks\s+/create.+/ru\s+system", "SYSTEM scheduled-task persistence", 4),
    (r"(?i)new-object\s+net\.webclient", "WebClient downloader", 3),
    (r"(?i)bypass\s*-scope|executionpolicy\s+bypass", "Execution policy bypass", 3),
    (r"(?i)add-type\s+-memberdefinition.+kernel32", "P/Invoke into kernel32", 4),
    (r"(?i)\$env:temp.+\\.exe|%temp%\\?\\w+\.exe", "Drops executable into TEMP", 2),
    (r"(?i)netsh\s+advfirewall\s+set.+off", "Firewall disable", 4),
    # expansion of real-world tradecraft
    (r"(?i)regsvr32(\.exe)?\s+/s\s+/u\s+/i:", "Regsvr32 sct payload (Squiblydoo)", 5),
    (r"(?i)msdt\.exe\s+-?-?", "MSDT (Follina) vector", 5),
    (r"(?i)cmstp(\.exe)?\s+/s\s+/ni", "CMSTP UAC bypass", 4),
    (r"(?i)\bverclsid\.exe\b", "Verclsid COM probing", 3),
    (r"(?i)bitsadmin(\.exe)?\s+/transfer", "BITSAdmin downloader", 4),
    (r"(?i)control\.exe\s+/name\s+microsoft\.defaultprograms", "Control-panel hijack", 2),
    (r"(?i)\.downloadstring\(|\.downloadfile\(|\.uploadstring\(", "WebClient/IRM download", 3),
    (r"(?i)os\.system\(|subprocess\.(call|popen|run)\(|exec\(|eval\(",
     "Python exec/subprocess/eval", 3),
    (r"(?i)cmd(\.exe)?\s*/[ck]\s", "Hidden cmd.exe payload (/c /k)", 3),
    (r"(?i)powershell(\.exe)?\s*-[a-z]+\s", "PowerShell child launch", 2),
    (r"(?i)start-process|start-job|invoke-command", "Process/spawn cmdlet", 2),
    (r"(?i)register-clmscript(?:debug)?|set-authenticodesignature", "Live script signing/load", 3),
    (r"(?i)new-object\s+system\.net\.sockets\.tcpclient", "Reverse-shell socket", 5),
    (r"(?i)while\(\$true\)|for\(\;\,", "Loop construct (possible dropper)", 1),
    (r"(?i)\[system\.diagnostics\.process\]::start", ".NET process start", 2),
]

BAD_NAME_TOKENS = re.compile(
    r"(?i)(keygen|kms(pico|auto)|crack(ed)?|patcher|nulled|activator|hacktool|"
    r"trainer|autoclicker|rat[-_ ]?client|stealer|logger|token[-_ ]?grabber|miner|"
    r"keylogger|cryptominer|backdoor|trojan|exploit|payload|dropper|worm|rootkit|"
    r"botnet|spyware|adware|scareware|ransom|wanna|locky|crypt0|gandcrab|"
    r"njrat|quasar|asyncrat|remcos|loki|azorult|redline|raccoon|vidar|formbook|"
    r"agenttesla|emotet|trickbot|qakbot|cobalt|metasploit|cobaltstrike|empire|"
    r"mimikatz|psexec|bloodhound|nanohttp|havij|sqlmap|dogecoin|bitcoin|monero)")

DOUBLE_EXT = re.compile(
    r"(?i)\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|mp4|mp3|zip)\s*\.(exe|scr|com|bat|cmd|pif|vbs|js|lnk)$")

RLO = "\u202e"  # right-to-left override — classic extension spoof


@dataclass
class Detection:
    name: str
    severity: str          # low | pup | medium | high | critical
    engine: str            # signature | heuristic | pe | yara | reputation
    reason: str = ""
    score: int = 0


@dataclass
class Verdict:
    path: str
    size: int = 0
    sha256: str = ""
    md5: str = ""
    clean: bool = True
    severity: str = "clean"
    score: int = 0
    signature: str = ""
    detections: list[Detection] = field(default_factory=list)
    error: str = ""

    @property
    def name(self) -> str:
        if not self.detections:
            return ""
        top = max(self.detections, key=lambda d: SEV_ORDER.get(d.severity, 0))
        return top.name

    def to_dict(self) -> dict:
        d = asdict(self)
        d["name"] = self.name
        return d


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    e = 0.0
    for c in counts:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return e


# ============================================================== the engine
class Engine:
    """Loads intel + rules once, then scan_file() is thread-safe."""

    def __init__(self, data_dir: str | None = None):
        self.data_dir = data_dir or store.DATA_DIR
        self.yara_rules = None
        self.md5_set: set[str] = set()
        self.sha_set: set[str] = set()
        self.url_hosts: set[str] = set()
        self.ip_set: set[str] = set()          # plain + CIDR IP indicators
        self.yara_error = ""
        self.rule_count = 0
        self.load()

    # ------------------------------------------------------------- loading
    def load(self) -> None:
        self._load_yara()
        self._load_hashes()
        self._load_urls()
        self._load_ips()

    def _load_yara(self) -> None:
        try:
            import yara
        except Exception as e:                                   # pragma: no cover
            self.yara_error = f"yara-python unavailable: {e}"
            return
        compiled = os.path.join(self.data_dir, "core.yarc")
        source = os.path.join(self.data_dir, "core.yar")
        try:
            if os.path.exists(compiled):
                self.yara_rules = yara.load(compiled)
            elif os.path.exists(source):
                self.yara_rules = yara.compile(source)
                self.yara_rules.save(compiled)
            else:
                self.yara_error = "no rule package installed"
                return
            meta = os.path.join(self.data_dir, "rules.meta")
            if os.path.exists(meta):
                try:
                    self.rule_count = int(open(meta).read().strip() or 0)
                except Exception:
                    self.rule_count = 0
        except Exception as e:
            self.yara_error = str(e)
            self.yara_rules = None

    def _load_hashes(self) -> None:
        for fn, target in (("md5.txt", self.md5_set), ("sha256.txt", self.sha_set)):
            p = os.path.join(self.data_dir, fn)
            if not os.path.exists(p):
                continue
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        line = line.strip().strip('"').lower()
                        if line and not line.startswith("#") and len(line) in (32, 64):
                            target.add(line)
            except Exception:
                pass

    def _load_urls(self) -> None:
        p = os.path.join(self.data_dir, "urlhaus.txt")
        if not os.path.exists(p):
            return
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    m = re.match(r"https?://([^/\s]+)", line)
                    if m:
                        self.url_hosts.add(m.group(1).lower())
        except Exception:
            pass
        # ThreatFox recent export carries fresh malware C2 / payload domains
        # and URLs; parse both so the Web Shield blocks them.
        tf = os.path.join(self.data_dir, "threatfox_domains.txt")
        if os.path.exists(tf):
            try:
                from .intel import _parse_threatfox_iocs
                _parse_threatfox_iocs(tf, self.url_hosts)
            except Exception:
                pass

    def _load_ips(self) -> None:
        """Load every IP blocklist into ip_set (plain IPs + CIDR ranges).
        Query-side matching (check_ip) expands a CIDR to its covered /24s so
        lookup stays a cheap set membership test."""
        from .intel import _parse_ips
        for fn in ("feodo.txt", "sslbl.txt", "spamhaus_drop.txt",
                   "spamhaus_edrop.txt", "blocklistde.txt"):
            p = os.path.join(self.data_dir, fn)
            if os.path.exists(p):
                _parse_ips(p, self.ip_set)

    @property
    def intel_size(self) -> int:
        return (len(self.md5_set) + len(self.sha_set) + len(self.url_hosts)
                + len(self.ip_set) + self.rule_count)

    # --------------------------------------------------------------- utils
    @staticmethod
    def should_scan(path: str, deep: bool = False) -> bool:
        """Extension gate for bulk scans.

        `deep` scans everything. Otherwise we take risky extensions at any size,
        plus ANY small file — malware is routinely dropped with a harmless
        extension (EICAR as .txt, payloads as .dat/.log), and hashing something
        under a few MB is cheap enough to be worth it.
        """
        if deep:
            return True
        ext = os.path.splitext(path)[1].lower()
        if ext in SCANNABLE or ext == "":
            return True
        try:
            return os.path.getsize(path) <= 4 * 1024 * 1024
        except OSError:
            return False

    # ---------------------------------------------------------- main entry
    def scan_file(self, path: str, deep: bool = False,
                  pup: bool = True, max_mb: int = 64) -> Verdict:
        # Never scan Aegis' own Virus Chest files — they are XOR-obfuscated
        # (high entropy by design) and re-detecting them would loop them back
        # into the chest. Skip by extension and by location.
        _ext = os.path.splitext(path)[1].lower()
        if _ext in (".aegis", ".aegls", ".meta") or store.CHEST_DIR.lower() in path.lower():
            v = Verdict(path=path)
            v.clean = True
            return v
        if _ext in (".zip", ".apk", ".jar", ".docx",
                                                  ".xlsx", ".pptx", ".ods", ".odt"):
            return self._scan_container(path, deep=deep, pup=pup, max_mb=max_mb)
        return self._scan_plain(path, deep=deep, pup=pup, max_mb=max_mb)

    def _scan_container(self, path: str, deep: bool, pup: bool, max_mb: int) -> Verdict:
        """Scan a container (zip-based + docx/xlsx) by exploding it in memory and
        running the full per-file pipeline on each entry. Catches payloads nested
        in archives, which the flat extension gate previously let through."""
        v = Verdict(path=path)
        try:
            st = os.stat(path)
        except OSError as e:
            v.error = str(e); return v
        v.size = st.st_size
        dets: list[Detection] = []
        scanned = 0
        try:
            import zipfile
            with zipfile.ZipFile(path) as z:
                for info in z.infolist():
                    if info.is_dir() or info.file_size > max_mb * 1024 * 1024:
                        continue
                    try:
                        data = z.read(info.filename)
                    except Exception:
                        continue
                    scanned += 1
                    # spoofed extension inside the archive (e.g. .pdf.exe)
                    if DOUBLE_EXT.search(info.filename.split("/")[-1]):
                        dets.append(Detection("Trojan:Zip/DoubleExtension", "high",
                                             "heuristic", "Archive entry uses a document-like "
                                             "name with an executable extension", 7))
                    # EICAR / known hashes inside the archive
                    if EICAR in data:
                        dets.append(Detection("EICAR-Test-File", "high", "signature",
                                             "Anti-malware test string found in archive", 10))
                        continue
                    h = hashlib.sha256(data).hexdigest()
                    if h in self.sha_set:
                        dets.append(Detection("Win32:Malware-gen [MalwareBazaar]", "critical",
                                             "signature", "Hash (in archive) matches known malware", 20))
                        continue
                    # run the script/document/pe layers on the raw bytes
                    dets += self._layer_script(info.filename, data[:1024 * 1024])
                    dets += self._layer_document(info.filename, data[:1024 * 1024])
        except Exception:
            # not a zip-family container (e.g. real 7z) — fall back to raw scan
            return self._scan_plain(path, deep=deep, pup=pup, max_mb=max_mb)
        if scanned and not dets:
            v.clean = True
            return v
        v.detections = dets
        if dets:
            v.severity = max(dets, key=lambda d: SEV_ORDER.get(d.severity, 0)).severity
            v.clean = False
        return v

    def _scan_plain(self, path: str, deep: bool, pup: bool, max_mb: int) -> Verdict:
        v = Verdict(path=path)
        try:
            st = os.stat(path)
        except OSError as e:
            v.error = str(e)
            return v
        v.size = st.st_size
        if v.size == 0:
            return v
        if v.size > max_mb * 1024 * 1024:
            v.error = "skipped: exceeds size limit"
            return v

        try:
            with open(path, "rb") as fh:
                head = fh.read(1024 * 1024)          # 1 MiB window for heuristics
                h256, hmd5 = hashlib.sha256(), hashlib.md5()
                h256.update(head)
                hmd5.update(head)
                while True:
                    chunk = fh.read(1024 * 1024)
                    if not chunk:
                        break
                    h256.update(chunk)
                    hmd5.update(chunk)
            v.sha256, v.md5 = h256.hexdigest(), hmd5.hexdigest()
        except OSError as e:
            v.error = f"unreadable: {e.strerror or e}"
            return v

        dets: list[Detection] = []
        dets += self._layer_signature(path, v, head)
        dets += self._layer_filename(path)
        # Whole-file entropy is a *weak* heuristic: high entropy is normal for
        # legitimately compressed/encrypted files (installers, zips, media, and
        # Aegis' own XOR'd Virus Chest files). Only treat it as a packer tell
        # when the file is actually a PE/executable AND heuristics aren't in
        # relaxed mode — otherwise it floods the log with false positives.
        ext = os.path.splitext(path)[1].lower()
        is_aegis_own = ext in (".aegis", ".aegls") or store.CHEST_DIR.lower() in path.lower()
        if (not is_aegis_own and ext in EXECUTABLE_EXT
                and store.get("scan.heuristics", "balanced") != "relaxed"):
            try:
                with open(path, "rb") as fh:
                    full = fh.read(4 * 1024 * 1024)
                fe = entropy(full)
                if fe > 7.85:
                    dets.append(Detection("Packed:Win32/HighEntropy", "medium", "pe",
                                         f"Whole-file entropy {fe:.2f} (packed/encrypted)", 3))
            except OSError:
                pass
        if head[:2] == b"MZ":
            v.signature = trust.verify(path)["status"]
            dets += self._layer_pe(path, head, v.size)
        else:
            dets += self._layer_script(path, head)
            dets += self._layer_document(path, head)
        dets += self._layer_yara(path)

        if not pup:
            dets = [d for d in dets if d.severity != "pup"]

        v.detections = dets
        v.score = sum(d.score for d in dets)
        if dets:
            v.severity = max(dets, key=lambda d: SEV_ORDER.get(d.severity, 0)).severity
        # heuristic aggregation: several medium hints => escalate
        if v.severity in ("low", "medium") and v.score >= 9:
            v.severity = "high"
        v.clean = not dets or v.severity == "clean"
        return v

    # ------------------------------------------------------------- layer 1
    def _layer_signature(self, path: str, v: Verdict, head: bytes) -> list[Detection]:
        out = []
        if EICAR in head:
            out.append(Detection("EICAR-Test-File", "high", "signature",
                                 "Standard anti-malware test string", 10))
            return out
        if v.md5 in self.md5_set or v.sha256 in self.sha_set:
            out.append(Detection("Win32:Malware-gen [MalwareBazaar]", "critical", "signature",
                                 "Hash matches a known malware sample", 20))
        return out

    # ------------------------------------------------------------- layer 2
    def _layer_filename(self, path: str) -> list[Detection]:
        out = []
        base = os.path.basename(path)
        if RLO in base:
            out.append(Detection("Trojan:Win32/ExtSpoof.RLO", "high", "heuristic",
                                 "Right-to-left override hides the real extension", 8))
        if DOUBLE_EXT.search(base):
            out.append(Detection("Trojan:Win32/DoubleExtension", "high", "heuristic",
                                 "Document-looking name with executable extension", 7))
        if BAD_NAME_TOKENS.search(base):
            out.append(Detection("PUP:Win32/RiskTool", "pup", "heuristic",
                                 "Filename matches known risk-tool patterns", 3))
        # Shortcut (.lnk) inspection — a .lnk aimed at powershell/cmd/cscript
        # with a hidden window is the most common drive-by / email vector.
        if base.lower().endswith(".lnk"):
            try:
                tgt = self._lnk_target(path)
                if tgt:
                    low = tgt.lower()
                    if any(k in low for k in ("powershell", "cmd.exe", "cscript",
                                             "wscript", "mshta", "rundll32", "regsvr32",
                                             "wscript.shell")):
                        out.append(Detection("Trojan:Win32/LnkExec", "high", "heuristic",
                                             "Shortcut launches a script host: " + tgt[:90], 7))
            except Exception:
                pass
        return out

    @staticmethod
    def _lnk_target(path: str) -> str:
        try:
            import win32com.shell.shell as shell  # type: ignore
            from win32com.shell import shellcon  # type: ignore
            return shell.SHGetShortcutTarget(path) or ""
        except Exception:
            # Fallback: parse the shell link for the command line.
            try:
                with open(path, "rb") as fh:
                    data = fh.read()
                s = data.decode("latin-1", "ignore")
                for tok in ("powershell", "cmd.exe", "cscript", "wscript", "mshta",
                            "rundll32", "regsvr32"):
                    i = s.lower().find(tok)
                    if i >= 0:
                        return s[i:i + 120]
            except Exception:
                pass
            return ""


    # ------------------------------------------------------------- layer 3
    def _layer_pe(self, path: str, head: bytes, size: int) -> list[Detection]:
        out: list[Detection] = []
        try:
            import pefile
        except Exception:
            return out

        # --- Authenticode gate -------------------------------------------
        # Catalog-signed OS binaries (notepad.exe et al.) have an EMPTY
        # security directory, so pefile alone reports them unsigned. Ask
        # WinVerifyTrust, which resolves catalogs, before running heuristics.
        sig = trust.verify(path)
        if sig["trusted"]:
            # A validly signed binary cannot be judged by API imports alone —
            # that is how real products avoid flagging half of System32.
            # Only tampering/revocation is reportable here; YARA still runs.
            return out
        if sig["status"] == "tampered":
            out.append(Detection("Trojan:Win32/TamperedSignature", "critical", "pe",
                                 "Digital signature does not match file contents — "
                                 "the binary was modified after signing", 12))
        elif sig["status"] in ("certificate revoked", "explicitly distrusted"):
            out.append(Detection("Trojan:Win32/RevokedCert", "high", "pe",
                                 f"Code-signing certificate is {sig['status']}", 7))

        try:
            pe = pefile.PE(path, fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
            ])
        except Exception:
            return out

        try:
            # -- packers / abnormal sections
            high_ent = 0
            for s in pe.sections:
                nm = s.Name.rstrip(b"\x00").decode("latin-1", "ignore").lower()
                if nm in PACKER_SECTIONS:
                    out.append(Detection(f"Packed:Win32/{PACKER_SECTIONS[nm]}", "low", "pe",
                                         f"Section '{nm}' indicates {PACKER_SECTIONS[nm]}", 2))
                try:
                    e = s.get_entropy()
                except Exception:
                    e = 0
                if e > 7.2 and s.SizeOfRawData > 4096:
                    high_ent += 1
                if s.Characteristics & 0xE0000000 == 0xE0000000:
                    out.append(Detection("Suspicious:Win32/RWXSection", "medium", "pe",
                                         f"Section '{nm}' is read+write+execute", 3))
            if high_ent >= 2:
                out.append(Detection("Packed:Win32/HighEntropy", "low", "pe",
                                     f"{high_ent} sections with entropy > 7.2 (packed/encrypted)", 2))

            # -- imports
            hits: list[tuple[str, int]] = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if not imp.name:
                            continue
                        nm = imp.name.decode("latin-1", "ignore").lower()
                        if nm in SUSPECT_IMPORTS:
                            desc, w = SUSPECT_IMPORTS[nm]
                            hits.append((desc, w))
                total = sum(w for _, w in hits)
                if total >= 9:
                    uniq = sorted({d for d, _ in hits})[:4]
                    out.append(Detection("Trojan:Win32/Injector.Heur", "high", "pe",
                                         "Injection-capable API set: " + ", ".join(uniq), 6))
                elif total >= 5:
                    uniq = sorted({d for d, _ in hits})[:4]
                    out.append(Detection("Suspicious:Win32/BehaviorAPI", "medium", "pe",
                                         "Suspicious API set: " + ", ".join(uniq), 3))
            elif size > 20000:
                out.append(Detection("Packed:Win32/NoImports", "medium", "pe",
                                     "Import table missing or hidden — typical of packers", 3))

            # -- authenticode presence (already verified above as untrusted)
            if hits:
                out.append(Detection("Unsigned:Win32/Binary", "low", "pe",
                                     f"Binary is {sig['status']} and uses sensitive APIs", 1))

            # -- TLS callbacks (anti-analysis)
            if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS:
                out.append(Detection("Suspicious:Win32/TLSCallback", "low", "pe",
                                     "TLS callback present (code runs before main)", 2))
        finally:
            try:
                pe.close()
            except Exception:
                pass
        return out

    # ------------------------------------------------------------- layer 4
    def _layer_script(self, path: str, head: bytes) -> list[Detection]:
        ext = os.path.splitext(path)[1].lower()
        if ext not in SCRIPT_EXT and b"powershell" not in head[:4096].lower():
            return []
        try:
            text = head.decode("utf-8", "ignore")
            if text.count("\x00") > len(text) // 4:      # UTF-16
                text = head.decode("utf-16", "ignore")
        except Exception:
            return []
        out, total = [], 0
        seen = set()
        for pat, desc, w in SCRIPT_PATTERNS:
            if re.search(pat, text) and desc not in seen:
                seen.add(desc)
                total += w
                out.append(Detection(f"Script:Heur/{desc.split()[0]}", "low", "heuristic", desc, w))
        if not out:
            return []
        # collapse into one meaningful detection
        reasons = "; ".join(d.reason for d in out[:5])
        if total >= 9:
            sev, nm = "critical", "Trojan:Script/Downloader.Obf"
        elif total >= 6:
            sev, nm = "high", "Trojan:Script/Suspicious.Heur"
        elif total >= 3:
            sev, nm = "medium", "Suspicious:Script/Behaviour"
        else:
            sev, nm = "low", "Suspicious:Script/Minor"
        return [Detection(nm, sev, "heuristic", reasons, total)]

    def _layer_document(self, path: str, head: bytes) -> list[Detection]:
        ext = os.path.splitext(path)[1].lower()
        if ext not in DOC_EXT:
            return []
        out = []
        if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":       # OLE2
            low = head.lower()
            if b"vba" in low or b"macros" in low:
                out.append(Detection("Suspicious:Doc/Macro", "medium", "heuristic",
                                     "Legacy Office document containing VBA macros", 4))
            if b"autoopen" in low or b"document_open" in low or b"workbook_open" in low:
                out.append(Detection("Trojan:Doc/AutoMacro", "high", "heuristic",
                                     "Macro configured to run automatically on open", 6))
        elif head[:2] == b"PK":
            try:
                with zipfile.ZipFile(path) as z:
                    names = z.namelist()
                    if any("vbaProject.bin" in n for n in names):
                        out.append(Detection("Suspicious:Doc/OOXMLMacro", "medium", "heuristic",
                                             "OOXML document embeds a VBA project", 4))
                    if any(n.endswith(".bin") and "oleObject" in n for n in names):
                        out.append(Detection("Suspicious:Doc/EmbeddedOLE", "medium", "heuristic",
                                             "Embedded OLE object (payload carrier)", 3))
            except Exception:
                pass
        return out

    # ------------------------------------------------------------- layer 5
    def _layer_yara(self, path: str) -> list[Detection]:
        if self.yara_rules is None:
            return []
        try:
            matches = self.yara_rules.match(path, timeout=20)
        except Exception:
            return []
        out = []
        for m in matches[:6]:
            meta = getattr(m, "meta", {}) or {}
            score = int(meta.get("score", 70) or 70)
            desc = str(meta.get("description", "") or "")[:160]
            if score >= 80:
                sev = "critical"
            elif score >= 70:
                sev = "high"
            elif score >= 50:
                sev = "medium"
            else:
                sev = "low"
            nm = m.rule.replace("_", ".")
            out.append(Detection(f"YARA:{nm}", sev, "yara",
                                 desc or f"Matched community rule {m.rule}",
                                 6 if sev in ("high", "critical") else 3))
        return out

    # ---------------------------------------------------------- url checks
    def check_url(self, url: str) -> dict:
        m = re.match(r"(?:https?://)?([^/\s]+)", url.strip(), re.I)
        host = (m.group(1) if m else url).lower()
        blocked = host in self.url_hosts
        if not blocked:                       # check parent domain
            parts = host.split(".")
            for i in range(1, len(parts) - 1):
                if ".".join(parts[i:]) in self.url_hosts:
                    blocked = True
                    break
        return {"host": host, "blocked": blocked,
                "reason": "Listed on URLhaus as a malware distribution host" if blocked else ""}

    # ---------------------------------------------------------- ip checks
    def check_ip(self, ip: str) -> dict:
        """Check an IPv4 against C2 / attack-source / hijacked-netblock lists.
        Plain-list match is direct; CIDR entries match any IP inside the /24
        of the CIDR's network address (good enough for blocklist precision)."""
        ip = (ip or "").strip()
        if not re.match(r"^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$", ip):
            return {"ip": ip, "blocked": False, "reason": "not an IPv4 address"}
        if ip in self.ip_set:
            return {"ip": ip, "blocked": True,
                    "reason": "Listed as a malicious / attack-source IP"}
        # CIDR membership: /24 of every stored CIDR range
        a, b, c, _ = ip.split(".")
        for entry in self.ip_set:
            if "/" in entry:
                try:
                    net, pre = entry.split("/")
                    na, nb, nc, _ = net.split(".")
                    if int(pre) >= 24 and na == a and nb == b and nc == c:
                        return {"ip": ip, "blocked": True,
                                "reason": f"Inside malicious netblock {entry}"}
                except Exception:
                    continue
        return {"ip": ip, "blocked": False, "reason": ""}
