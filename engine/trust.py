"""Aegis Security — Authenticode trust verification.

pefile only sees the *embedded* security directory. Most Windows system
binaries (notepad.exe, etc.) are **catalog-signed**: VA=0, size=0 in the PE
header, yet fully trusted. Checking only the directory produces mass false
positives on clean OS files.

This module calls WinVerifyTrust (wintrust.dll), which resolves embedded AND
catalog signatures exactly like Explorer's Digital Signatures tab. Results are
cached because the call costs 5-30 ms.
"""
from __future__ import annotations

import ctypes
import os
import threading
from ctypes import wintypes

# ---------------------------------------------------------------- constants
WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2
WTD_SAFER_FLAG = 0x00000100
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000

TRUST_E_NOSIGNATURE = 0x800B0100
TRUST_E_BAD_DIGEST = 0x80096010
TRUST_E_EXPLICIT_DISTRUST = 0x800B0111
CERT_E_REVOKED = 0x800B010C
CERT_E_UNTRUSTEDROOT = 0x800B0109
CERT_E_EXPIRED = 0x800B0101

WINTRUST_ACTION_GENERIC_VERIFY_V2 = "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}"


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", ctypes.c_byte * 8)]


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", ctypes.POINTER(GUID))]


class WINTRUST_CATALOG_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("dwCatalogVersion", wintypes.DWORD),
                ("pcwszCatalogFilePath", wintypes.LPCWSTR),
                ("pcwszMemberTag", wintypes.LPCWSTR),
                ("pcwszMemberFilePath", wintypes.LPCWSTR),
                ("hMemberFile", wintypes.HANDLE),
                ("pbCalculatedFileHash", ctypes.POINTER(ctypes.c_byte)),
                ("cbCalculatedFileHash", wintypes.DWORD),
                ("pcCatalogContext", ctypes.c_void_p),
                ("hCatAdmin", wintypes.HANDLE)]


class CATALOG_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("wszCatalogFile", ctypes.c_wchar * 260)]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p),
                ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD),
                ("dwUnionChoice", wintypes.DWORD),
                ("pFile", ctypes.c_void_p),
                ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", wintypes.LPCWSTR),
                ("dwProvFlags", wintypes.DWORD),
                ("dwUIContext", wintypes.DWORD),
                ("pSignatureSettings", ctypes.c_void_p)]


def _guid_from_string(s: str) -> GUID:
    g = GUID()
    ole32 = ctypes.windll.ole32
    ole32.CLSIDFromString(wintypes.LPCWSTR(s), ctypes.byref(g))
    return g


_cache: dict[str, dict] = {}
_lock = threading.Lock()

try:
    _wintrust = ctypes.windll.wintrust
    _wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID),
                                         ctypes.c_void_p]
    _wintrust.WinVerifyTrust.restype = ctypes.c_long
    _ACTION = _guid_from_string(WINTRUST_ACTION_GENERIC_VERIFY_V2)
    _AVAILABLE = True
except Exception:                                                # pragma: no cover
    _AVAILABLE = False
    _ACTION = None


# ---- Catalog API prototypes -------------------------------------------------
# CRITICAL: ctypes defaults every unprototyped return value to C int (32-bit).
# CryptCATAdmin* return 64-bit HANDLEs, so without an explicit restype the
# handle is silently truncated and every downstream call fails. This is why
# catalog-signed system binaries were being reported "unsigned".
_CAT_OK = False
if _AVAILABLE:
    try:
        _ws = _wintrust
        _k32 = ctypes.windll.kernel32

        _ws.CryptCATAdminAcquireContext.argtypes = [
            ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(GUID), wintypes.DWORD]
        _ws.CryptCATAdminAcquireContext.restype = wintypes.BOOL

        try:
            _ws.CryptCATAdminAcquireContext2.argtypes = [
                ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(GUID),
                wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD]
            _ws.CryptCATAdminAcquireContext2.restype = wintypes.BOOL
            _HAS_CTX2 = True
        except AttributeError:
            _HAS_CTX2 = False

        try:
            _ws.CryptCATAdminCalcHashFromFileHandle2.argtypes = [
                wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
                ctypes.c_void_p, wintypes.DWORD]
            _ws.CryptCATAdminCalcHashFromFileHandle2.restype = wintypes.BOOL
            _HAS_HASH2 = True
        except AttributeError:
            _HAS_HASH2 = False

        _ws.CryptCATAdminCalcHashFromFileHandle.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p, wintypes.DWORD]
        _ws.CryptCATAdminCalcHashFromFileHandle.restype = wintypes.BOOL

        _ws.CryptCATAdminEnumCatalogFromHash.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
            wintypes.DWORD, ctypes.c_void_p]
        _ws.CryptCATAdminEnumCatalogFromHash.restype = wintypes.HANDLE

        _ws.CryptCATCatalogInfoFromContext.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(CATALOG_INFO), wintypes.DWORD]
        _ws.CryptCATCatalogInfoFromContext.restype = wintypes.BOOL

        _ws.CryptCATAdminReleaseCatalogContext.argtypes = [
            wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD]
        _ws.CryptCATAdminReleaseCatalogContext.restype = wintypes.BOOL

        _ws.CryptCATAdminReleaseContext.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        _ws.CryptCATAdminReleaseContext.restype = wintypes.BOOL

        _k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                     ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                     wintypes.HANDLE]
        _k32.CreateFileW.restype = wintypes.HANDLE
        _k32.CloseHandle.argtypes = [wintypes.HANDLE]
        _k32.CloseHandle.restype = wintypes.BOOL
        _CAT_OK = True
    except Exception:
        _CAT_OK = False


# Publishers whose signed binaries we treat as inherently trusted, so PE
# heuristics never escalate them. Signature must verify first.
TRUSTED_PUBLISHERS = (
    "microsoft windows", "microsoft corporation", "microsoft windows publisher",
    "microsoft windows hardware compatibility publisher",
    "google llc", "mozilla corporation", "apple inc", "adobe inc",
    "valve corp", "nvidia corporation", "intel corporation",
    "advanced micro devices", "realtek semiconductor", "lenovo",
    "dell inc", "hp inc", "python software foundation", "oracle america",
    "discord inc", "spotify ab", "dropbox, inc",
)


def verify(path: str) -> dict:
    """Return {signed, trusted, status, code}. Handles catalog signatures."""
    try:
        key = os.path.normcase(os.path.abspath(path))
        st = os.stat(path)
        key = f"{key}|{st.st_mtime_ns}|{st.st_size}"
    except OSError:
        return {"signed": False, "trusted": False, "status": "unreadable", "code": -1}

    with _lock:
        hit = _cache.get(key)
    if hit is not None:
        return hit

    result = _verify_uncached(path)

    with _lock:
        if len(_cache) > 4000:
            _cache.clear()
        _cache[key] = result
    return result


def _verify_uncached(path: str) -> dict:
    if not _AVAILABLE:
        return {"signed": False, "trusted": False, "status": "wintrust unavailable",
                "code": -1}

    res = _verify_embedded(path)
    if res["trusted"] or res["status"] in ("tampered", "certificate revoked",
                                           "explicitly distrusted"):
        return res
    # No embedded signature (or it failed) -> try the security catalogs.
    # This is what makes notepad.exe/cmd.exe verify as trusted.
    cat = _verify_catalog(path)
    if cat is not None:
        return cat
    return res


def _verify_embedded(path: str) -> dict:
    fi = WINTRUST_FILE_INFO()
    fi.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    fi.pcwszFilePath = path
    fi.hFile = None
    fi.pgKnownSubject = None

    wd = WINTRUST_DATA()
    wd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    wd.dwUIChoice = WTD_UI_NONE
    wd.fdwRevocationChecks = WTD_REVOKE_NONE
    wd.dwUnionChoice = WTD_CHOICE_FILE
    wd.pFile = ctypes.cast(ctypes.pointer(fi), ctypes.c_void_p)
    wd.dwStateAction = WTD_STATEACTION_VERIFY
    wd.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL

    try:
        rc = _wintrust.WinVerifyTrust(None, ctypes.byref(_ACTION), ctypes.byref(wd))
    except Exception as e:
        return {"signed": False, "trusted": False, "status": f"error: {e}", "code": -1}
    finally:
        try:
            wd.dwStateAction = WTD_STATEACTION_CLOSE
            _wintrust.WinVerifyTrust(None, ctypes.byref(_ACTION), ctypes.byref(wd))
        except Exception:
            pass
    return _map_code(rc)


def _verify_catalog(path: str) -> dict | None:
    """Resolve a catalog signature (Windows component signing).

    Flow: CryptCATAdminAcquireContext2 -> CalcHashFromFileHandle2 ->
    EnumCatalogFromHash -> CatalogInfoFromContext -> WinVerifyTrust(CATALOG).
    Returns None when the file is in no catalog (caller keeps the embedded
    result), otherwise a normal verdict dict.
    """
    if not _CAT_OK:
        return None

    h_cat = wintypes.HANDLE()
    h_file = None
    cat_ctx = None
    acquired = False
    try:
        if _HAS_CTX2:
            acquired = bool(_ws.CryptCATAdminAcquireContext2(
                ctypes.byref(h_cat), None, "SHA256", None, 0))
        if not acquired:
            acquired = bool(_ws.CryptCATAdminAcquireContext(
                ctypes.byref(h_cat), None, 0))
        if not acquired:
            return None

        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x00000001
        OPEN_EXISTING = 3
        INVALID = ctypes.c_void_p(-1).value

        h_file = _k32.CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                                  None, OPEN_EXISTING, 0, None)
        if not h_file or h_file == INVALID:
            return None

        size = wintypes.DWORD(0)
        if _HAS_HASH2:
            _ws.CryptCATAdminCalcHashFromFileHandle2(
                h_cat, h_file, ctypes.byref(size), None, 0)
            if size.value == 0:
                return None
            buf = (ctypes.c_byte * size.value)()
            if not _ws.CryptCATAdminCalcHashFromFileHandle2(
                    h_cat, h_file, ctypes.byref(size), buf, 0):
                return None
        else:
            _ws.CryptCATAdminCalcHashFromFileHandle(
                h_file, ctypes.byref(size), None, 0)
            if size.value == 0:
                return None
            buf = (ctypes.c_byte * size.value)()
            if not _ws.CryptCATAdminCalcHashFromFileHandle(
                    h_file, ctypes.byref(size), buf, 0):
                return None

        cat_ctx = _ws.CryptCATAdminEnumCatalogFromHash(
            h_cat, buf, size.value, 0, None)
        if not cat_ctx:
            return None                        # not catalog-signed at all

        ci = CATALOG_INFO()
        ci.cbStruct = ctypes.sizeof(CATALOG_INFO)
        if not _ws.CryptCATCatalogInfoFromContext(cat_ctx, ctypes.byref(ci), 0):
            return None
        catalog_file = ci.wszCatalogFile
        tag = "".join("%02X" % (b & 0xFF) for b in buf)

        wci = WINTRUST_CATALOG_INFO()
        wci.cbStruct = ctypes.sizeof(WINTRUST_CATALOG_INFO)
        wci.dwCatalogVersion = 0
        wci.pcwszCatalogFilePath = catalog_file
        wci.pcwszMemberTag = tag
        wci.pcwszMemberFilePath = path
        wci.hMemberFile = h_file
        wci.pbCalculatedFileHash = ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte))
        wci.cbCalculatedFileHash = size.value
        wci.pcCatalogContext = None
        wci.hCatAdmin = h_cat

        wd = WINTRUST_DATA()
        wd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        wd.dwUIChoice = WTD_UI_NONE
        wd.fdwRevocationChecks = WTD_REVOKE_NONE
        wd.dwUnionChoice = 2                       # WTD_CHOICE_CATALOG
        wd.pFile = ctypes.cast(ctypes.pointer(wci), ctypes.c_void_p)
        wd.dwStateAction = WTD_STATEACTION_VERIFY
        wd.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL

        rc = _wintrust.WinVerifyTrust(None, ctypes.byref(_ACTION), ctypes.byref(wd))
        try:
            wd.dwStateAction = WTD_STATEACTION_CLOSE
            _wintrust.WinVerifyTrust(None, ctypes.byref(_ACTION), ctypes.byref(wd))
        except Exception:
            pass

        out = _map_code(rc)
        if out["trusted"]:
            out["status"] = "valid (catalog)"
            out["catalog"] = os.path.basename(catalog_file)
        return out
    except Exception:
        return None
    finally:
        try:
            if cat_ctx:
                _ws.CryptCATAdminReleaseCatalogContext(h_cat, cat_ctx, 0)
        except Exception:
            pass
        try:
            if h_file:
                _k32.CloseHandle(h_file)
        except Exception:
            pass
        try:
            if acquired and h_cat:
                _ws.CryptCATAdminReleaseContext(h_cat, 0)
        except Exception:
            pass


def _map_code(rc: int) -> dict:
    code = rc & 0xFFFFFFFF
    if rc == 0:
        return {"signed": True, "trusted": True, "status": "valid", "code": 0}
    if code == TRUST_E_NOSIGNATURE:
        return {"signed": False, "trusted": False, "status": "unsigned", "code": code}
    if code == TRUST_E_BAD_DIGEST:
        return {"signed": True, "trusted": False, "status": "tampered", "code": code}
    if code == TRUST_E_EXPLICIT_DISTRUST:
        return {"signed": True, "trusted": False, "status": "explicitly distrusted",
                "code": code}
    if code == CERT_E_REVOKED:
        return {"signed": True, "trusted": False, "status": "certificate revoked",
                "code": code}
    if code == CERT_E_UNTRUSTEDROOT:
        return {"signed": True, "trusted": False, "status": "untrusted root", "code": code}
    if code == CERT_E_EXPIRED:
        return {"signed": True, "trusted": False, "status": "certificate expired",
                "code": code}
    return {"signed": False, "trusted": False, "status": f"unverified (0x{code:08X})",
            "code": code}


def publisher(path: str) -> str:
    """Best-effort signer name from the embedded certificate (may be empty for
    catalog-signed files; trust status is what matters for suppression)."""
    try:
        import pefile
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]])
        d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        if d.VirtualAddress == 0 or d.Size == 0:
            pe.close()
            return ""
        blob = pe.write()[d.VirtualAddress + 8: d.VirtualAddress + d.Size]
        pe.close()
        text = bytes(blob).decode("latin-1", "ignore")
        import re
        for m in re.finditer(r"[\x20-\x7e]{6,}", text):
            s = m.group(0)
            for tp in TRUSTED_PUBLISHERS:
                if tp in s.lower():
                    return s.strip()
        return ""
    except Exception:
        return ""


def is_os_binary(path: str) -> bool:
    """True for files inside the Windows directory — combined with a valid
    signature this is a strong clean signal."""
    try:
        p = os.path.normcase(os.path.abspath(path))
        win = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))
        return p.startswith(win)
    except Exception:
        return False
