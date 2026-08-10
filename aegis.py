"""Aegis Security — application entry point."""
from __future__ import annotations

import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def resource_path(rel: str) -> str:
    """Resolve a bundled resource path.

    When frozen with PyInstaller the app is extracted under sys._MEIPASS.
    PyInstaller 6.x collects data files into an _internal/ subfolder, so we
    check both the MEIPASS root and its _internal child. When run from source
    it's next to this file.
    """
    candidates = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(meipass)
        candidates.append(os.path.join(meipass, "_internal"))
    candidates.append(os.path.dirname(os.path.abspath(__file__)))
    for base in candidates:
        p = os.path.join(base, rel)
        if os.path.exists(p):
            return p
    # fall back to first candidate even if missing (caller handles absence)
    return os.path.join(candidates[0], rel)


# Declare DPI awareness BEFORE any window exists. On this machine Windows runs
# at 150% scaling; without this the WebView is created at a virtualised size and
# the layout is clipped on the right edge.
if sys.platform == "win32":
    import ctypes
    for _attempt in (
        lambda: ctypes.windll.shcore.SetProcessDpiAwarenessContext(-4),
        lambda: ctypes.windll.user32.SetProcessDpiAwarenessContext(-4),
        lambda: ctypes.windll.shcore.SetProcessDpiAwareness(2),
        lambda: ctypes.windll.user32.SetProcessDPIAware(),
    ):
        try:
            _attempt()
            break
        except Exception:
            continue

import webview                                                   # noqa: E402

from engine import store                                         # noqa: E402
from engine.api import Api                                       # noqa: E402
from engine.tray import TrayIcon, show_window, hide_window       # noqa: E402

UI_DIR = resource_path("ui")
INDEX = os.path.join(UI_DIR, "index.html")


_MUTEX = None
_BOOT_MUTEX = None
_SHOW_EVENT_NAME = "Local\\AegisSecurity_ShowUI"
_MUTEX_NAME = "Local\\AegisSecurity_v2"
_BOOT_MUTEX_NAME = "Local\\AegisSecurity_boot_v2"


def _boot_lock() -> bool:
    """Claim a per-process-TREE boot lock.

    Returns True for the process that should actually build the UI. A venv
    trampoline re-execs this file in a child, so both parent and child reach
    here; the parent wins the lock, and we pass the win down to the child via
    an env var so the child (which is the one that really runs the app) is
    allowed through while any *unrelated* later launch is not.
    """
    global _BOOT_MUTEX
    if sys.platform != "win32":
        return True
    if os.environ.get("_AEGIS_BOOT_OWNER") == "1":
        return True                       # trampoline child of the winner
    k = _k32()
    _BOOT_MUTEX = k.CreateMutexW(None, True, _BOOT_MUTEX_NAME)
    err = k.GetLastError()                # read immediately
    if err in (183, 5):                   # ALREADY_EXISTS / ACCESS_DENIED
        return False
    os.environ["_AEGIS_BOOT_OWNER"] = "1"
    return True


def _k32():
    import ctypes
    k = ctypes.windll.kernel32
    k.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    k.CreateMutexW.restype = ctypes.c_void_p
    k.CreateEventW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p]
    k.CreateEventW.restype = ctypes.c_void_p
    k.OpenEventW.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_wchar_p]
    k.OpenEventW.restype = ctypes.c_void_p
    k.OpenMutexW.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_wchar_p]
    k.OpenMutexW.restype = ctypes.c_void_p
    k.CloseHandle.argtypes = [ctypes.c_void_p]
    k.SetEvent.argtypes = [ctypes.c_void_p]
    k.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    k.GetLastError.restype = ctypes.c_uint
    return k


def _already_running() -> bool:
    """True when another Aegis APP is already live.

    One process must own real-time protection: two File Shields on the same
    folders fight over the same files and the loser's detections vanish. So a
    second launch does NOT start an engine — it just asks the live one to show
    its window (see _signal_show / _watch_show_requests).

    Subtlety: a venv's python.exe can be a trampoline that re-execs the real
    interpreter, so ONE launch produces a parent->child pair running this same
    file. If the parent grabbed the mutex the child would think an app was
    already running and exit, and nothing would ever start. The mutex is
    therefore only claimed once the UI actually exists (_claim_singleton, called
    from _bootstrap); here we merely probe whether a *live window* is present.
    """
    if sys.platform != "win32":
        return False
    k = _k32()
    # Probe without taking ownership: opening an existing mutex tells us a real
    # instance has booted its UI.
    SYNCHRONIZE = 0x00100000
    h = k.OpenMutexW(SYNCHRONIZE, False, _MUTEX_NAME)
    if h:
        k.CloseHandle(h)
        return True
    # No mutex yet, but a window can exist for a split second before the claim.
    return bool(_find_window("Aegis Security"))


def _claim_singleton() -> None:
    """Take ownership of the singleton mutex (called once the UI is up)."""
    global _MUTEX
    if sys.platform != "win32":
        return
    k = _k32()
    _MUTEX = k.CreateMutexW(None, True, _MUTEX_NAME)


def _signal_show() -> None:
    """Second instance: poke the running one, then exit quietly."""
    k = _k32()
    EVENT_MODIFY_STATE = 0x0002
    import ctypes
    import time as _t
    # Hand our foreground privilege to the running app so its own
    # SetForegroundWindow call is honoured rather than silently flashing.
    ASFW_ANY = -1
    try:
        ctypes.windll.user32.AllowSetForegroundWindow(ASFW_ANY)
    except Exception:
        pass
    for _ in range(20):
        h = k.OpenEventW(EVENT_MODIFY_STATE, False, _SHOW_EVENT_NAME)
        if h:
            k.SetEvent(h)
            k.CloseHandle(h)
            return
        if _find_window("Aegis Security"):
            break
        _t.sleep(0.25)
    # Fallback: owner may be elevated (its event unreachable), so raise directly.
    _force_foreground(_find_window("Aegis Security"))


def _find_window(title: str):
    import ctypes
    return ctypes.windll.user32.FindWindowW(None, title)


def _force_foreground(hwnd) -> None:
    """Restore + raise a window, working around Windows' foreground lock.

    Windows refuses SetForegroundWindow from a process that doesn't own the
    current foreground window. The reliable workaround is to (a) let the
    calling process hand over its foreground privilege, (b) attach to the
    foreground thread's input queue, and (c) briefly set the window topmost.
    """
    if not hwnd:
        return
    import ctypes
    import time as _t
    u = ctypes.windll.user32
    k = ctypes.windll.kernel32
    SW_RESTORE, SW_SHOW = 9, 5
    HWND_TOPMOST, HWND_NOTOPMOST = -1, -2
    SWP_NOMOVE, SWP_NOSIZE, SWP_SHOWWINDOW = 0x0002, 0x0001, 0x0040

    # ShowWindowAsync posts instead of sending: a synchronous ShowWindow from a
    # worker thread waits on the UI thread and can hang the app.
    if u.IsIconic(hwnd):
        u.ShowWindowAsync(hwnd, SW_RESTORE)
    else:
        u.ShowWindowAsync(hwnd, SW_SHOW)
    _t.sleep(0.15)

    # Let whoever currently owns the foreground release it to the target's pid.
    try:
        pid = ctypes.c_ulong()
        u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        u.AllowSetForegroundWindow(pid.value)
    except Exception:
        pass

    fg = u.GetForegroundWindow()
    cur = k.GetCurrentThreadId()
    # AttachThreadInput is only safe across DIFFERENT processes. Attaching to
    # our own UI thread from a worker thread (e.g. when the app is already
    # foregrounded) deadlocks the WebView2 message pump and Windows paints the
    # window "Not Responding".
    own = ctypes.c_ulong()
    u.GetWindowThreadProcessId(hwnd, ctypes.byref(own))
    cur_pid = k.GetCurrentProcessId()
    same_thread = (u.GetWindowThreadProcessId(hwnd, None) == cur)
    tgt = 0
    attached = False
    if not same_thread:
        tgt = u.GetWindowThreadProcessId(fg, None) if fg else 0
        if tgt and tgt != cur:
            fgpid = ctypes.c_ulong()
            if fg:
                u.GetWindowThreadProcessId(fg, ctypes.byref(fgpid))
            # Don't attach into our own process either — same deadlock risk.
            if fgpid.value != cur_pid:
                attached = bool(u.AttachThreadInput(cur, tgt, True))
    try:
        u.BringWindowToTop(hwnd)
        u.SetForegroundWindow(hwnd)
        u.SetActiveWindow(hwnd)
        if u.GetForegroundWindow() != hwnd:
            # Last resort: flick topmost so the window manager promotes it.
            u.SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                           SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW)
            _t.sleep(0.05)
            u.SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0,
                           SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW)
            u.SetForegroundWindow(hwnd)
        if u.GetForegroundWindow() != hwnd:
            # Still refused (a remote-desktop client or full-screen app owns
            # the foreground lock). Flash the taskbar button so the user sees
            # that their second launch did something.
            class FLASHWINFO(ctypes.Structure):
                _fields_ = [("cbSize", ctypes.c_uint),
                            ("hwnd", ctypes.c_void_p),
                            ("dwFlags", ctypes.c_uint),
                            ("uCount", ctypes.c_uint),
                            ("dwTimeout", ctypes.c_uint)]
            FLASHW_ALL, FLASHW_TIMERNOFG = 0x00000003, 0x0000000C
            fi = FLASHWINFO(ctypes.sizeof(FLASHWINFO), hwnd,
                            FLASHW_ALL | FLASHW_TIMERNOFG, 3, 0)
            u.FlashWindowEx(ctypes.byref(fi))
    finally:
        if attached:
            u.AttachThreadInput(cur, tgt, False)


def _watch_show_requests(window) -> None:
    """Owner instance: block on the named event; reveal the UI when poked.

    IMPORTANT: never call into pywebview's window object from here. Those calls
    marshal onto the WebView2 UI thread and, when that thread is itself busy
    (or is waiting on us), the app deadlocks and Windows paints it
    "Not Responding". Pure Win32 calls against the HWND are safe from any
    thread, so we raise the window that way instead.
    """
    if sys.platform != "win32":
        return
    k = _k32()
    h = k.CreateEventW(None, False, False, _SHOW_EVENT_NAME)   # auto-reset
    if not h:
        return
    while True:
        if k.WaitForSingleObject(h, 0xFFFFFFFF) != 0:
            return
        try:
            _force_foreground(_find_window("Aegis Security"))
        except Exception:
            pass


def _bootstrap(api: Api, window) -> None:
    """Runs once the window exists.

    pywebview invokes this on the GUI thread, so it must return immediately —
    starting the shields (which builds watchdog observers and walks the
    filesystem) here would freeze the window into "Not Responding". All of the
    slow work therefore happens on a worker thread.
    """
    api.window = window
    # Set the real Aegis icon on the window + taskbar so it doesn't show the
    # python interpreter icon (and any crash dialog references "Aegis").
    _set_window_icon(window)

    # ── System tray: the app stays alive (and keeps protecting) in the tray
    #    when the UI is closed. The tray menu can Open the UI, enable/disable
    #    real-time protection, or Quit. The window's X only hides to tray.
    ico = resource_path(os.path.join("ui", "aegis.ico"))
    tray = TrayIcon(
        ico,
        "Aegis Security",
        on_open=lambda: (show_window(api.window), _force_foreground(_find_window("Aegis Security"))),
        on_quit=lambda: _tray_quit(api),
        on_toggle=lambda: _tray_toggle(api, tray),
        protection_label=lambda: (
            "Disable Protection" if api.shields.status().get("running") else "Enable Protection"),
    )
    tray.start()
    api._tray = tray
    # The UI's X / api.close() hides to tray instead of exiting.
    api._on_close = lambda: hide_window(api.window)
    api._on_minimize = lambda: hide_window(api.window)

    if os.environ.get("AEGIS_NO_BOOTSTRAP") == "1":
        return

    def _work():
        # Claim the singleton so later launches reveal this window instead of
        # booting a second protection engine.
        _claim_singleton()
        threading.Thread(target=_watch_show_requests, args=(window,),
                         daemon=True).start()
        if os.environ.get("AEGIS_NO_SHIELDS") == "1":
            return
        if store.get("shield.file", True) or store.get("shield.behavior", True):
            try:
                api.shields.start()
            except Exception as e:
                store.log("error", "medium", "Shields failed to start", str(e))
        if store.get("intel.auto_update", True):
            import time
            if time.time() - store.get("intel.last_update", 0) > 21600:
                threading.Timer(
                    4.0, lambda: api.updater.update(include_rules=False)).start()

    threading.Thread(target=_work, daemon=True).start()


def _set_window_icon(window) -> None:
    """Apply the Aegis .ico to the real Win32 window (taskbar + title).
    pywebview 6.x has no icon kwarg, so we poke the HWND directly.
    Runs on the GUI thread (called from _bootstrap)."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ico = resource_path(os.path.join("ui", "aegis.ico"))
        if not os.path.exists(ico):
            return
        u = ctypes.windll.user32
        k = ctypes.windll.kernel32
        # Find the top-level Aegis HWND.
        hwnd = u.FindWindowW(None, "Aegis Security")
        if not hwnd:
            return
        # Load both small + large icon sizes from the .ico (multi-size).
        LR_LOADFROMFILE = 0x10
        IMAGE_ICON = 1
        hlarge = u.LoadImageW(0, ico, IMAGE_ICON, 256, 256, LR_LOADFROMFILE)
        hsmall = u.LoadImageW(0, ico, IMAGE_ICON, 16, 16, LR_LOADFROMFILE)
        WM_SETICON = 0x80
        ICON_SMALL, ICON_LARGE = 0, 1
        if hlarge:
            u.SendMessageW(hwnd, WM_SETICON, ICON_LARGE, hlarge)
        if hsmall:
            u.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, hsmall)
    except Exception:
        pass


def _tray_quit(api: Api) -> None:
    """Tray "Quit": stop protection, kill the tray icon, destroy the window.

    Destroying the window lets webview.start return, after which main() runs
    its shields.stop() cleanup and the process exits. This is the ONLY path
    that terminates Aegis — the UI's X only hides to tray.
    """
    try:
        api._tray.stop()
    except Exception:
        pass
    try:
        api.shields.stop()
    except Exception:
        pass
    try:
        api.window.destroy()
    except Exception:
        pass


def _tray_toggle(api: Api, tray) -> None:
    """Tray "Enable/Disable Protection": flip real-time shields and refresh the
    menu label so the next open shows the correct action."""
    try:
        if api.shields.status().get("running"):
            api.shields.stop()
            store.log("app", "warn", "Real-time protection disabled (tray)", "")
        else:
            api.shields.start()
            store.log("app", "info", "Real-time protection enabled (tray)", "")
    except Exception as e:
        store.log("error", "medium", "Tray protection toggle failed", str(e))
    try:
        tray.refresh()
    except Exception:
        pass


def main() -> int:
    print("[DBG] main start", flush=True)
    if not os.path.exists(INDEX):
        print("UI missing:", INDEX)
        return 1

    print("[DBG] before _already_running", flush=True)
    if _already_running() or not _boot_lock():
        print("[DBG] already running or boot locked — signaling show", flush=True)
        # Don't boot a second engine — just bring the live one to the front.
        _signal_show()
        return 0
    print("[DBG] after boot lock, before Api()", flush=True)

    # ── Unique WebView2 profile per launch ──────────────────────────────────
    # A lingering renderer from a previous (killed) instance can keep the
    # shared profile folder open, so the next launch's WebView2 controller
    # fails with 0x800700AA "resource in use" and the window paints BLACK.
    # Giving every launch its own profile folder removes that contention
    # entirely, so re-opening Aegis is always clean.
    import atexit
    import shutil as _shutil
    import tempfile as _tempfile
    _wv2 = os.path.join(_tempfile.gettempdir(), "aegis_wv2_%d" % os.getpid())
    os.makedirs(_wv2, exist_ok=True)
    os.environ["WEBVIEW2_USER_DATA_FOLDER"] = _wv2
    atexit.register(lambda: _shutil.rmtree(_wv2, ignore_errors=True))

    # Stability: force software rendering. On this machine the default GPU
    # path makes the WebView2 renderer crash mid-launch ("refresh the page" /
    # Aw-Snap), leaving a blank UI. Disabling GPU + software rasterizer keeps
    # the renderer alive. Append so the optional CDP flag below still wins.
    _wv_args = "--disable-gpu --disable-software-rasterizer --disable-dev-shm-usage --disable-features=msWebView2Update"
    if os.environ.get("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"):
        os.environ["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] += " " + _wv_args
    else:
        os.environ["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = _wv_args

    # Optional remote-debugging port for automated UI verification.
    if os.environ.get("AEGIS_CDP"):
        os.environ["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] += (
            " --remote-debugging-port=" + os.environ["AEGIS_CDP"] +
            " --remote-allow-origins=*")

    api = Api()
    print("[DBG] after Api(), before create_window", flush=True)
    window = webview.create_window(
        "Aegis Security",
        INDEX,
        js_api=api,
        width=1280,
        height=850,
        min_size=(1060, 700),
        background_color="#0d1117",
        frameless=True,
        easy_drag=True,
        text_select=False,
    )

    # ── FIX (correct): pywebview 6.2.1 serializes the JS-API by walking
    #    dir(api) and RECURSING into every non-callable sub-object that has a
    #    __module__. On Win11 LTSC, `window.native.AccessibilityObject` returns
    #    a brand-new COM proxy on every getattr, so an id()-based guard never
    #    fires and we hit "maximum recursion depth exceeded" → webview.start
    #    never returns → the window paints "Not Responding" forever.
    #    The real function is inject_pywebview.<locals>.get_functions (there is
    #    NO top-level webview.util.get_functions). Replace inject_pywebview with
    #    a version whose inner walker: skips `native` + Accessibility/COM names,
    #    enforces a hard depth cap, and guards on (id, name).
    import webview.util as _wvutil
    from webview.util import inspect as _inspect, logger as _wvlog
    from webview.util import load_js_files, json

    _SKIP_NAMES = {"native", "AccessibilityObject", "Accessibility", "OleWindow",
                   "Bounds", "Parent", "Window", "Application"}
    _MAX_DEPTH = 6

    def _safe_inject_pywebview(platform, window):
        exposed_objects = []

        def get_args(func):
            return list(_inspect.getfullargspec(func).args)

        def get_functions(obj, base_name="", functions=None, depth=0):
            if depth > _MAX_DEPTH:
                return functions if functions is not None else {}
            if functions is None:
                functions = {}
            obj_id = id(obj)
            key = (obj_id, base_name)
            if key in exposed_objects:
                return functions
            exposed_objects.append(key)
            try:
                names = list(dir(obj))
            except Exception:
                return functions
            for name in names:
                if name.startswith("_") or name in _SKIP_NAMES:
                    continue
                try:
                    attr = getattr(obj, name)
                except Exception:
                    continue
                if not getattr(attr, "_serializable", True):
                    continue
                full_name = f"{base_name}.{name}" if base_name else name
                try:
                    if _inspect.ismethod(attr) or _inspect.isfunction(attr):
                        functions[full_name] = get_args(attr)[1:]
                    elif _inspect.isclass(attr):
                        get_functions(attr, full_name, functions, depth + 1)
                    elif isinstance(attr, object) and not callable(attr) and hasattr(attr, "__module__"):
                        cls_name = getattr(getattr(attr, "__class__", None), "__name__", "")
                        if cls_name in _SKIP_NAMES:
                            continue
                        get_functions(attr, full_name, functions, depth + 1)
                except Exception as e:
                    _wvlog.error(f"Error while processing {full_name}: {e}")
                    continue
            return functions

        def generate_func():
            functions = get_functions(window._js_api)
            if len(window._functions) > 0:
                expose_functions = {n: get_args(f) for n, f in window._functions.items()}
            else:
                expose_functions = {}
            functions.update(expose_functions)
            return [{"func": n, "params": p} for n, p in functions.items()]

        def generate_js_object():
            from webview.util import load_js_files as _ljs, json as _json  # local refs
            js_code, finish_script = _ljs(window, platform)
            window.run_js(js_code)
            try:
                with window._expose_lock:
                    func_list = generate_func()
                    window.run_js(finish_script % {"functions": _json.dumps(func_list)})
                    window.events._pywebviewready.set()
                    window.events.loaded.set()
            except Exception as e:
                _wvlog.exception(e)
                window.events.loaded.set()

        window.events.before_load.set()
        js_code, finish_script = load_js_files(window, platform)
        import threading as _th
        _th.Thread(target=generate_js_object).start()

    _wvutil.inject_pywebview = _safe_inject_pywebview
    print("[DBG] recursion-safe inject_pywebview installed", flush=True)
    print("[DBG] after create_window, before webview.start", flush=True)
    store.log("app", "info", "Aegis Security started",
              f"{api.engine.rule_count:,} rules · "
              f"{len(api.engine.md5_set) + len(api.engine.sha_set):,} signatures")

    webview.start(lambda: _bootstrap(api, window), debug=os.environ.get("AEGIS_DEBUG") == "1")

    try:
        api.shields.stop()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
