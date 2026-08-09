"""Aegis Security — dependency-free Windows system tray icon.

Uses raw Win32 (Shell_NotifyIcon / shell32) so no extra packages are needed.
The tray owns the "live but window-hidden" lifecycle: the app keeps protecting
in real time while hidden, and the tray menu (or a double-click) brings it back.

Interaction model requested by the user:
  • Left-click / double-click the tray icon  -> open the UI
  • Right-click                        -> menu: Open · Enable/Disable Protection · Quit
  • The UI's X (api.close) only hides to tray — it never exits the app.
  • Only the tray's "Quit" actually terminates Aegis.

Window show/hide is driven async (pywebview marshals internally) so we never
deadlock the WebView2 UI thread.
"""
from __future__ import annotations

import ctypes
import os
import threading

import webview  # only for the Window type; safe to import

# ── Win32 constants ──────────────────────────────────────────────────────
WM_APP = 0x8000
NIM_ADD = 0x00000000
NIM_MODIFY = 0x00000001
NIM_DELETE = 0x00000002
NIF_MESSAGE = 0x00000001
NIF_ICON = 0x00000002
NIF_TIP = 0x00000004
WM_LBUTTONUP = 0x0202
WM_LBUTTONDBLCLK = 0x0203
WM_RBUTTONUP = 0x0205
WM_COMMAND = 0x0111
WM_DESTROY = 0x0002
WM_QUIT = 0x0012
TPM_RETURNCMD = 0x0100


class TrayIcon:
    """Minimal systray host.

    Callbacks (all optional):
      on_open()    -> show the UI
      on_quit()    -> terminate Aegis
      on_toggle()  -> enable/disable real-time protection
      protection_label() -> current menu label, e.g. "Disable Protection"
    """

    def __init__(self, icon_path: str, tooltip: str = "Aegis Security",
                 on_open=None, on_quit=None, on_toggle=None,
                 protection_label=None):
        self.icon_path = icon_path
        self.tooltip = tooltip
        self.on_open = on_open
        self.on_quit = on_quit
        self.on_toggle = on_toggle
        self.protection_label = protection_label or (lambda: "Disable Protection")
        self._hwnd = None
        self._msg = WM_APP + 1
        self._thread = None
        self._running = threading.Event()
        self._wndclass_atom = None
        self._wndproc_ref = None   # keep the ctypes callback alive
        self._ico_handle = 0

    # ── public API ────────────────────────────────────────────────────
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._running.set()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running.clear()
        try:
            ctypes.windll.user32.PostMessageW(self._hwnd, WM_QUIT, 0, 0)
        except Exception:
            pass

    def set_tooltip(self, text: str) -> None:
        if not self._hwnd:
            return
        self.tooltip = text
        self._notify(NIM_MODIFY)

    def refresh(self) -> None:
        """Rebuild the icon/menu state (e.g. after a protection toggle)."""
        if self._hwnd:
            self._notify(NIM_MODIFY)

    # ── internals ─────────────────────────────────────────────────────
    def _run(self) -> None:
        u = ctypes.windll.user32
        k = ctypes.windll.kernel32
        shell = ctypes.windll.shell32
        # DefWindowProcW must take pointer-sized args; without this, large
        # lparam values (e.g. from WM_COMMAND) overflow c_int and the callback
        # raises, which Windows swallows but breaks default message handling.
        u.DefWindowProcW.argtypes = [ctypes.c_void_p, ctypes.c_uint,
                                     ctypes.c_void_p, ctypes.c_void_p]
        u.DefWindowProcW.restype = ctypes.c_long

        # Keep the WNDPROC reference alive for the lifetime of the window.
        self._wndproc_ref = WNDPROC(self._wndproc)
        wc = WNDCLASS()
        wc.lpfnWndProc = ctypes.cast(self._wndproc_ref, ctypes.c_void_p)
        wc.lpszClassName = "AegisTrayCls"
        self._wndclass_atom = u.RegisterClassW(ctypes.byref(wc))
        self._hwnd = u.CreateWindowExW(0, "AegisTrayCls", "AegisTray",
                                        0, 0, 0, 0, 0, 0, 0, 0, None)
        self._ico_handle = self._load_icon()

        # Proper prototypes for shell32 (avoids stack corruption).
        shell.Shell_NotifyIconW.argtypes = [ctypes.c_uint, ctypes.POINTER(NOTIFYICONDATA)]
        shell.Shell_NotifyIconW.restype = ctypes.c_int

        self._notify(NIM_ADD)
        self._notify(NIM_MODIFY)

        msg = MSG()
        while self._running.is_set():
            r = u.GetMessageW(ctypes.byref(msg), self._hwnd, 0, 0)
            if r == 0 or r == -1:
                break
            u.TranslateMessage(ctypes.byref(msg))
            u.DispatchMessageW(ctypes.byref(msg))

        self._notify(NIM_DELETE)
        try:
            if self._ico_handle:
                u.DestroyIcon(self._ico_handle)
        except Exception:
            pass
        try:
            if self._wndclass_atom:
                u.UnregisterClassW("AegisTrayCls", k.GetModuleHandleW(None))
        except Exception:
            pass

    def _wndproc(self, hwnd, msg, wparam, lparam):
        u = ctypes.windll.user32
        if msg == self._msg:
            if lparam in (WM_LBUTTONUP, WM_LBUTTONDBLCLK):
                self._invoke(self.on_open)
            elif lparam == WM_RBUTTONUP:
                self._show_menu()
            return 1
        return u.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _invoke(self, cb):
        if cb:
            try:
                cb()
            except Exception:
                pass

    def _show_menu(self) -> None:
        u = ctypes.windll.user32
        m = u.CreatePopupMenu()
        u.AppendMenuW(m, 0x0000, 1001, "Open Aegis")
        u.AppendMenuW(m, 0x0000, 1003, self.protection_label())
        u.AppendMenuW(m, 0x0000, 1002, "Quit Aegis")
        p = POINT()
        u.GetCursorPos(ctypes.byref(p))
        u.SetForegroundWindow(self._hwnd)   # so the menu dismisses on outside-click
        cmd = u.TrackPopupMenu(m, TPM_RETURNCMD, p.x, p.y, 0, self._hwnd, None)
        u.DestroyMenu(m)
        if cmd == 1001:
            self._invoke(self.on_open)
        elif cmd == 1003:
            self._invoke(self.on_toggle)
        elif cmd == 1002:
            self._invoke(self.on_quit)

    def _load_icon(self) -> int:
        u = ctypes.windll.user32
        if self.icon_path and os.path.exists(self.icon_path):
            try:
                return u.LoadImageW(0, self.icon_path, 1, 16, 16, 0x10)  # IMAGE_ICON
            except Exception:
                pass
        return 0

    def _notify(self, action: int) -> None:
        shell = ctypes.windll.shell32
        nid = NOTIFYICONDATA()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATA)
        nid.hWnd = self._hwnd
        nid.uID = 1
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        nid.uCallbackMessage = self._msg
        nid.hIcon = self._ico_handle or 0
        nid.szTip = (self.tooltip or "")[:127]
        try:
            shell.Shell_NotifyIconW(action, ctypes.byref(nid))
        except Exception:
            pass


# ── ctypes structure / prototype plumbing ──────────────────────────────────
class POINT(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]


class MSG(ctypes.Structure):
    _fields_ = [
        ("hWnd", ctypes.c_void_p), ("message", ctypes.c_uint),
        ("wParam", ctypes.c_void_p), ("lParam", ctypes.c_void_p),
        ("time", ctypes.c_uint), ("pt", POINT), ("lPrivate", ctypes.c_uint),
    ]


class WNDCLASS(ctypes.Structure):
    _fields_ = [
        ("style", ctypes.c_uint),
        ("lpfnWndProc", ctypes.c_void_p),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", ctypes.c_void_p),
        ("hIcon", ctypes.c_void_p),
        ("hCursor", ctypes.c_void_p),
        ("hbrBackground", ctypes.c_void_p),
        ("lpszMenuName", ctypes.c_wchar_p),
        ("lpszClassName", ctypes.c_wchar_p),
    ]


class NOTIFYICONDATA(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_uint),
        ("hWnd", ctypes.c_void_p),
        ("uID", ctypes.c_uint),
        ("uFlags", ctypes.c_uint),
        ("uCallbackMessage", ctypes.c_uint),
        ("hIcon", ctypes.c_void_p),
        ("szTip", ctypes.c_wchar * 128),
        ("dwState", ctypes.c_uint),
        ("dwStateMask", ctypes.c_uint),
        ("szInfo", ctypes.c_wchar * 256),
        ("uTimeoutOrVersion", ctypes.c_uint),
        ("szInfoTitle", ctypes.c_wchar * 64),
        ("dwInfoFlags", ctypes.c_uint),
        ("guidItem", ctypes.c_byte * 16),
        ("hBalloonIcon", ctypes.c_void_p),
    ]


WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, ctypes.c_uint,
                             ctypes.c_void_p, ctypes.c_void_p)


def show_window(window) -> None:
    """Restore + raise the main window from any thread.

    pywebview's window.show() can be a no-op on a frameless WinForms window,
    so we also drive the real top-level HWND directly with ShowWindowAsync and
    then promote it to the foreground.
    """
    if window:
        try:
            window.show()
        except Exception:
            pass
    hwnd = ctypes.windll.user32.FindWindowW(None, "Aegis Security")
    if hwnd:
        u = ctypes.windll.user32
        u.ShowWindowAsync(hwnd, 9)     # SW_RESTORE
        _force_foreground(hwnd)


def hide_window(window) -> None:
    """Hide the main window (keeps the app + shields alive).

    Same reasoning as show_window: drive the real HWND directly because
    window.hide() does not reliably collapse a frameless WinForms window.
    """
    if window:
        try:
            window.hide()
        except Exception:
            pass
    hwnd = ctypes.windll.user32.FindWindowW(None, "Aegis Security")
    if hwnd:
        ctypes.windll.user32.ShowWindowAsync(hwnd, 0)   # SW_HIDE


def _force_foreground(hwnd) -> None:
    """Raise a window, working around Windows' foreground lock."""
    if not hwnd:
        return
    u = ctypes.windll.user32
    SW_SHOW = 5
    HWND_TOPMOST, HWND_NOTOPMOST = -1, -2
    SWP_NOMOVE, SWP_NOSIZE, SWP_SHOWWINDOW = 0x0002, 0x0001, 0x0040
    if u.IsIconic(hwnd):
        u.ShowWindowAsync(hwnd, 9)
    else:
        u.ShowWindowAsync(hwnd, SW_SHOW)
    try:
        pid = ctypes.c_ulong()
        u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        u.AllowSetForegroundWindow(pid.value)
    except Exception:
        pass
    u.BringWindowToTop(hwnd)
    u.SetForegroundWindow(hwnd)
    u.SetActiveWindow(hwnd)
