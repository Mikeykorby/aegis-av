# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for Aegis Security.

Build:  pyinstaller aegis.spec
Output: dist/aegis.exe  (single portable executable)

The WebView2 runtime is a system component, so it is NOT bundled — the
frozen app uses the same Edge/WebView2 already on the machine.
"""
import os

block_cipher = None

ui_dir = os.path.join(SPECPATH, "ui")
added_files = [
    (ui_dir, "ui"),
]

a = Analysis(
    ["aegis.py"],
    pathex=[SPECPATH],
    binaries=[],
    datas=added_files,
    hiddenimports=[
        "engine",
        "engine.api",
        "engine.shields",
        "engine.tools",
        "engine.store",
        "engine.tray",
        "engine.kernel_probe",
        "engine.hardening",
        "engine.intel",
        "engine.detect",
        "engine.scanner",
        "engine.trust",
        "engine.appupdater",
        "watchdog",
        "watchdog.observers",
        "watchdog.events",
        "psutil",
        "webview",
        "webview.util",
        "winreg",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "unittest",
        "pydoc",
        "doctest",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="aegis",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(ui_dir, "aegis.ico"),
    version=os.path.join(SPECPATH, "version_info.txt"),
)
