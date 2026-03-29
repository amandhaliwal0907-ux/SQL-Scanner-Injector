
# build.py - Compile SQLi Scout to a standalone Windows .exe
# Requirements:
#   pip install PyQt5 pyinstaller requests beautifulsoup4 colorama lxml
# Usage:
#   python build.py
# Output:
#   dist/SQLiScout.exe  (single-file executable, about 60-90 MB)

import os
import sys
import subprocess
import shutil

APP_NAME    = "SQLiScout"
ENTRY_POINT = "gui.py"
ICON_FILE   = "icon.ico"   # optional — place icon.ico in this folder

SOURCE_FILES = [
    "gui.py",
    "scanner.py",
    "crawler.py",
    "payloads.py",
    "reporter.py",
    "utils.py",
]


def check_files():
    missing = [f for f in SOURCE_FILES if not os.path.exists(f)]
    if missing:
        print(f"[!] Missing files: {', '.join(missing)}")
        print("    Make sure all source files are in the same directory as build.py")
        sys.exit(1)
    print(f"[+] All source files present")


def check_deps():
    try:
        import PyInstaller
        print(f"[+] PyInstaller {PyInstaller.__version__} found")
    except ImportError:
        print("[!] PyInstaller not found — installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    deps = ["PyQt5", "requests", "bs4", "colorama", "lxml"]
    for dep in deps:
        try:
            __import__(dep)
            print(f"[+] {dep} OK")
        except ImportError:
            print(f"[!] {dep} not found — installing...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", dep])


def build():
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",                         # Single .exe file
        "--windowed",                         # No console window (GUI app)
        "--name", APP_NAME,
        "--clean",                            # Clean build cache
        "--noconfirm",                        # Overwrite existing build

        # Hidden imports PyInstaller sometimes misses
        "--hidden-import", "PyQt5.sip",
        "--hidden-import", "PyQt5.QtCore",
        "--hidden-import", "PyQt5.QtWidgets",
        "--hidden-import", "PyQt5.QtGui",
        "--hidden-import", "requests",
        "--hidden-import", "bs4",
        "--hidden-import", "lxml",
        "--hidden-import", "lxml.etree",
        "--hidden-import", "colorama",
        "--hidden-import", "difflib",
        "--hidden-import", "concurrent.futures",

        # Exclude heavy unused packages to keep size down
        "--exclude-module", "matplotlib",
        "--exclude-module", "numpy",
        "--exclude-module", "pandas",
        "--exclude-module", "scipy",
        "--exclude-module", "PIL",
        "--exclude-module", "tkinter",
        "--exclude-module", "unittest",

        ENTRY_POINT,
    ]

    # Add icon if it exists
    if os.path.exists(ICON_FILE):
        cmd.extend(["--icon", ICON_FILE])
        print(f"[+] Using icon: {ICON_FILE}")
    else:
        print(f"[~] No icon.ico found — using default (place icon.ico here to customise)")

    print("\n[*] Building executable…")
    print(f"    Command: {' '.join(cmd)}\n")

    result = subprocess.run(cmd)

    if result.returncode == 0:
        exe_path = os.path.join("dist", f"{APP_NAME}.exe")
        size_mb  = os.path.getsize(exe_path) / (1024 * 1024) if os.path.exists(exe_path) else 0
        print(f"\n{'='*50}")
        print(f"  Build successful!")
        print(f"  Output : {exe_path}")
        print(f"  Size   : {size_mb:.1f} MB")
        print(f"{'='*50}\n")
        print("  Run it: double-click SQLiScout.exe")
        print("  Or:     dist\\SQLiScout.exe\n")
    else:
        print(f"\n[!] Build failed with exit code {result.returncode}")
        print("    Check the output above for errors")
        sys.exit(1)


def cleanup():
    """Remove build artifacts, keep only dist/"""
    for path in ["build", f"{APP_NAME}.spec"]:
        if os.path.exists(path):
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
    print("[+] Cleaned up build artifacts")


if __name__ == "__main__":
    print("="*50)
    print(f"  SQLi Scout — Build Script")
    print("="*50 + "\n")

    check_files()
    check_deps()
    print()
    build()
    cleanup()
