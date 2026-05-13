"""Install d810-ng for headless / ida-hub use.

Auto-detects IDA Pro's bundled Python and plugins directory.
Performs two steps:
  1. pip install d810-ng into IDA's Python environment
  2. Copy the plugin entry-point (d810ng.py) into IDA's plugins/ directory
"""

from __future__ import annotations

import argparse
import glob
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
_PLUGIN_SRC = _PROJECT_ROOT / "src" / "d810ng.py"


# ── IDA directory detection ──────────────────────────────────────────

def _ida_dir_from_binary_in_path() -> Path | None:
    """Resolve IDA install dir from idat64/ida64 found in PATH."""
    for name in ("idat64", "ida64", "idat", "ida"):
        which = shutil.which(name)
        if which:
            return Path(which).resolve().parent
    return None


def _ida_dir_from_env() -> Path | None:
    """Check IDADIR environment variable."""
    val = os.environ.get("IDADIR")
    if val:
        p = Path(val)
        if p.is_dir():
            return p
    return None


def _ida_dir_from_common_paths() -> Path | None:
    """Probe well-known install locations (no recursive search)."""
    home = Path.home()
    system = platform.system()

    candidates: list[str] = []
    if system == "Linux":
        candidates += [
            str(home / "ida-pro-*"),
            str(home / "idapro-*"),
            str(home / "idapro"),
            "/opt/ida*",
            "/opt/idapro*",
        ]
    elif system == "Darwin":
        candidates += [
            "/Applications/IDA Pro*.app/Contents/MacOS",
            str(home / "ida-pro-*"),
            str(home / "idapro-*"),
        ]
    elif system == "Windows":
        candidates += [
            r"C:\Program Files\IDA Pro *",
            r"C:\IDA Pro *",
            str(home / "ida-pro-*"),
            str(home / "idapro-*"),
        ]

    for pattern in candidates:
        matches = sorted(glob.glob(pattern), reverse=True)
        for m in matches:
            p = Path(m)
            if p.is_dir():
                return p
    return None


def detect_ida_dir() -> Path | None:
    """Try multiple strategies to find IDA install directory."""
    for fn in (_ida_dir_from_env, _ida_dir_from_binary_in_path, _ida_dir_from_common_paths):
        result = fn()
        if result:
            return result
    return None


def find_ida_python(ida_dir: Path) -> Path | None:
    """Locate IDA's bundled Python interpreter inside an IDA install dir."""
    system = platform.system()

    if system == "Windows":
        candidates = [
            ida_dir / "python_standalone" / "python.exe",
            ida_dir / "python_standalone" / "python3.exe",
        ]
    else:
        candidates = [
            ida_dir / "python_standalone" / "bin" / "python3",
            ida_dir / "python_standalone" / "bin" / "python",
        ]

    for c in candidates:
        if c.is_file():
            return c
    return None


def find_plugins_dir(ida_dir: Path) -> Path:
    """Return IDA's plugins/ directory (may not yet exist)."""
    return ida_dir / "plugins"


# ── Installation actions ─────────────────────────────────────────────

def pip_install(python: Path) -> None:
    """Install d810-ng into the given Python environment."""
    cmd = [str(python), "-m", "pip", "install", str(_PROJECT_ROOT)]
    print(f"  Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)


def copy_plugin(plugins_dir: Path) -> None:
    """Copy d810ng.py into IDA's plugins directory."""
    plugins_dir.mkdir(parents=True, exist_ok=True)
    dest = plugins_dir / _PLUGIN_SRC.name
    shutil.copy2(_PLUGIN_SRC, dest)
    print(f"  Copied {_PLUGIN_SRC.name} -> {dest}")


def verify(python: Path) -> bool:
    """Quick import check."""
    cmd = [
        str(python), "-c",
        "from d810.headless import start, stop, configure, status; print('OK')",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0 and "OK" in result.stdout


# ── CLI ──────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Install d810-ng for headless / ida-hub use.",
    )
    parser.add_argument(
        "--ida-dir",
        type=Path,
        default=None,
        help="IDA Pro install directory (auto-detected if omitted).",
    )
    parser.add_argument(
        "--skip-pip",
        action="store_true",
        help="Skip pip install, only copy plugin file.",
    )
    parser.add_argument(
        "--skip-plugin-copy",
        action="store_true",
        help="Skip copying d810ng.py to plugins dir.",
    )
    args = parser.parse_args()

    # 1. Find IDA directory
    ida_dir = args.ida_dir
    if ida_dir is None:
        print("[1/3] Detecting IDA Pro installation...")
        ida_dir = detect_ida_dir()
        if ida_dir is None:
            print(
                "ERROR: Could not auto-detect IDA Pro installation.\n"
                "Please specify with --ida-dir /path/to/ida"
            )
            sys.exit(1)
    print(f"  IDA directory: {ida_dir}")

    # 2. Find IDA Python
    print("[2/3] Locating IDA's bundled Python...")
    ida_python = find_ida_python(ida_dir)
    if ida_python is None:
        print(
            f"ERROR: Could not find Python interpreter in {ida_dir}/python_standalone/\n"
            "Please check your IDA Pro installation."
        )
        sys.exit(1)
    print(f"  IDA Python: {ida_python}")

    # 3. Install
    print("[3/3] Installing d810-ng...")
    if not args.skip_pip:
        pip_install(ida_python)

    if not args.skip_plugin_copy:
        plugins_dir = find_plugins_dir(ida_dir)
        copy_plugin(plugins_dir)

    # Verify
    print("\nVerifying installation...")
    if verify(ida_python):
        print("d810-ng installed successfully.")
    else:
        print(
            "WARNING: Import verification failed.\n"
            "This may be normal if IDA-specific modules (idaapi, etc.) are not available\n"
            "outside of IDA. The install should still work inside IDA/idat64."
        )


if __name__ == "__main__":
    main()
