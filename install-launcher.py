#!/usr/bin/env python3
"""Install this checkout's launcher in the current user's application menu."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

APP_ID = 'brief-connection-watcher'
APP_NAME = 'Brief Connection Watcher'
ADMIN = True


def desktop_value(value):
    """Escape strings according to the Desktop Entry specification."""
    return str(value).replace("\\", "\\\\").replace("\n", r"\n").replace("\r", r"\r").replace("\t", r"\t")


def exec_arg(value):
    # Exec has its own quoting layer; percent introduces desktop field codes.
    value = str(value).replace("%", "%%")
    for char in ("\\", '"', "`", "$"):
        value = value.replace(char, "\\" + char)
    return desktop_value('"' + value + '"')


def install(desktop=False, normal_user=False):
    source = Path(__file__).resolve().parent
    data_home = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share")
    if not data_home.is_absolute():
        raise ValueError("XDG_DATA_HOME must be an absolute path")
    applications = data_home / "applications"
    applications.mkdir(parents=True, exist_ok=True)
    script = source / ("run-admin.sh" if ADMIN and not normal_user else "run.sh")
    contents = "\n".join([
        "[Desktop Entry]", "Version=1.0", "Type=Application",
        "Name=" + APP_NAME,
        "Comment=" + ("Launch with administrator authentication" if ADMIN and not normal_user else "Launch " + APP_NAME),
        "Exec=/bin/bash " + exec_arg(script),
        "Path=" + desktop_value(source),
        "Icon=" + desktop_value(source / "assets/icon.png"),
        "Terminal=false", "Categories=System;", "StartupNotify=false", "",
    ])
    target = applications / (APP_ID + ".desktop")
    target.write_text(contents, encoding="utf-8")
    target.chmod(0o755)
    if desktop:
        if shutil.which("xdg-user-dir"):
            result = subprocess.run(["xdg-user-dir", "DESKTOP"], capture_output=True, text=True, check=True)
            desktop_dir = Path(result.stdout.strip())
            if not desktop_dir.is_absolute() or desktop_dir == Path.home():
                raise ValueError("No desktop folder is configured; menu launcher was installed")
        else:
            desktop_dir = Path.home() / "Desktop"
        desktop_dir.mkdir(parents=True, exist_ok=True)
        target = desktop_dir / target.name
        target.write_text(contents, encoding="utf-8")
        target.chmod(0o755)
        if shutil.which("gio"):
            checksum = hashlib.sha256(target.read_bytes()).hexdigest()
            for key, value in (("metadata::trusted", "true"), ("metadata::xfce-exe-checksum", checksum),
                               ("metadata::custom-icon", (source / "assets/icon.png").as_uri())):
                subprocess.run(["gio", "set", "-t", "string", str(target), key, value], capture_output=True)
    print(f"Installed {target}")
    print("Keep this checkout in place; rerun the installer if you move it.")
    return target


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--desktop", action="store_true", help="also add an icon to the desktop")
    parser.add_argument("--normal-user", action="store_true", help="launch without requesting administrator privileges")
    args = parser.parse_args()
    install(args.desktop, args.normal_user)
