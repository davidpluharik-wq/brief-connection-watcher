import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class LauncherTests(unittest.TestCase):
    def test_installer_handles_checkout_paths_with_spaces(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory) / "checkout with spaces"
            checkout.mkdir()
            shutil.copy2(ROOT / "install-launcher.py", checkout)
            shutil.copytree(ROOT / "assets", checkout / "assets")
            spec = importlib.util.spec_from_file_location("installer", checkout / "install-launcher.py")
            installer = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(installer)
            data = Path(directory) / "application data"
            with patch.dict(os.environ, {"XDG_DATA_HOME": str(data)}):
                launcher = installer.install()
                text = launcher.read_text()
                expected = "run-admin.sh" if installer.ADMIN else "run.sh"
                self.assertIn('Exec=/bin/bash "' + str(checkout / expected) + '"', text)
                self.assertIn("Icon=" + str(checkout / "assets/icon.png"), text)
                installer.install(normal_user=True)
                self.assertIn('Exec=/bin/bash "' + str(checkout / "run.sh") + '"', launcher.read_text())
            if shutil.which("desktop-file-validate"):
                subprocess.run(["desktop-file-validate", str(launcher)], check=True)

    def test_run_uses_checkout_environment_and_preserves_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory) / "checkout with spaces"
            interpreter = checkout / ".venv/bin/python"
            interpreter.parent.mkdir(parents=True)
            interpreter.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
            interpreter.chmod(0o755)
            shutil.copy2(ROOT / "run.sh", checkout)
            result = subprocess.run(["bash", str(checkout / "run.sh"), "argument with spaces"],
                                    cwd="/", capture_output=True, text=True, check=True)
            self.assertEqual(result.stdout.splitlines(),
                             [str(checkout / 'brief_connection_watcher.py'), "argument with spaces"])


    @unittest.skipIf(os.geteuid() == 0, "authentication wrapper requires a non-root test user")
    def test_admin_wrapper_preserves_display_without_forwarding_other_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory) / "checkout with spaces"
            checkout.mkdir()
            shutil.copy2(ROOT / "run-admin.sh", checkout)
            commands = Path(directory) / "commands"
            commands.mkdir()
            fake_pkexec = commands / "pkexec"
            fake_pkexec.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
            fake_pkexec.chmod(0o755)
            env = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ.get("PATH", ""),
                       DISPLAY=":123", XAUTHORITY="/tmp/auth with spaces", PRIVATE_TEST_TOKEN="do-not-forward")
            result = subprocess.run(["bash", str(checkout / "run-admin.sh"), "argument with spaces"],
                                    env=env, capture_output=True, text=True, check=True)
            args = result.stdout.splitlines()
            self.assertEqual(args[0], "/usr/bin/env")
            self.assertIn("DISPLAY=:123", args)
            self.assertIn("XAUTHORITY=/tmp/auth with spaces", args)
            self.assertEqual(args[-3:], ["/bin/bash", str(checkout / "run.sh"), "argument with spaces"])
            self.assertNotIn("PRIVATE_TEST_TOKEN=do-not-forward", args)


@unittest.skipUnless(os.environ.get("DISPLAY"), "GUI startup check requires X11 or xvfb-run")
class DesktopTests(unittest.TestCase):
    def test_main_opens_and_closes_without_callback_errors(self):
        import brief_connection_watcher as app
        import tkinter as tk
        from tkinter import messagebox
        real_tk = tk.Tk
        callback_errors = []

        def temporary_window():
            window = real_tk()
            window.report_callback_exception = lambda *error: callback_errors.append(error)
            window.after(200, window.destroy)
            return window

        with tempfile.TemporaryDirectory() as directory:
            # No network commands or privilege prompts during construction.
            with patch.object(tk, "Tk", side_effect=temporary_window), \
                 patch.object(messagebox, "showwarning"), \
                 patch("subprocess.run", return_value=subprocess.CompletedProcess([], 1, "", "")), \
                 patch.object(app, "DB_PATH", str(Path(directory) / "test.db"), create=True):
                app.main()
        self.assertEqual(callback_errors, [])
