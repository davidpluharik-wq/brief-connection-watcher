# Brief Connection Watcher

Observe ARP traffic and flag brief observed sessions.

## Setup

Python 3.10+ on a Linux desktop.
From this folder:

```sh
sudo apt install python3-venv python3-tk iproute2 tcpdump
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python3 brief_connection_watcher.py
```

`./run.sh` works from any directory and uses `.venv/bin/python` when present,
otherwise `python3` from your current environment. Install OS dependencies
separately. No launcher installs packages automatically.

## Desktop launcher

```sh
python3 install-launcher.py --desktop
```

Run the installer as your normal desktop user. It adds the app to your application
menu and desktop with its bundled icon. Omit `--desktop` for a menu entry only.
Keep the checkout in place; rerun the installer after moving it. On desktops that
ask, choose **Allow Launching** or **Mark as Trusted** for the desktop shortcut.

The icon requests administrator authentication through PolicyKit (`pkexec`).
Install your distribution's PolicyKit package and use an X11 desktop session.
For a standard user icon instead, add `--normal-user` when installing.
For administrator launch from a graphical terminal, use `./run-admin.sh`.
This preserves X11 display authentication and uses this project's virtual
environment. Elevated sessions store home-directory settings and exports as root;
desktop notifications may be unavailable. Native Wayland elevation is unsupported.

## Checks

```sh
python3 -m compileall -q -x '/\.venv/' .
# For GUI tests, install xvfb and xauth, then run:
xvfb-run -a python3 -m unittest discover -s tests -v
bash -n *.sh
```

The GitHub Actions workflow runs these offline checks on Python 3.10, 3.12 and
3.13 and 3.14. It checks GUI construction under a virtual X11 display, without live network
operations or administrator authentication. Hardware behavior needs local testing.

## Repository use

This folder is self-contained: copy it into its own GitHub repository with its
hidden `.github/` and `.gitignore` files. No sibling projects are required.
Generated data, credentials, captures and virtual environments are ignored.
No license has been selected; add your chosen LICENSE before distributing under
an open-source license.

Requires packet-capture privileges (normally root). From an X11 terminal:
`./run-admin.sh` (uses `.venv` when present).
ARP silence is a gap in observed traffic, not proof of a device disconnecting.

## Troubleshooting

- Missing Python module: install `requirements.txt` into `.venv` if provided.
- Missing `tkinter`: install the Python Tk package from your OS package manager.
- A command is unavailable: install the corresponding OS package listed above.
- Icons stopped working after moving the checkout: rerun `install-launcher.py`.
