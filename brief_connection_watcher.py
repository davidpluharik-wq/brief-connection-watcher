#!/usr/bin/env python3
"""
Brief Connection Watcher
--------------------------
Passively listens to ARP traffic on your network interface (using scapy)
and tracks how long each device is visible. Unlike periodic nmap scans,
this catches devices that connect for only a few seconds, because it's
always listening rather than checking in on a timer.

Requirements:
  - scapy:  python -m pip install -r requirements.txt
            (or: sudo apt install python3-scapy)
  - tkinter (usually pre-installed; if missing: sudo apt install python3-tk)
  - Root privileges (raw socket access is required to sniff packets):

        sudo -E env DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY python3 brief_connection_watcher.py

How it works:
  - Every ARP packet seen updates a MAC's "last seen" time.
  - If a MAC hasn't been seen for STALE_TIMEOUT seconds, its session is
    considered closed, and its total visible duration is computed.
  - Sessions shorter than BRIEF_THRESHOLD seconds are flagged as a
    "brief connection" — the kind of thing a periodic scan would miss
    entirely — and you get a popup + log entry for it.
"""

import queue
import subprocess
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime

try:
    from scapy.all import sniff, ARP, get_if_list
except (ImportError, OSError):
    sniff = None  # handled at startup with a friendly error

STALE_TIMEOUT = 6      # seconds of silence before we consider a device "gone"
BRIEF_THRESHOLD = 10   # sessions shorter than this many seconds get flagged


class SnifferThread(threading.Thread):
    """Sniffs ARP packets and tracks per-MAC session start/end times."""

    def __init__(self, iface: str, event_queue: queue.Queue):
        super().__init__(daemon=True)
        self.iface = iface
        self.event_queue = event_queue
        self._stop_flag = threading.Event()
        self.active_sessions = {}  # mac -> {"ip":..., "first_seen":..., "last_seen":...}
        self.lock = threading.Lock()

    def stop(self):
        self._stop_flag.set()

    def _handle_packet(self, pkt):
        if not pkt.haslayer(ARP):
            return
        mac = pkt[ARP].hwsrc
        ip = pkt[ARP].psrc
        now = time.time()

        with self.lock:
            if mac not in self.active_sessions:
                self.active_sessions[mac] = {"ip": ip, "first_seen": now, "last_seen": now}
                self.event_queue.put(("device_appeared", {"mac": mac, "ip": ip, "time": now}))
            else:
                self.active_sessions[mac]["last_seen"] = now
                self.active_sessions[mac]["ip"] = ip  # update in case of IP change (DHCP)

    def _check_stale_sessions(self):
        """Runs periodically to close out sessions that have gone quiet."""
        now = time.time()
        with self.lock:
            stale_macs = [
                mac for mac, s in self.active_sessions.items()
                if now - s["last_seen"] > STALE_TIMEOUT
            ]
            for mac in stale_macs:
                session = self.active_sessions.pop(mac)
                duration = session["last_seen"] - session["first_seen"]
                self.event_queue.put(("session_closed", {
                    "mac": mac,
                    "ip": session["ip"],
                    "duration": duration,
                    "first_seen": session["first_seen"],
                    "last_seen": session["last_seen"],
                }))

    def run(self):
        if sniff is None:
            self.event_queue.put(("error", "scapy is not installed. Run: python -m pip install -r requirements.txt"))
            return

        last_stale_check = time.time()
        try:
            while not self._stop_flag.is_set():
                try:
                    sniff(iface=self.iface, filter="arp", prn=self._handle_packet,
                          store=False, timeout=1)
                except PermissionError:
                    self.event_queue.put(("error", "Permission denied. This app needs root — see the instructions at the top of the script."))
                    return
                except OSError as e:
                    self.event_queue.put(("error", f"Network error: {e}"))
                    return

                if time.time() - last_stale_check >= 1:
                    self._check_stale_sessions()
                    last_stale_check = time.time()
        finally:
            # Flush remaining active sessions as closed on shutdown, so nothing is lost
            with self.lock:
                for mac, session in self.active_sessions.items():
                    duration = session["last_seen"] - session["first_seen"]
                    self.event_queue.put(("session_closed", {
                        "mac": mac,
                        "ip": session["ip"],
                        "duration": duration,
                        "first_seen": session["first_seen"],
                        "last_seen": session["last_seen"],
                    }))


class BriefConnectionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Brief Connection Watcher")
        self.root.geometry("880x560")
        self.root.minsize(700, 420)

        self.event_queue = queue.Queue()
        self.sniffer_thread = None
        self.active_rows = {}  # mac -> treeview item id (active table)

        self._build_ui()
        self._poll_queue()
        self._tick_active_table()

    # ---------------- UI ----------------

    def _build_ui(self):
        controls = ttk.Frame(self.root, padding=10)
        controls.pack(fill="x")

        ttk.Label(controls, text="Interface:").grid(row=0, column=0, sticky="w")
        self.iface_combo = ttk.Combobox(controls, width=15, state="readonly")
        self.iface_combo["values"] = self._list_interfaces()
        if self.iface_combo["values"]:
            self.iface_combo.current(0)
        self.iface_combo.grid(row=0, column=1, padx=(5, 15))

        self.start_button = ttk.Button(controls, text="Start Listening", command=self.start_listening)
        self.start_button.grid(row=0, column=2, padx=5)

        self.stop_button = ttk.Button(controls, text="Stop", command=self.stop_listening, state="disabled")
        self.stop_button.grid(row=0, column=3, padx=5)

        self.status_label = ttk.Label(controls, text="Idle.", foreground="#555")
        self.status_label.grid(row=0, column=4, padx=20)

        # Split view: active devices (top), session history (bottom)
        paned = ttk.PanedWindow(self.root, orient="vertical")
        paned.pack(fill="both", expand=True, padx=10, pady=5)

        active_frame = ttk.Frame(paned)
        ttk.Label(active_frame, text="Currently Active Devices:").pack(anchor="w")
        active_columns = ("ip", "mac", "seen_for")
        self.active_tree = ttk.Treeview(active_frame, columns=active_columns, show="headings", height=6)
        for col, label, width in [("ip", "IP Address", 150), ("mac", "MAC Address", 180), ("seen_for", "Seen For", 100)]:
            self.active_tree.heading(col, text=label)
            self.active_tree.column(col, width=width, anchor="w")
        self.active_tree.pack(fill="both", expand=True)
        paned.add(active_frame, weight=1)

        history_frame = ttk.Frame(paned)
        ttk.Label(history_frame, text="Connection History (most recent first):").pack(anchor="w")
        history_columns = ("time", "ip", "mac", "duration", "flag")
        self.history_tree = ttk.Treeview(history_frame, columns=history_columns, show="headings", height=10)
        for col, label, width in [
            ("time", "Ended At", 120),
            ("ip", "IP Address", 140),
            ("mac", "MAC Address", 170),
            ("duration", "Duration", 90),
            ("flag", "Note", 220),
        ]:
            self.history_tree.heading(col, text=label)
            self.history_tree.column(col, width=width, anchor="w")
        self.history_tree.tag_configure("brief", background="#ffd6d6")
        self.history_tree.pack(fill="both", expand=True)
        paned.add(history_frame, weight=2)

        # Log area
        log_frame = ttk.Frame(self.root, padding=10)
        log_frame.pack(fill="both", expand=False)
        ttk.Label(log_frame, text="Activity Log:").pack(anchor="w")
        self.log_text = tk.Text(log_frame, height=6, state="disabled", wrap="word", bg="#111", fg="#ddd")
        self.log_text.pack(fill="both", expand=True)

    def _list_interfaces(self):
        try:
            result = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True, timeout=5)
            names = []
            for line in result.stdout.splitlines():
                parts = line.split(":")
                if len(parts) > 1:
                    name = parts[1].strip().split("@")[0]
                    if name != "lo":
                        names.append(name)
            return names
        except Exception:
            if sniff is not None:
                try:
                    return get_if_list()
                except Exception:
                    return []
            return []

    # ---------------- Actions ----------------

    def start_listening(self):
        if sniff is None:
            messagebox.showerror("scapy not found", "Install scapy first:\npython -m pip install -r requirements.txt")
            return

        iface = self.iface_combo.get()
        if not iface:
            messagebox.showerror("No interface", "Please select a network interface.")
            return

        self.sniffer_thread = SnifferThread(iface, self.event_queue)
        self.sniffer_thread.start()

        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.iface_combo.config(state="disabled")
        self.status_label.config(text=f"Listening on {iface}...")
        self._log(f"Started listening on {iface}.")

    def stop_listening(self):
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.sniffer_thread = None
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.iface_combo.config(state="readonly")
        self.status_label.config(text="Stopped.")
        self._log("Stopped listening.")

    # ---------------- Queue polling ----------------

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()

                if kind == "device_appeared":
                    self._log(f"Device appeared: {payload['ip']} ({payload['mac']})")

                elif kind == "session_closed":
                    self._add_history_row(payload)
                    if payload["mac"] in self.active_rows:
                        self.active_tree.delete(self.active_rows.pop(payload["mac"]))

                elif kind == "error":
                    self.status_label.config(text=f"Error: {payload}")
                    self._log(f"ERROR: {payload}")
                    messagebox.showerror("Error", payload)

        except queue.Empty:
            pass

        self.root.after(300, self._poll_queue)

    def _tick_active_table(self):
        """Refreshes the 'currently active' table every second based on live sessions."""
        if self.sniffer_thread:
            with self.sniffer_thread.lock:
                sessions = dict(self.sniffer_thread.active_sessions)

            seen_macs = set(sessions.keys())

            # Remove rows for devices no longer active (already closed via queue, but just in case)
            for mac in list(self.active_rows.keys()):
                if mac not in seen_macs:
                    self.active_tree.delete(self.active_rows.pop(mac))

            # Add/update rows
            now = time.time()
            for mac, session in sessions.items():
                seen_for = f"{now - session['first_seen']:.0f}s"
                if mac in self.active_rows:
                    self.active_tree.item(self.active_rows[mac], values=(session["ip"], mac, seen_for))
                else:
                    item_id = self.active_tree.insert("", "end", values=(session["ip"], mac, seen_for))
                    self.active_rows[mac] = item_id

        self.root.after(1000, self._tick_active_table)

    # ---------------- Helpers ----------------

    def _add_history_row(self, payload):
        ended_at = datetime.fromtimestamp(payload["last_seen"]).strftime("%H:%M:%S")
        duration = payload["duration"]
        is_brief = duration < BRIEF_THRESHOLD
        note = f"⚠ Brief connection ({duration:.1f}s)" if is_brief else "Normal session"

        self.history_tree.insert("", 0, values=(
            ended_at, payload["ip"], payload["mac"], f"{duration:.1f}s", note
        ), tags=("brief",) if is_brief else ())

        self._log(f"Session ended: {payload['ip']} ({payload['mac']}) — {duration:.1f}s — {note}")

        if is_brief:
            try:
                subprocess.run(["notify-send", "Brief connection detected!",
                                 f"{payload['ip']} ({payload['mac']}) was on the network for only {duration:.1f}s"],
                                check=False, timeout=5)
            except Exception:
                pass

    def _log(self, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")


def main():
    root = tk.Tk()
    app = BriefConnectionApp(root)

    def on_close():
        if app.sniffer_thread:
            app.sniffer_thread.stop()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
