from __future__ import annotations

import subprocess
import sys
import xml.etree.ElementTree as ET
import tkinter as tk
from tkinter import ttk, messagebox
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional
import threading

# ── Timezone ──────────────────────────────────────────────────────────────────
CST = timezone(timedelta(hours=-6))

# ── Event constants ───────────────────────────────────────────────────────────
EVENT_LOGON_SUCCESS = 4624

HUMAN_LOGON_TYPES = {2, 3, 7, 10, 11}

SYSTEM_ACCOUNTS = {
    "-", "", "ANONYMOUS LOGON", "SYSTEM",
    "LOCAL SERVICE", "NETWORK SERVICE",
}

LOGON_TYPE_NAMES = {
    2:  "Interactive",
    3:  "Network (SSH/SMB)",
    7:  "Unlock",
    10: "Remote (RDP)",
    11: "Cached",
}

DEFAULT_COUNT = 50000

COLUMNS = ("User", "Domain", "Time", "Type", "Computer", "IP")

# ── Data class ────────────────────────────────────────────────────────────────
@dataclass
class Login:
    user: str
    domain: str
    logon_type: int
    logon_type_name: str
    time: datetime
    computer: str
    ip: str


# ── Parsing helpers ───────────────────────────────────────────────────────────
def run_wevtutil(count: int) -> str:
    query = f"*[System[EventID={EVENT_LOGON_SUCCESS}]]"
    cmd = [
        "wevtutil", "qe", "Security",
        f"/q:{query}", "/f:xml", f"/c:{count}", "/rd:true",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        msg = (result.stderr or result.stdout).strip()
        raise RuntimeError(msg if msg else "wevtutil failed.")
    return result.stdout.strip()


def wrap_xml(xml_text: str) -> str:
    cleaned = "\n".join(
        line for line in xml_text.splitlines()
        if not line.strip().startswith("<?xml")
    )
    return f"<Events>{cleaned}</Events>"


def ns(tag: str) -> str:
    return f"{{http://schemas.microsoft.com/win/2004/08/events/event}}{tag}"


def get_field(event_elem: ET.Element, name: str) -> str:
    event_data = event_elem.find(ns("EventData"))
    if event_data is None:
        return ""
    for item in event_data.findall(ns("Data")):
        if item.attrib.get("Name") == name:
            return (item.text or "").strip()
    return ""


def get_system_field(event_elem: ET.Element, tag: str) -> str:
    system = event_elem.find(ns("System"))
    if system is None:
        return ""
    elem = system.find(ns(tag))
    if elem is None or elem.text is None:
        return ""
    return elem.text.strip()


def parse_time(event_elem: ET.Element) -> Optional[datetime]:
    system = event_elem.find(ns("System"))
    if system is None:
        return None
    tc = system.find(ns("TimeCreated"))
    if tc is None:
        return None
    raw = tc.attrib.get("SystemTime", "")
    if not raw:
        return None
    try:
        base = raw.rstrip("Z")
        if "." in base:
            dt_part, frac = base.split(".", 1)
            frac = (frac + "000000")[:6]
            base = f"{dt_part}.{frac}"
        return datetime.fromisoformat(base).replace(tzinfo=timezone.utc)
    except Exception:
        return None


def parse_login(event_elem: ET.Element) -> Optional[Login]:
    logon_type_str = get_field(event_elem, "LogonType")
    try:
        logon_type = int(logon_type_str)
    except ValueError:
        return None

    if logon_type not in HUMAN_LOGON_TYPES:
        return None

    user = get_field(event_elem, "TargetUserName")
    domain = get_field(event_elem, "TargetDomainName")

    if not user or user in SYSTEM_ACCOUNTS or user.endswith("$"):
        return None

    time = parse_time(event_elem)
    if time is None:
        return None

    computer = get_system_field(event_elem, "Computer") or "-"

    ip = get_field(event_elem, "IpAddress")
    if not ip or ip in ("-", "::1", "::"):
        ip = get_field(event_elem, "WorkstationName") or "-"

    return Login(
        user=user,
        domain=domain,
        logon_type=logon_type,
        logon_type_name=LOGON_TYPE_NAMES.get(logon_type, str(logon_type)),
        time=time,
        computer=computer,
        ip=ip,
    )


def fmt_time(dt: datetime) -> str:
    return dt.astimezone(CST).strftime("%Y-%m-%d %H:%M:%S CST")


def fetch_logins(count: int) -> List[Login]:
    raw_xml = run_wevtutil(count)
    if not raw_xml:
        return []
    root = ET.fromstring(wrap_xml(raw_xml))

    logins: List[Login] = []
    for event_elem in root.findall(ns("Event")):
        login = parse_login(event_elem)
        if login is not None:
            logins.append(login)

    # Deduplicate by (user, second)
    seen: Dict[tuple, Login] = {}
    for login in logins:
        key = (login.user, login.time.strftime("%Y-%m-%d %H:%M:%S"))
        if key not in seen:
            seen[key] = login
    logins = list(seen.values())
    logins.sort(key=lambda l: l.time, reverse=True)
    return logins


# ── GUI ───────────────────────────────────────────────────────────────────────
class LoginViewer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Log and Key - Windows Login Viewer")
        self.geometry("1050x580")
        self.minsize(700, 400)
        self.configure(bg="#1a1a2e")
        self._build_ui()
        self._refresh()

    def _build_ui(self):
        # ── Header bar ────────────────────────────────────────────────────────
        header = tk.Frame(self, bg="#16213e", pady=10)
        header.pack(fill="x")

        tk.Label(
            header, text="Log and Key - Windows Login Viewer",
            bg="#16213e", fg="#e0e0e0",
            font=("Consolas", 16, "bold"),
        ).pack(side="left", padx=16)

        # Refresh button
        ctrl = tk.Frame(header, bg="#16213e")
        ctrl.pack(side="right", padx=16)

        self._refresh_btn = tk.Button(
            ctrl, text="⟳  Refresh",
            bg="#0f3460", fg="#e0e0e0",
            activebackground="#1a5276", activeforeground="white",
            relief="flat", font=("Consolas", 10, "bold"),
            cursor="hand2", padx=12, pady=4,
            command=self._refresh,
        )
        self._refresh_btn.pack(side="left")

        # ── Status bar ────────────────────────────────────────────────────────
        self._status_var = tk.StringVar(value="Loading...")
        status_bar = tk.Frame(self, bg="#16213e", pady=5)
        status_bar.pack(fill="x", side="bottom")
        tk.Label(
            status_bar, textvariable=self._status_var,
            bg="#16213e", fg="#888", font=("Consolas", 9),
        ).pack(side="left", padx=16)

        # ── Table ─────────────────────────────────────────────────────────────
        table_frame = tk.Frame(self, bg="#1a1a2e")
        table_frame.pack(fill="both", expand=True, padx=12, pady=(8, 0))

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview",
            background="#1a1a2e",
            foreground="#e0e0e0",
            fieldbackground="#1a1a2e",
            rowheight=26,
            font=("Consolas", 10),
        )
        style.configure("Treeview.Heading",
            background="#0f3460",
            foreground="#e0e0e0",
            font=("Consolas", 10, "bold"),
            relief="flat",
        )
        style.map("Treeview",
            background=[("selected", "#0f3460")],
            foreground=[("selected", "#ffffff")],
        )
        style.map("Treeview.Heading",
            background=[("active", "#1a5276")],
        )

        self._tree = ttk.Treeview(
            table_frame,
            columns=COLUMNS,
            show="headings",
            selectmode="browse",
        )

        col_widths = {
            "User": 220, "Domain": 140, "Time": 200,
            "Type": 140, "Computer": 100, "IP": 110,
        }
        for col in COLUMNS:
            self._tree.heading(col, text=col, command=lambda c=col: self._sort(c))
            self._tree.column(col, width=col_widths[col], anchor="w", minwidth=60)

        # Alternating row colours
        self._tree.tag_configure("odd",  background="#1a1a2e")
        self._tree.tag_configure("even", background="#16213e")

        # Type-specific highlight colours
        self._tree.tag_configure("unlock",      foreground="#5dade2")
        self._tree.tag_configure("interactive", foreground="#58d68d")
        self._tree.tag_configure("network",     foreground="#f39c12")
        self._tree.tag_configure("rdp",         foreground="#a569bd")

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=scrollbar.set)

        self._tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self._sort_col = "Time"
        self._sort_asc = False

    def _type_tag(self, logon_type: int, row_tag: str) -> tuple:
        type_tag = {
            7:  "unlock",
            2:  "interactive",
            3:  "network",
            10: "rdp",
        }.get(logon_type, "")
        return (row_tag, type_tag) if type_tag else (row_tag,)

    def _populate(self, logins: List[Login]):
        self._logins = logins
        self._tree.delete(*self._tree.get_children())
        for i, l in enumerate(logins):
            row_tag = "even" if i % 2 == 0 else "odd"
            tags = self._type_tag(l.logon_type, row_tag)
            self._tree.insert("", "end", values=(
                l.user,
                l.domain,
                fmt_time(l.time),
                l.logon_type_name,
                l.computer,
                l.ip,
            ), tags=tags)

        count = len(logins)
        self._status_var.set(
            f"{count} login{'s' if count != 1 else ''} found  •  "
            f"Last refreshed: {datetime.now().strftime('%H:%M:%S')}"
        )

    def _sort(self, col: str):
        if self._sort_col == col:
            self._sort_asc = not self._sort_asc
        else:
            self._sort_col = col
            self._sort_asc = True

        reverse = not self._sort_asc
        key_map = {
            "User":     lambda l: l.user.lower(),
            "Domain":   lambda l: l.domain.lower(),
            "Time":     lambda l: l.time,
            "Type":     lambda l: l.logon_type_name,
            "Computer": lambda l: l.computer.lower(),
            "IP":       lambda l: l.ip,
        }
        logins = sorted(self._logins, key=key_map[col], reverse=reverse)
        self._populate(logins)

    def _refresh(self):
        self._refresh_btn.config(state="disabled", text="Loading...")
        self._status_var.set("Fetching events...")

        def worker():
            try:
                logins = fetch_logins(DEFAULT_COUNT)
                self.after(0, lambda: self._populate(logins))
            except RuntimeError as e:
                self.after(0, lambda: self._on_error(str(e)))
            finally:
                self.after(0, lambda: self._refresh_btn.config(
                    state="normal", text="⟳  Refresh"
                ))

        threading.Thread(target=worker, daemon=True).start()

    def _on_error(self, msg: str):
        self._status_var.set(f"Error: {msg}")
        messagebox.showerror(
            "Error",
            f"{msg}\n\nMake sure you are running as Administrator.",
        )


if __name__ == "__main__":
    app = LoginViewer()
    app.mainloop()