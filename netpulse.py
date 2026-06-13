#!/usr/bin/env python3
"""
netpulse: alert when a Linux process uploads/downloads above a small threshold.

This intentionally wraps nethogs instead of pretending /proc exposes reliable
per-process network byte counters. nethogs does the hard privileged attribution;
netpulse adds thresholding, cooldowns, desktop notifications, history, and an
optional Tk GUI with live graphs/overlay widgets.
"""

from __future__ import annotations

import argparse
import os
import pwd
import queue
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional


PROTOCOL_TOKENS = {"TCP", "UDP", "UNKNOWN", "?", "SCTP"}
SKIP_PREFIXES = (
    "refreshing",
    "waiting",
    "adding",
    "creating",
    "available",
    "device",
    "unknown option",
)
DEFAULT_HISTORY_DB = Path.home() / ".local" / "state" / "netpulse" / "history.sqlite3"


@dataclass(frozen=True)
class RateLine:
    raw: str
    process: str
    display_name: str
    pid: Optional[int]
    uid: Optional[int]
    protocol: Optional[str]
    sent_kb_s: float
    recv_kb_s: float

    @property
    def key(self) -> str:
        if self.pid is not None:
            return f"pid:{self.pid}"
        return f"proc:{self.process}"


@dataclass(frozen=True)
class TrafficSample:
    timestamp: float
    key: str
    process: str
    display_name: str
    pid: Optional[int]
    uid: Optional[int]
    protocol: Optional[str]
    sent_kb_s: float
    recv_kb_s: float
    interval_s: float = 1.0

    @property
    def sent_kib(self) -> float:
        return self.sent_kb_s * self.interval_s

    @property
    def recv_kib(self) -> float:
        return self.recv_kb_s * self.interval_s

    @property
    def total_kb_s(self) -> float:
        return self.sent_kb_s + self.recv_kb_s


@dataclass
class AlertState:
    up_streak: int = 0
    down_streak: int = 0
    either_streak: int = 0
    last_up_alert: float = 0.0
    last_down_alert: float = 0.0
    last_either_alert: float = 0.0


@dataclass
class AppTotals:
    display_name: str
    sent_kib: float = 0.0
    recv_kib: float = 0.0
    last_seen: float = 0.0
    current_up: float = 0.0
    current_down: float = 0.0
    peak_up: float = 0.0
    peak_down: float = 0.0

    @property
    def total_kib(self) -> float:
        return self.sent_kib + self.recv_kib


def is_number_token(token: str) -> bool:
    return re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", token) is not None


def _extract_pid_uid(process: str) -> tuple[Optional[int], Optional[int]]:
    """
    nethogs usually renders process identity as:
      /usr/lib/firefox/firefox/1234/1000
    meaning command/pid/uid.

    Keep this tolerant because nethogs output varies slightly across versions.
    """
    match = re.search(r"/(?P<pid>\d+)/(?P<uid>\d+)$", process)
    if not match:
        return None, None
    return int(match.group("pid")), int(match.group("uid"))


def _display_name(process: str, pid: Optional[int], uid: Optional[int]) -> str:
    if not process or process.lower() == "unknown":
        return "unknown"

    trimmed = process
    if pid is not None and uid is not None:
        suffix = f"/{pid}/{uid}"
        if trimmed.endswith(suffix):
            trimmed = trimmed[: -len(suffix)]

    base = Path(trimmed).name
    return base or trimmed


def parse_nethogs_line(line: str) -> Optional[RateLine]:
    """
    Parse common nethogs trace-mode lines.

    Common forms include:
      /usr/lib/firefox/firefox/1234/1000 TCP 0.123 456.789
      /usr/bin/python3/2222/1000 UDP 17.500 0.000 KB/sec
      unknown TCP 0.000 0.000
      total 12.34 56.78

    nethogs reports sent then received in KB/s when using view mode 0.
    """
    raw = line.rstrip("\n")
    stripped = raw.strip()
    if not stripped:
        return None

    lowered = stripped.lower()
    if lowered.startswith(SKIP_PREFIXES):
        return None
    if lowered.startswith("total"):
        return None
    if "sent" in lowered and "received" in lowered:
        return None

    tokens = stripped.split()
    numeric_positions = [(idx, float(tok)) for idx, tok in enumerate(tokens) if is_number_token(tok)]
    if len(numeric_positions) < 2:
        return None

    sent_idx, sent = numeric_positions[-2]
    recv_idx, recv = numeric_positions[-1]
    if recv_idx <= sent_idx:
        return None

    left_tokens = tokens[:sent_idx]
    if not left_tokens:
        return None

    protocol = None
    if left_tokens[-1].upper() in PROTOCOL_TOKENS:
        protocol = left_tokens[-1].upper()
        process_tokens = left_tokens[:-1]
    else:
        process_tokens = left_tokens

    process = " ".join(process_tokens).strip()
    if not process:
        return None

    pid, uid = _extract_pid_uid(process)
    return RateLine(
        raw=raw,
        process=process,
        display_name=_display_name(process, pid, uid),
        pid=pid,
        uid=uid,
        protocol=protocol,
        sent_kb_s=sent,
        recv_kb_s=recv,
    )


def human_rate(kb_s: float) -> str:
    if kb_s >= 1024 * 1024:
        return f"{kb_s / (1024 * 1024):.2f} GiB/s"
    if kb_s >= 1024:
        return f"{kb_s / 1024:.2f} MiB/s"
    return f"{kb_s:.1f} KiB/s"


def human_bytes_from_kib(kib: float) -> str:
    if kib >= 1024 * 1024:
        return f"{kib / (1024 * 1024):.2f} GiB"
    if kib >= 1024:
        return f"{kib / 1024:.2f} MiB"
    return f"{kib:.1f} KiB"


def default_history_path() -> Path:
    return DEFAULT_HISTORY_DB


class UsageHistory:
    """Small SQLite-backed store for process traffic samples and app rollups."""

    def __init__(self, path: Path, retention_hours: float = 24.0) -> None:
        self.path = path.expanduser()
        self.retention_hours = retention_hours
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()

    def _init_schema(self) -> None:
        with self.conn:
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS samples (
                    ts REAL NOT NULL,
                    process_key TEXT NOT NULL,
                    process TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    pid INTEGER,
                    uid INTEGER,
                    protocol TEXT,
                    sent_kb_s REAL NOT NULL,
                    recv_kb_s REAL NOT NULL,
                    interval_s REAL NOT NULL DEFAULT 1.0
                )
                """
            )
            columns = {row[1] for row in self.conn.execute("PRAGMA table_info(samples)")}
            if "interval_s" not in columns:
                self.conn.execute("ALTER TABLE samples ADD COLUMN interval_s REAL NOT NULL DEFAULT 1.0")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts)")
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_samples_display_ts ON samples(display_name, ts)"
            )

    def add(self, sample: TrafficSample) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                """
                INSERT INTO samples (
                    ts, process_key, process, display_name, pid, uid, protocol, sent_kb_s, recv_kb_s, interval_s
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sample.timestamp,
                    sample.key,
                    sample.process,
                    sample.display_name,
                    sample.pid,
                    sample.uid,
                    sample.protocol,
                    sample.sent_kb_s,
                    sample.recv_kb_s,
                    sample.interval_s,
                ),
            )

    def prune(self, now: Optional[float] = None) -> None:
        if self.retention_hours <= 0:
            return
        cutoff = (now or time.time()) - self.retention_hours * 3600
        with self._lock, self.conn:
            self.conn.execute("DELETE FROM samples WHERE ts < ?", (cutoff,))

    def top_apps(self, since_seconds: float = 3600, limit: int = 10) -> list[tuple[str, float, float]]:
        cutoff = time.time() - since_seconds
        with self._lock:
            rows = self.conn.execute(
                """
                SELECT display_name, SUM(sent_kb_s * interval_s), SUM(recv_kb_s * interval_s)
                FROM samples
                WHERE ts >= ?
                GROUP BY display_name
                ORDER BY SUM((sent_kb_s + recv_kb_s) * interval_s) DESC
                LIMIT ?
                """,
                (cutoff, limit),
            ).fetchall()
        return [(str(name), float(up or 0.0), float(down or 0.0)) for name, up, down in rows]

    def close(self) -> None:
        self.conn.close()


def desktop_notify(title: str, body: str, urgency: str = "normal") -> bool:
    """
    Send a Linux desktop notification.

    If running under sudo, try to send the notification to the original desktop
    user instead of root. If that fails, the caller can fall back to stdout.
    """
    notify_send = shutil.which("notify-send")
    if not notify_send:
        return False

    base_cmd = [notify_send, "-a", "netpulse", "-u", urgency, title, body]

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root" and os.geteuid() == 0:
        try:
            user_info = pwd.getpwnam(sudo_user)
            uid = user_info.pw_uid
            env_args = [
                f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
                f"XDG_RUNTIME_DIR=/run/user/{uid}",
            ]
            if os.environ.get("DISPLAY"):
                env_args.append(f"DISPLAY={os.environ['DISPLAY']}")
            cmd = ["sudo", "-u", sudo_user, "env", *env_args, *base_cmd]
            result = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=4,
                check=False,
            )
            return result.returncode == 0
        except Exception:
            return False

    try:
        result = subprocess.run(
            base_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=4,
            check=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def alert(args: argparse.Namespace, title: str, body: str, urgency: str = "normal") -> None:
    timestamp = time.strftime("%H:%M:%S")
    line = f"[{timestamp}] {title}: {body}"
    print(line, flush=True)

    if args.no_notify:
        return

    if not desktop_notify(title, body, urgency=urgency):
        if args.beep:
            print("\a", end="", flush=True)


def build_nethogs_command(args: argparse.Namespace) -> list[str]:
    nethogs = shutil.which("nethogs")
    if not nethogs:
        raise SystemExit(
            "nethogs is not installed. On Ubuntu/Mint/Debian: sudo apt install nethogs"
        )

    # stdbuf makes trace-mode output less likely to sit in a pipe buffer.
    cmd: list[str] = []
    if shutil.which("stdbuf"):
        cmd.extend(["stdbuf", "-oL"])

    cmd.extend([
        nethogs,
        "-t",             # trace mode, parseable-ish line output
        "-v", "0",        # KB/s view mode
        "-d", str(args.interval),
    ])

    if args.device:
        cmd.append(args.device)

    return cmd


def maybe_reexec_with_sudo(args: argparse.Namespace) -> None:
    if args.dry_run or args.no_sudo:
        return
    if os.name != "posix":
        return
    if os.geteuid() == 0:
        return

    sudo = shutil.which("sudo")
    if not sudo:
        raise SystemExit("This needs root privileges for nethogs, but sudo was not found.")

    script = str(Path(__file__).resolve())
    os.execvp(sudo, [sudo, "-E", sys.executable, script, *sys.argv[1:]])


def copy_stderr(pipe) -> None:
    try:
        for line in iter(pipe.readline, ""):
            if line:
                print(line.rstrip("\n"), file=sys.stderr, flush=True)
    except Exception:
        pass


def make_sample(rate: RateLine, timestamp: Optional[float] = None, interval_s: float = 1.0) -> TrafficSample:
    return TrafficSample(
        timestamp=timestamp or time.time(),
        key=rate.key,
        process=rate.process,
        display_name=rate.display_name,
        pid=rate.pid,
        uid=rate.uid,
        protocol=rate.protocol,
        sent_kb_s=rate.sent_kb_s,
        recv_kb_s=rate.recv_kb_s,
        interval_s=interval_s,
    )


def process_rate_line(
    args: argparse.Namespace,
    rate: RateLine,
    states: dict[str, AlertState],
    on_sample: Optional[Callable[[TrafficSample], None]] = None,
    notifier: Optional[Callable[[argparse.Namespace, str, str, str], None]] = None,
) -> None:
    state = states.setdefault(rate.key, AlertState())
    now = time.monotonic()
    sample = make_sample(rate, interval_s=getattr(args, "interval", 1.0))
    if on_sample:
        on_sample(sample)

    over_up = rate.sent_kb_s >= args.up_kb
    over_down = rate.recv_kb_s >= args.down_kb
    over_either = max(rate.sent_kb_s, rate.recv_kb_s) >= args.either_kb if args.either_kb is not None else False

    state.up_streak = state.up_streak + 1 if over_up else 0
    state.down_streak = state.down_streak + 1 if over_down else 0
    state.either_streak = state.either_streak + 1 if over_either else 0

    pid_part = f" pid {rate.pid}" if rate.pid is not None else ""
    proto_part = f" {rate.protocol}" if rate.protocol else ""
    body = (
        f"{rate.display_name}{pid_part}{proto_part} "
        f"up {human_rate(rate.sent_kb_s)}, down {human_rate(rate.recv_kb_s)}"
    )
    send_alert = notifier or alert

    if (
        over_up
        and state.up_streak >= args.samples
        and now - state.last_up_alert >= args.cooldown
    ):
        state.last_up_alert = now
        send_alert(args, "NetPulse upload", body, args.urgency)

    if (
        over_down
        and state.down_streak >= args.samples
        and now - state.last_down_alert >= args.cooldown
    ):
        state.last_down_alert = now
        send_alert(args, "NetPulse download", body, args.urgency)

    if (
        over_either
        and state.either_streak >= args.samples
        and now - state.last_either_alert >= args.cooldown
    ):
        state.last_either_alert = now
        send_alert(args, "NetPulse traffic", body, args.urgency)

    if args.verbose:
        print(
            f"{rate.display_name:24} up={human_rate(rate.sent_kb_s):>12} "
            f"down={human_rate(rate.recv_kb_s):>12} raw={rate.raw}",
            flush=True,
        )


def run_monitor(args: argparse.Namespace) -> int:
    maybe_reexec_with_sudo(args)

    if args.dry_run:
        examples = [
            "/usr/lib/firefox/firefox/1234/1000 TCP 0.123 456.789",
            "/usr/bin/python3/2222/1000 UDP 17.500 0.000 KB/sec",
            "unknown TCP 0.000 0.000",
            "total 12.34 56.78",
            "Refreshing:",
        ]
        for line in examples:
            parsed = parse_nethogs_line(line)
            print(f"{line!r} -> {parsed}")
        return 0

    history = None if args.no_history else UsageHistory(Path(args.history_db), args.history_retention_hours)
    last_prune = time.monotonic()

    def store_sample(sample: TrafficSample) -> None:
        nonlocal last_prune
        if history:
            history.add(sample)
            if time.monotonic() - last_prune > 300:
                history.prune(sample.timestamp)
                last_prune = time.monotonic()

    try:
        return stream_nethogs(args, on_sample=store_sample)
    finally:
        if history:
            history.close()


def stream_nethogs(
    args: argparse.Namespace,
    on_sample: Optional[Callable[[TrafficSample], None]] = None,
    notifier: Optional[Callable[[argparse.Namespace, str, str, str], None]] = None,
    stop_event: Optional[threading.Event] = None,
) -> int:
    cmd = build_nethogs_command(args)
    print("Starting:", " ".join(cmd), flush=True)
    print(
        f"Alert thresholds: upload >= {args.up_kb} KiB/s, "
        f"download >= {args.down_kb} KiB/s"
        + (f", either >= {args.either_kb} KiB/s" if args.either_kb is not None else "")
        + f" for {args.samples} consecutive sample(s). Cooldown: {args.cooldown}s.",
        flush=True,
    )

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        universal_newlines=True,
    )

    assert proc.stdout is not None
    assert proc.stderr is not None

    stderr_thread = threading.Thread(target=copy_stderr, args=(proc.stderr,), daemon=True)
    stderr_thread.start()

    states: dict[str, AlertState] = {}

    def stop_child(signum, frame):
        try:
            proc.terminate()
        except Exception:
            pass
        raise SystemExit(128 + signum)

    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, stop_child)
        signal.signal(signal.SIGTERM, stop_child)

    try:
        for line in proc.stdout:
            if stop_event and stop_event.is_set():
                break
            parsed = parse_nethogs_line(line)
            if parsed is None:
                continue
            process_rate_line(args, parsed, states, on_sample=on_sample, notifier=notifier)
    finally:
        try:
            proc.terminate()
        except Exception:
            pass

    return proc.wait()


class NetPulseGui:
    """Tk dashboard with live process table, graph, alert log, and compact overlay."""

    def __init__(self, args: argparse.Namespace) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.tk = tk
        self.ttk = ttk
        self.args = args
        self.root = tk.Tk()
        self.root.title("NetPulse")
        self.root.geometry("980x680")
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.stop_event = threading.Event()
        self.totals: dict[str, AppTotals] = {}
        self.timeline: list[tuple[float, float, float]] = []
        self.alerts: list[str] = []
        self.started_at = time.time()
        self.history = None if args.no_history else UsageHistory(Path(args.history_db), args.history_retention_hours)
        self.last_prune = time.monotonic()
        self.overlay = None
        self.overlay_label = None
        self._build_ui()

    def _build_ui(self) -> None:
        tk = self.tk
        ttk = self.ttk

        toolbar = ttk.Frame(self.root, padding=8)
        toolbar.pack(fill=tk.X)
        ttk.Label(toolbar, text="Upload KiB/s").pack(side=tk.LEFT)
        self.up_var = tk.StringVar(value=str(self.args.up_kb))
        ttk.Entry(toolbar, width=8, textvariable=self.up_var).pack(side=tk.LEFT, padx=(4, 12))
        ttk.Label(toolbar, text="Download KiB/s").pack(side=tk.LEFT)
        self.down_var = tk.StringVar(value=str(self.args.down_kb))
        ttk.Entry(toolbar, width=8, textvariable=self.down_var).pack(side=tk.LEFT, padx=(4, 12))
        ttk.Button(toolbar, text="Apply thresholds", command=self.apply_thresholds).pack(side=tk.LEFT)
        self.overlay_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(toolbar, text="Overlay", variable=self.overlay_var, command=self.toggle_overlay).pack(side=tk.LEFT, padx=12)
        ttk.Label(toolbar, text=f"History: {self.args.history_db}").pack(side=tk.RIGHT)

        summary = ttk.Frame(self.root, padding=(8, 0, 8, 8))
        summary.pack(fill=tk.X)
        self.summary_var = tk.StringVar(value="Waiting for nethogs samples…")
        ttk.Label(summary, textvariable=self.summary_var, font=("TkDefaultFont", 11, "bold")).pack(anchor=tk.W)

        self.graph = tk.Canvas(self.root, height=220, bg="#101820", highlightthickness=0)
        self.graph.pack(fill=tk.X, padx=8, pady=(0, 8))

        columns = ("app", "pid", "up", "down", "total", "peak", "last")
        self.table = ttk.Treeview(self.root, columns=columns, show="headings", height=12)
        headings = {
            "app": "App",
            "pid": "PID/key",
            "up": "Current up",
            "down": "Current down",
            "total": "Session total",
            "peak": "Peak up/down",
            "last": "Last seen",
        }
        widths = {"app": 180, "pid": 120, "up": 110, "down": 110, "total": 130, "peak": 150, "last": 90}
        for column in columns:
            self.table.heading(column, text=headings[column])
            self.table.column(column, width=widths[column], anchor=tk.W)
        self.table.pack(fill=tk.BOTH, expand=True, padx=8)

        bottom = ttk.LabelFrame(self.root, text="Alerts and threshold crossings", padding=8)
        bottom.pack(fill=tk.BOTH, expand=False, padx=8, pady=8)
        self.alert_text = tk.Text(bottom, height=6, wrap=tk.WORD)
        self.alert_text.pack(fill=tk.BOTH, expand=True)

        self.status_var = tk.StringVar(value="Starting monitor…")
        ttk.Label(self.root, textvariable=self.status_var, anchor=tk.W, padding=(8, 0, 8, 8)).pack(fill=tk.X)
        self.toggle_overlay()

    def apply_thresholds(self) -> None:
        try:
            self.args.up_kb = max(0.0, float(self.up_var.get()))
            self.args.down_kb = max(0.0, float(self.down_var.get()))
            self.status_var.set(
                f"Thresholds updated: up >= {self.args.up_kb} KiB/s, down >= {self.args.down_kb} KiB/s"
            )
        except ValueError:
            self.status_var.set("Threshold update ignored: enter numeric KiB/s values.")

    def toggle_overlay(self) -> None:
        tk = self.tk
        if self.overlay_var.get() and self.overlay is None:
            self.overlay = tk.Toplevel(self.root)
            self.overlay.title("NetPulse overlay")
            self.overlay.attributes("-topmost", True)
            self.overlay.geometry("320x120+30+30")
            self.overlay.configure(bg="#101820")
            self.overlay_label = tk.Label(
                self.overlay,
                text="NetPulse\nWaiting for samples…",
                fg="#f2f7ff",
                bg="#101820",
                justify=tk.LEFT,
                font=("TkDefaultFont", 10, "bold"),
                padx=12,
                pady=10,
            )
            self.overlay_label.pack(fill=tk.BOTH, expand=True)
            self.overlay.protocol("WM_DELETE_WINDOW", lambda: self.overlay_var.set(False) or self.toggle_overlay())
        elif not self.overlay_var.get() and self.overlay is not None:
            self.overlay.destroy()
            self.overlay = None
            self.overlay_label = None

    def on_sample(self, sample: TrafficSample) -> None:
        self.events.put(("sample", sample))

    def on_alert(self, args: argparse.Namespace, title: str, body: str, urgency: str) -> None:
        alert(args, title, body, urgency)
        self.events.put(("alert", f"[{time.strftime('%H:%M:%S')}] {title}: {body}"))

    def start(self) -> int:
        maybe_reexec_with_sudo(self.args)
        self.worker = threading.Thread(target=self._run_worker, daemon=True)
        self.worker.start()
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.after(250, self.drain_events)
        self.root.mainloop()
        if self.history:
            self.history.close()
        return 0

    def _run_worker(self) -> None:
        try:
            code = stream_nethogs(
                self.args,
                on_sample=self.on_sample,
                notifier=self.on_alert,
                stop_event=self.stop_event,
            )
            self.events.put(("status", f"nethogs exited with status {code}"))
        except Exception as exc:
            self.events.put(("status", f"Monitor failed: {exc}"))

    def drain_events(self) -> None:
        processed = 0
        while processed < 200:
            try:
                kind, payload = self.events.get_nowait()
            except queue.Empty:
                break
            processed += 1
            if kind == "sample":
                self.record_sample(payload)  # type: ignore[arg-type]
            elif kind == "alert":
                self.record_alert(str(payload))
            elif kind == "status":
                self.status_var.set(str(payload))
        self.refresh_ui()
        self.root.after(500, self.drain_events)

    def record_sample(self, sample: TrafficSample) -> None:
        elapsed = max(self.args.interval, sample.timestamp - self.started_at)
        total = self.totals.setdefault(sample.key, AppTotals(sample.display_name))
        total.display_name = sample.display_name
        total.sent_kib += sample.sent_kib
        total.recv_kib += sample.recv_kib
        total.last_seen = sample.timestamp
        total.current_up = sample.sent_kb_s
        total.current_down = sample.recv_kb_s
        total.peak_up = max(total.peak_up, sample.sent_kb_s)
        total.peak_down = max(total.peak_down, sample.recv_kb_s)
        self.timeline.append((sample.timestamp, sample.sent_kb_s, sample.recv_kb_s))
        cutoff = sample.timestamp - max(60.0, self.args.graph_minutes * 60.0)
        self.timeline = [point for point in self.timeline if point[0] >= cutoff]
        if self.history:
            self.history.add(sample)
            if time.monotonic() - self.last_prune > 300:
                self.history.prune(sample.timestamp)
                self.last_prune = time.monotonic()
        self.status_var.set(f"Tracking {len(self.totals)} processes for {elapsed / 60:.1f} minutes")

    def record_alert(self, line: str) -> None:
        self.alerts.append(line)
        self.alerts = self.alerts[-100:]
        self.alert_text.insert(self.tk.END, line + "\n")
        self.alert_text.see(self.tk.END)

    def refresh_ui(self) -> None:
        now = time.time()
        for item in self.table.get_children():
            self.table.delete(item)
        rows = sorted(self.totals.items(), key=lambda item: item[1].total_kib, reverse=True)[: self.args.top]
        for key, total in rows:
            age = max(0.0, now - total.last_seen)
            self.table.insert(
                "",
                self.tk.END,
                values=(
                    total.display_name,
                    key,
                    human_rate(total.current_up),
                    human_rate(total.current_down),
                    human_bytes_from_kib(total.total_kib),
                    f"{human_rate(total.peak_up)} / {human_rate(total.peak_down)}",
                    f"{age:.0f}s ago",
                ),
            )
        up = sum(total.current_up for total in self.totals.values())
        down = sum(total.current_down for total in self.totals.values())
        session = sum(total.total_kib for total in self.totals.values())
        top_text = ", ".join(f"{total.display_name} {human_bytes_from_kib(total.total_kib)}" for _, total in rows[:3])
        self.summary_var.set(
            f"Live up {human_rate(up)} · down {human_rate(down)} · session {human_bytes_from_kib(session)}"
            + (f" · top: {top_text}" if top_text else "")
        )
        self.draw_graph()
        if self.overlay_label:
            overlay_lines = [
                "NetPulse overlay",
                f"↑ {human_rate(up)}   ↓ {human_rate(down)}",
                f"Session {human_bytes_from_kib(session)}",
            ]
            overlay_lines.extend(f"{total.display_name}: {human_rate(total.current_up + total.current_down)}" for _, total in rows[:3])
            self.overlay_label.configure(text="\n".join(overlay_lines))

    def draw_graph(self) -> None:
        canvas = self.graph
        canvas.delete("all")
        width = max(1, canvas.winfo_width())
        height = max(1, canvas.winfo_height())
        pad = 28
        canvas.create_text(12, 10, text="Live bandwidth history", fill="#f2f7ff", anchor=self.tk.W)
        canvas.create_line(pad, height - pad, width - pad, height - pad, fill="#425466")
        canvas.create_line(pad, pad, pad, height - pad, fill="#425466")
        if not self.timeline:
            canvas.create_text(width / 2, height / 2, text="Waiting for traffic samples", fill="#9fb3c8")
            return
        points = self.timeline[-500:]
        start = points[0][0]
        end = max(points[-1][0], start + 1)
        max_rate = max(max(up, down, self.args.up_kb, self.args.down_kb) for _, up, down in points)
        max_rate = max(max_rate, 1.0)

        def xy(ts: float, rate: float) -> tuple[float, float]:
            x = pad + (ts - start) / (end - start) * (width - 2 * pad)
            y = height - pad - (rate / max_rate) * (height - 2 * pad)
            return x, y

        up_line: list[float] = []
        down_line: list[float] = []
        for ts, up, down in points:
            up_line.extend(xy(ts, up))
            down_line.extend(xy(ts, down))
        if len(up_line) >= 4:
            canvas.create_line(*up_line, fill="#ffb020", width=2, smooth=True)
            canvas.create_line(*down_line, fill="#36c5f0", width=2, smooth=True)
        for threshold, color, label in ((self.args.up_kb, "#ffb020", "up threshold"), (self.args.down_kb, "#36c5f0", "down threshold")):
            _, y = xy(end, threshold)
            canvas.create_line(pad, y, width - pad, y, fill=color, dash=(4, 3))
            canvas.create_text(width - pad - 4, y - 8, text=label, fill=color, anchor=self.tk.E)
        canvas.create_text(pad, height - 8, text="old", fill="#9fb3c8", anchor=self.tk.W)
        canvas.create_text(width - pad, height - 8, text="now", fill="#9fb3c8", anchor=self.tk.E)
        canvas.create_text(width - pad, pad, text=human_rate(max_rate), fill="#9fb3c8", anchor=self.tk.E)

    def close(self) -> None:
        self.stop_event.set()
        self.root.after(100, self.root.destroy)


def run_gui(args: argparse.Namespace) -> int:
    try:
        app = NetPulseGui(args)
    except ImportError as exc:
        raise SystemExit(f"Tkinter is required for --gui: {exc}") from exc
    return app.start()


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Alert when a Linux process uploads/downloads above a threshold.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the Tk dashboard with live graph, process table, alert log, and overlay.",
    )
    parser.add_argument(
        "--up-kb",
        type=float,
        default=16.0,
        help="Upload threshold in KiB/s per process.",
    )
    parser.add_argument(
        "--down-kb",
        type=float,
        default=16.0,
        help="Download threshold in KiB/s per process.",
    )
    parser.add_argument(
        "--either-kb",
        type=float,
        default=None,
        help="Optional threshold for either direction. Disabled unless set.",
    )
    parser.add_argument(
        "-i",
        "--interval",
        type=float,
        default=1.0,
        help="nethogs sampling interval in seconds.",
    )
    parser.add_argument(
        "-s",
        "--samples",
        type=int,
        default=2,
        help="Consecutive over-threshold samples required before alerting.",
    )
    parser.add_argument(
        "-c",
        "--cooldown",
        type=float,
        default=30.0,
        help="Minimum seconds between repeated alerts for the same process/direction.",
    )
    parser.add_argument(
        "-d",
        "--device",
        default=None,
        help="Network interface to monitor, e.g. eth0, wlan0, enp5s0, tun0. Omit for nethogs default.",
    )
    parser.add_argument(
        "--history-db",
        default=str(default_history_path()),
        help="SQLite file used to persist per-app traffic samples over time.",
    )
    parser.add_argument(
        "--history-retention-hours",
        type=float,
        default=24.0,
        help="Hours of detailed samples to retain in the history database. Use 0 to keep all samples.",
    )
    parser.add_argument(
        "--no-history",
        action="store_true",
        help="Disable SQLite traffic history recording.",
    )
    parser.add_argument(
        "--graph-minutes",
        type=float,
        default=10.0,
        help="Minutes of live samples to show in the GUI graph.",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=12,
        help="Number of processes to show in GUI top-usage table.",
    )
    parser.add_argument(
        "--no-notify",
        action="store_true",
        help="Print alerts only; do not use notify-send.",
    )
    parser.add_argument(
        "--beep",
        action="store_true",
        help="Terminal bell if desktop notification fails.",
    )
    parser.add_argument(
        "--urgency",
        choices=["low", "normal", "critical"],
        default="normal",
        help="Desktop notification urgency.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print every parsed process rate line.",
    )
    parser.add_argument(
        "--no-sudo",
        action="store_true",
        help="Do not auto-relaunch through sudo. Useful inside containers/tests.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Test parser without launching nethogs.",
    )
    return parser.parse_args(argv)


def main() -> int:
    args = parse_args()
    if args.samples < 1:
        raise SystemExit("--samples must be >= 1")
    if args.interval <= 0:
        raise SystemExit("--interval must be > 0")
    if args.cooldown < 0:
        raise SystemExit("--cooldown must be >= 0")
    if args.history_retention_hours < 0:
        raise SystemExit("--history-retention-hours must be >= 0")
    if args.graph_minutes <= 0:
        raise SystemExit("--graph-minutes must be > 0")
    if args.top < 1:
        raise SystemExit("--top must be >= 1")
    if args.gui:
        return run_gui(args)
    return run_monitor(args)


if __name__ == "__main__":
    raise SystemExit(main())
