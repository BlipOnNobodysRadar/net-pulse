#!/usr/bin/env python3
"""
netpulse: alert when a Linux process uploads/downloads above a small threshold.

This intentionally wraps nethogs instead of pretending /proc exposes reliable
per-process network byte counters. nethogs does the hard privileged attribution;
netpulse adds thresholding, cooldowns, and notifications.
"""

from __future__ import annotations

import argparse
import os
import pwd
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


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


@dataclass
class AlertState:
    up_streak: int = 0
    down_streak: int = 0
    either_streak: int = 0
    last_up_alert: float = 0.0
    last_down_alert: float = 0.0
    last_either_alert: float = 0.0


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


def process_rate_line(
    args: argparse.Namespace,
    rate: RateLine,
    states: dict[str, AlertState],
) -> None:
    state = states.setdefault(rate.key, AlertState())
    now = time.monotonic()

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

    if (
        over_up
        and state.up_streak >= args.samples
        and now - state.last_up_alert >= args.cooldown
    ):
        state.last_up_alert = now
        alert(args, "NetPulse upload", body, urgency=args.urgency)

    if (
        over_down
        and state.down_streak >= args.samples
        and now - state.last_down_alert >= args.cooldown
    ):
        state.last_down_alert = now
        alert(args, "NetPulse download", body, urgency=args.urgency)

    if (
        over_either
        and state.either_streak >= args.samples
        and now - state.last_either_alert >= args.cooldown
    ):
        state.last_either_alert = now
        alert(args, "NetPulse traffic", body, urgency=args.urgency)

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

    signal.signal(signal.SIGINT, stop_child)
    signal.signal(signal.SIGTERM, stop_child)

    try:
        for line in proc.stdout:
            parsed = parse_nethogs_line(line)
            if parsed is None:
                continue
            process_rate_line(args, parsed, states)
    finally:
        try:
            proc.terminate()
        except Exception:
            pass

    return proc.wait()


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Alert when a Linux process uploads/downloads above a threshold.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
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
    return run_monitor(args)


if __name__ == "__main__":
    raise SystemExit(main())
