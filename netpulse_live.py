#!/usr/bin/env python3
"""Cycle-correct NetPulse entry point.

This companion command uses the existing NetPulse parser, alert policy, history
store, and Tk widgets while feeding them completed nethogs sampling cycles.
"""

from __future__ import annotations

import argparse
import os
import queue
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Optional

import netpulse
from netpulse_cycles import CycleSnapshot, TraceCycleAssembler, is_cycle_boundary


def _emit_snapshot(
    snapshot: Optional[CycleSnapshot],
    on_sample: Optional[Callable[[netpulse.TrafficSample], None]],
    on_cycle: Optional[Callable[[CycleSnapshot], None]],
) -> None:
    if snapshot is None:
        return
    if on_sample:
        for rate in snapshot.rates:
            on_sample(
                netpulse.TrafficSample(
                    timestamp=snapshot.ended_at,
                    key=rate.key,
                    process=rate.process,
                    display_name=rate.display_name,
                    pid=rate.pid,
                    uid=rate.uid,
                    protocol=rate.protocol,
                    sent_kb_s=rate.sent_kb_s,
                    recv_kb_s=rate.recv_kb_s,
                    interval_s=snapshot.interval_s,
                )
            )
    if on_cycle:
        on_cycle(snapshot)


def stream_nethogs_cycles(
    args: argparse.Namespace,
    on_sample: Optional[Callable[[netpulse.TrafficSample], None]] = None,
    on_cycle: Optional[Callable[[CycleSnapshot], None]] = None,
    notifier: Optional[Callable[[argparse.Namespace, str, str, str], None]] = None,
    stop_event: Optional[threading.Event] = None,
) -> int:
    cmd = netpulse.build_nethogs_command(args)
    print("Starting cycle-aware stream:", " ".join(cmd), flush=True)
    print(
        f"Alert thresholds: upload >= {args.up_kb} KiB/s, "
        f"download >= {args.down_kb} KiB/s"
        + (f", either >= {args.either_kb} KiB/s" if args.either_kb is not None else "")
        + f" for {args.samples} completed sample(s). Cooldown: {args.cooldown}s.",
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

    stderr_thread = threading.Thread(
        target=netpulse.copy_stderr,
        args=(proc.stderr,),
        name="nethogs-stderr",
        daemon=True,
    )
    stderr_thread.start()

    assembler = TraceCycleAssembler(args.interval)
    states: dict[str, netpulse.AlertState] = {}

    def stop_child(signum, frame):
        try:
            proc.terminate()
        except OSError:
            pass
        raise SystemExit(128 + signum)

    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, stop_child)
        signal.signal(signal.SIGTERM, stop_child)

    try:
        for line in proc.stdout:
            if stop_event and stop_event.is_set():
                break
            now = time.time()
            if is_cycle_boundary(line):
                _emit_snapshot(assembler.boundary(now), on_sample, on_cycle)
                continue

            rate = netpulse.parse_nethogs_line(line)
            if rate is None:
                continue

            # Keep the original per-process threshold/cooldown policy, but defer
            # history and dashboard updates until the cycle is internally complete.
            netpulse.process_rate_line(
                args,
                rate,
                states,
                on_sample=None,
                notifier=notifier,
            )
            assembler.add_rate(
                timestamp=now,
                process=rate.process,
                display_name=rate.display_name,
                pid=rate.pid,
                uid=rate.uid,
                protocol=rate.protocol,
                sent_kb_s=rate.sent_kb_s,
                recv_kb_s=rate.recv_kb_s,
            )
    finally:
        _emit_snapshot(assembler.finish(time.time()), on_sample, on_cycle)
        try:
            proc.terminate()
        except OSError:
            pass

    return proc.wait()


def _reexec_this_script_with_sudo(args: argparse.Namespace) -> None:
    if args.dry_run or args.no_sudo or os.name != "posix" or os.geteuid() == 0:
        return
    sudo = shutil.which("sudo")
    if not sudo:
        raise SystemExit("This needs root privileges for nethogs, but sudo was not found.")
    script = str(Path(__file__).resolve())
    os.execvp(sudo, [sudo, "-E", sys.executable, script, *sys.argv[1:]])


class CycleAwareNetPulseGui(netpulse.NetPulseGui):
    """Use completed sampling cycles for current totals and graph points."""

    def __init__(self, args: argparse.Namespace) -> None:
        super().__init__(args)
        self.completed_cycles = 0

    def _run_worker(self) -> None:
        try:
            code = stream_nethogs_cycles(
                self.args,
                on_sample=self.on_sample,
                on_cycle=self.on_cycle,
                notifier=self.on_alert,
                stop_event=self.stop_event,
            )
            self.events.put(("status", f"nethogs exited with status {code}"))
        except Exception as exc:
            self.events.put(("status", f"Monitor failed: {exc}"))

    def on_cycle(self, snapshot: CycleSnapshot) -> None:
        self.events.put(("cycle", snapshot))

    def drain_events(self) -> None:
        processed = 0
        while processed < 500:
            try:
                kind, payload = self.events.get_nowait()
            except queue.Empty:
                break
            processed += 1
            if kind == "sample":
                self.record_sample(payload)  # type: ignore[arg-type]
            elif kind == "cycle":
                self.record_cycle(payload)  # type: ignore[arg-type]
            elif kind == "alert":
                self.record_alert(str(payload))
            elif kind == "status":
                self.status_var.set(str(payload))
        self.refresh_ui()
        self.root.after(250, self.drain_events)

    def record_sample(self, sample: netpulse.TrafficSample) -> None:
        total = self.totals.setdefault(sample.key, netpulse.AppTotals(sample.display_name))
        total.display_name = sample.display_name
        total.sent_kib += sample.sent_kib
        total.recv_kib += sample.recv_kib
        total.last_seen = sample.timestamp
        total.current_up = sample.sent_kb_s
        total.current_down = sample.recv_kb_s
        total.peak_up = max(total.peak_up, sample.sent_kb_s)
        total.peak_down = max(total.peak_down, sample.recv_kb_s)

        if self.history:
            self.history.add(sample)
            if time.monotonic() - self.last_prune > 300:
                self.history.prune(sample.timestamp)
                self.last_prune = time.monotonic()

    def record_cycle(self, snapshot: CycleSnapshot) -> None:
        active_keys = snapshot.keys
        for key, total in self.totals.items():
            if key not in active_keys:
                total.current_up = 0.0
                total.current_down = 0.0

        self.timeline.append(
            (snapshot.ended_at, snapshot.total_sent_kb_s, snapshot.total_recv_kb_s)
        )
        cutoff = snapshot.ended_at - max(60.0, self.args.graph_minutes * 60.0)
        self.timeline = [point for point in self.timeline if point[0] >= cutoff]
        self.completed_cycles += 1
        elapsed = max(0.0, snapshot.ended_at - self.started_at)
        self.status_var.set(
            f"{self.completed_cycles} completed cycles · "
            f"{len(active_keys)} active processes · {elapsed / 60:.1f} minutes"
        )


def run_cycle_monitor(args: argparse.Namespace) -> int:
    history = None if args.no_history else netpulse.UsageHistory(
        Path(args.history_db), args.history_retention_hours
    )
    last_prune = time.monotonic()

    def store_sample(sample: netpulse.TrafficSample) -> None:
        nonlocal last_prune
        if not history:
            return
        history.add(sample)
        if time.monotonic() - last_prune > 300:
            history.prune(sample.timestamp)
            last_prune = time.monotonic()

    try:
        return stream_nethogs_cycles(args, on_sample=store_sample)
    finally:
        if history:
            history.close()


def main() -> int:
    args = netpulse.parse_args()
    if args.dry_run:
        return netpulse.run_monitor(args)

    _reexec_this_script_with_sudo(args)
    # Prevent the imported entry point from re-execing netpulse.py instead of us.
    args.no_sudo = True

    if args.gui:
        try:
            return CycleAwareNetPulseGui(args).start()
        except ImportError as exc:
            raise SystemExit(f"Tkinter is required for --gui: {exc}") from exc
    return run_cycle_monitor(args)


if __name__ == "__main__":
    raise SystemExit(main())
