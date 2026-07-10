#!/usr/bin/env python3
"""Cycle-aware helpers for NetPulse's nethogs trace stream.

nethogs trace mode emits one line per process and uses ``Refreshing:`` as a
sampling-cycle boundary. Treating each process line as an independent time
point makes aggregate graphs and "current" totals misleading. This module
turns the line stream into completed, internally consistent sampling cycles.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass(frozen=True)
class CycleRate:
    key: str
    process: str
    display_name: str
    pid: Optional[int]
    uid: Optional[int]
    protocol: Optional[str]
    sent_kb_s: float
    recv_kb_s: float


@dataclass(frozen=True)
class CycleSnapshot:
    started_at: float
    ended_at: float
    interval_s: float
    rates: tuple[CycleRate, ...]

    @property
    def total_sent_kb_s(self) -> float:
        return sum(rate.sent_kb_s for rate in self.rates)

    @property
    def total_recv_kb_s(self) -> float:
        return sum(rate.recv_kb_s for rate in self.rates)

    @property
    def keys(self) -> frozenset[str]:
        return frozenset(rate.key for rate in self.rates)


@dataclass
class _MutableRate:
    key: str
    process: str
    display_name: str
    pid: Optional[int]
    uid: Optional[int]
    protocols: set[str]
    sent_kb_s: float = 0.0
    recv_kb_s: float = 0.0

    def freeze(self) -> CycleRate:
        protocol = "+".join(sorted(self.protocols)) if self.protocols else None
        return CycleRate(
            key=self.key,
            process=self.process,
            display_name=self.display_name,
            pid=self.pid,
            uid=self.uid,
            protocol=protocol,
            sent_kb_s=self.sent_kb_s,
            recv_kb_s=self.recv_kb_s,
        )


def is_cycle_boundary(line: str) -> bool:
    return line.strip().lower().startswith("refreshing")


def stable_process_key(
    *,
    process: str,
    display_name: str,
    pid: Optional[int],
    uid: Optional[int],
) -> str:
    """Avoid folding a recycled PID into an unrelated process's session total."""
    if pid is None:
        return f"proc:{process}"
    uid_part = "?" if uid is None else str(uid)
    return f"pid:{pid}:uid:{uid_part}:app:{display_name}"


class TraceCycleAssembler:
    """Accumulate parsed nethogs rows until the next refresh boundary."""

    def __init__(self, expected_interval_s: float = 1.0) -> None:
        if expected_interval_s <= 0:
            raise ValueError("expected_interval_s must be positive")
        self.expected_interval_s = float(expected_interval_s)
        self._started_at: Optional[float] = None
        self._rates: dict[str, _MutableRate] = {}

    def add_rate(
        self,
        *,
        timestamp: float,
        process: str,
        display_name: str,
        pid: Optional[int],
        uid: Optional[int],
        protocol: Optional[str],
        sent_kb_s: float,
        recv_kb_s: float,
    ) -> None:
        if self._started_at is None:
            self._started_at = timestamp

        key = stable_process_key(
            process=process,
            display_name=display_name,
            pid=pid,
            uid=uid,
        )
        current = self._rates.get(key)
        if current is None:
            current = _MutableRate(
                key=key,
                process=process,
                display_name=display_name,
                pid=pid,
                uid=uid,
                protocols=set(),
            )
            self._rates[key] = current

        if protocol:
            current.protocols.add(protocol)
        current.sent_kb_s += max(0.0, float(sent_kb_s))
        current.recv_kb_s += max(0.0, float(recv_kb_s))

    def boundary(self, timestamp: float) -> Optional[CycleSnapshot]:
        """Finish the previous cycle and begin a new one at ``timestamp``."""
        if self._started_at is None:
            self._started_at = timestamp
            return None

        snapshot = self._snapshot(timestamp)
        self._started_at = timestamp
        self._rates = {}
        return snapshot

    def finish(self, timestamp: float) -> Optional[CycleSnapshot]:
        """Flush the final partial cycle at process exit."""
        if self._started_at is None or not self._rates:
            return None
        snapshot = self._snapshot(timestamp)
        self._started_at = None
        self._rates = {}
        return snapshot

    def _snapshot(self, timestamp: float) -> CycleSnapshot:
        assert self._started_at is not None
        measured = timestamp - self._started_at
        interval = self._effective_interval(measured)
        rates = tuple(
            rate.freeze()
            for rate in sorted(
                self._rates.values(),
                key=lambda item: (item.display_name.lower(), item.key),
            )
        )
        return CycleSnapshot(
            started_at=self._started_at,
            ended_at=timestamp,
            interval_s=interval,
            rates=rates,
        )

    def _effective_interval(self, measured: float) -> float:
        # Preserve ordinary scheduling jitter, but do not turn suspend/resume
        # gaps into fictional multi-hour transfer totals.
        lower = self.expected_interval_s * 0.25
        upper = max(self.expected_interval_s * 4.0, self.expected_interval_s + 5.0)
        if measured < lower or measured > upper:
            return self.expected_interval_s
        return measured


def aggregate_rates(rates: Iterable[CycleRate]) -> tuple[float, float]:
    sent = 0.0
    received = 0.0
    for rate in rates:
        sent += rate.sent_kb_s
        received += rate.recv_kb_s
    return sent, received
