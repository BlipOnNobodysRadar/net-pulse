import argparse
import unittest
from unittest.mock import Mock, patch

import netpulse
import netpulse_live
from netpulse_cycles import CycleRate, CycleSnapshot


class EmitSnapshotTests(unittest.TestCase):
    def args(self):
        return argparse.Namespace(
            up_kb=16.0,
            down_kb=16.0,
            either_kb=None,
            samples=2,
            cooldown=30.0,
            urgency="normal",
            verbose=False,
            no_notify=True,
            beep=False,
        )

    def snapshot(self):
        return CycleSnapshot(
            started_at=100.0,
            ended_at=101.0,
            interval_s=1.0,
            rates=(
                CycleRate(
                    key="pid:42:uid:1000:app:browser",
                    process="/usr/bin/browser/42/1000",
                    display_name="browser",
                    pid=42,
                    uid=1000,
                    protocol="TCP+UDP",
                    sent_kb_s=20.0,
                    recv_kb_s=5.0,
                ),
            ),
        )

    def test_one_completed_cycle_advances_alert_policy_once(self):
        samples = []
        cycles = []
        states = {}
        with patch.object(netpulse_live.netpulse, "process_rate_line") as process:
            netpulse_live._emit_snapshot(
                self.snapshot(),
                self.args(),
                states,
                samples.append,
                cycles.append,
                None,
            )

        process.assert_called_once()
        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0].sent_kb_s, 20.0)
        self.assertEqual(samples[0].protocol, "TCP+UDP")
        self.assertEqual(cycles, [self.snapshot()])

    def test_empty_cycle_still_reaches_dashboard_to_clear_ghost_rates(self):
        empty = CycleSnapshot(100.0, 101.0, 1.0, ())
        cycles = []
        with patch.object(netpulse_live.netpulse, "process_rate_line") as process:
            netpulse_live._emit_snapshot(
                empty,
                self.args(),
                {},
                None,
                cycles.append,
                None,
            )
        process.assert_not_called()
        self.assertEqual(cycles, [empty])


class DashboardCycleTests(unittest.TestCase):
    def test_record_cycle_zeros_processes_missing_from_latest_round(self):
        gui = netpulse_live.CycleAwareNetPulseGui.__new__(
            netpulse_live.CycleAwareNetPulseGui
        )
        gui.totals = {
            "active": netpulse.AppTotals("active", current_up=3.0, current_down=4.0),
            "gone": netpulse.AppTotals("gone", current_up=50.0, current_down=60.0),
        }
        gui.timeline = []
        gui.args = argparse.Namespace(graph_minutes=5.0)
        gui.completed_cycles = 0
        gui.started_at = 90.0
        gui.status_var = Mock()

        snapshot = CycleSnapshot(
            started_at=100.0,
            ended_at=101.0,
            interval_s=1.0,
            rates=(
                CycleRate(
                    key="active",
                    process="active",
                    display_name="active",
                    pid=None,
                    uid=None,
                    protocol="TCP",
                    sent_kb_s=3.0,
                    recv_kb_s=4.0,
                ),
            ),
        )

        gui.record_cycle(snapshot)

        self.assertEqual(gui.totals["active"].current_up, 3.0)
        self.assertEqual(gui.totals["gone"].current_up, 0.0)
        self.assertEqual(gui.totals["gone"].current_down, 0.0)
        self.assertEqual(gui.timeline, [(101.0, 3.0, 4.0)])
        self.assertEqual(gui.completed_cycles, 1)


if __name__ == "__main__":
    unittest.main()
