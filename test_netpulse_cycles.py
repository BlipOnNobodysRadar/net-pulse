import unittest

from netpulse_cycles import TraceCycleAssembler, is_cycle_boundary, stable_process_key


class CycleAssemblerTests(unittest.TestCase):
    def setUp(self):
        self.assembler = TraceCycleAssembler(expected_interval_s=1.0)

    def add(
        self,
        timestamp,
        *,
        process="/usr/bin/firefox/10/1000",
        name="firefox",
        pid=10,
        uid=1000,
        protocol="TCP",
        sent=1.0,
        recv=2.0,
    ):
        self.assembler.add_rate(
            timestamp=timestamp,
            process=process,
            display_name=name,
            pid=pid,
            uid=uid,
            protocol=protocol,
            sent_kb_s=sent,
            recv_kb_s=recv,
        )

    def test_first_boundary_starts_cycle_without_emitting_empty_snapshot(self):
        self.assertIsNone(self.assembler.boundary(100.0))
        self.add(100.1)
        snapshot = self.assembler.boundary(101.0)
        self.assertIsNotNone(snapshot)
        self.assertEqual(len(snapshot.rates), 1)

    def test_duplicate_pid_protocol_rows_are_aggregated(self):
        self.assembler.boundary(100.0)
        self.add(100.1, protocol="TCP", sent=3.0, recv=4.0)
        self.add(100.2, protocol="UDP", sent=5.0, recv=6.0)
        snapshot = self.assembler.boundary(101.0)
        rate = snapshot.rates[0]
        self.assertEqual(rate.sent_kb_s, 8.0)
        self.assertEqual(rate.recv_kb_s, 10.0)
        self.assertEqual(rate.protocol, "TCP+UDP")
        self.assertEqual(snapshot.total_sent_kb_s, 8.0)
        self.assertEqual(snapshot.total_recv_kb_s, 10.0)

    def test_absent_process_does_not_leak_into_next_cycle(self):
        self.assembler.boundary(100.0)
        self.add(100.1)
        first = self.assembler.boundary(101.0)
        second = self.assembler.boundary(102.0)
        self.assertEqual(len(first.rates), 1)
        self.assertEqual(second.rates, ())
        self.assertEqual(second.keys, frozenset())

    def test_measured_jitter_becomes_history_interval(self):
        self.assembler.boundary(100.0)
        self.add(100.1)
        snapshot = self.assembler.boundary(101.25)
        self.assertAlmostEqual(snapshot.interval_s, 1.25)

    def test_suspend_gap_falls_back_to_expected_interval(self):
        self.assembler.boundary(100.0)
        self.add(100.1)
        snapshot = self.assembler.boundary(1000.0)
        self.assertEqual(snapshot.interval_s, 1.0)

    def test_finish_flushes_partial_cycle_once(self):
        self.add(100.0)
        snapshot = self.assembler.finish(101.0)
        self.assertIsNotNone(snapshot)
        self.assertIsNone(self.assembler.finish(102.0))


class HelpersTests(unittest.TestCase):
    def test_refresh_marker_detection_is_case_and_whitespace_tolerant(self):
        self.assertTrue(is_cycle_boundary("  Refreshing:  \n"))
        self.assertFalse(is_cycle_boundary("firefox TCP 1 2"))

    def test_stable_key_disambiguates_pid_reuse_by_app(self):
        firefox = stable_process_key(
            process="/usr/bin/firefox/42/1000",
            display_name="firefox",
            pid=42,
            uid=1000,
        )
        curl = stable_process_key(
            process="/usr/bin/curl/42/1000",
            display_name="curl",
            pid=42,
            uid=1000,
        )
        self.assertNotEqual(firefox, curl)


if __name__ == "__main__":
    unittest.main()
