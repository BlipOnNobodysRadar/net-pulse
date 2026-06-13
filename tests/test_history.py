import argparse
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from netpulse import TrafficSample, UsageHistory, parse_args, parse_nethogs_line, process_rate_line


def test_usage_history_tracks_top_apps(tmp_path):
    db_path = tmp_path / "history.sqlite3"
    history = UsageHistory(db_path, retention_hours=24)
    try:
        now = time.time()
        history.add(
            TrafficSample(
                timestamp=now,
                key="pid:1",
                process="/usr/bin/curl/1/1000",
                display_name="curl",
                pid=1,
                uid=1000,
                protocol="TCP",
                sent_kb_s=3.0,
                recv_kb_s=7.0,
                interval_s=2.0,
            )
        )
        assert history.top_apps(since_seconds=60, limit=1) == [("curl", 6.0, 14.0)]
    finally:
        history.close()


def test_process_rate_line_emits_samples_and_alerts():
    args = argparse.Namespace(
        up_kb=4.0,
        down_kb=100.0,
        either_kb=None,
        samples=1,
        cooldown=0.0,
        urgency="normal",
        verbose=False,
        interval=2.0,
    )
    parsed = parse_nethogs_line("/usr/bin/curl/42/1000 TCP 5.000 1.000")
    samples = []
    alerts = []

    process_rate_line(
        args,
        parsed,
        {},
        on_sample=samples.append,
        notifier=lambda _args, title, body, urgency: alerts.append((title, body, urgency)),
    )

    assert samples[0].display_name == "curl"
    assert samples[0].sent_kb_s == 5.0
    assert samples[0].sent_kib == 10.0
    assert alerts[0][0] == "NetPulse upload"


def test_gui_and_history_options_parse():
    args = parse_args(["--gui", "--history-db", "/tmp/netpulse.db", "--graph-minutes", "5", "--top", "3"])
    assert args.gui is True
    assert args.history_db == "/tmp/netpulse.db"
    assert args.graph_minutes == 5
    assert args.top == 3
