import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from netpulse import parse_nethogs_line


def test_parse_firefox_line():
    line = "/usr/lib/firefox/firefox/1234/1000 TCP 0.123 456.789"
    parsed = parse_nethogs_line(line)
    assert parsed is not None
    assert parsed.display_name == "firefox"
    assert parsed.pid == 1234
    assert parsed.uid == 1000
    assert parsed.sent_kb_s == 0.123
    assert parsed.recv_kb_s == 456.789


def test_ignore_total():
    assert parse_nethogs_line("total 12.34 56.78") is None


def test_parse_unknown():
    parsed = parse_nethogs_line("unknown TCP 0.000 1.000")
    assert parsed is not None
    assert parsed.display_name == "unknown"
    assert parsed.pid is None
    assert parsed.recv_kb_s == 1.0
