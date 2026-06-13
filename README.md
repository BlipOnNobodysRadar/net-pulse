# net-pulse

A tiny Linux utility that alerts when a process is uploading or downloading above a small threshold — now with an optional GUI dashboard, always-on-top overlay, persistent per-app history, and live bandwidth graphs.

It wraps `nethogs` because Linux does not expose clean, reliable per-process bandwidth counters through plain `/proc`. `nethogs` does the privileged network/process attribution; this script adds thresholds, cooldowns, desktop notifications, SQLite history, and a Tk-based UI.

## What it does

- Watches per-process upload and download rates.
- Alerts when a process stays above your configured threshold.
- Uses desktop notifications through `notify-send`, with terminal output as a fallback.
- Records per-app traffic samples to a local SQLite database so usage can be reviewed over time.
- Provides a GUI dashboard with:
  - live upload/download graph with threshold overlays,
  - sortable-style top usage table for current app/process traffic,
  - session totals, peaks, and last-seen ages,
  - alert log for threshold crossings,
  - compact always-on-top overlay for at-a-glance bandwidth.
- Lets you tune threshold, sample interval, consecutive samples, cooldown, network interface, history retention, graph window, and number of top apps.

Default behavior: alert when a process uploads or downloads at `16 KiB/s` or more for `2` consecutive samples, with a `30s` per-process cooldown. History is stored at `~/.local/state/netpulse/history.sqlite3` and detailed samples are retained for `24` hours by default.

## Install on Linux Mint / Ubuntu / Debian

```bash
sudo apt update
sudo apt install nethogs libnotify-bin python3 python3-tk
```

Then from this repo:

```bash
chmod +x netpulse.py
./netpulse.py
```

The script will relaunch itself through `sudo -E` because `nethogs` needs root privileges.

## GUI dashboard

Start the dashboard:

```bash
./netpulse.py --gui
```

Useful GUI options:

```bash
./netpulse.py --gui --graph-minutes 30 --top 20
```

```bash
./netpulse.py --gui --up-kb 8 --down-kb 32 --samples 2 --cooldown 20
```

The GUI includes editable upload/download threshold fields. Click **Apply thresholds** to adjust threshold lines and future alerts while the monitor is running. The overlay is enabled by default and can be toggled from the toolbar.

> Note: GUI mode uses Python's built-in Tk bindings (`python3-tk` on Debian/Ubuntu/Mint). Because `nethogs` requires privileges, the app still uses the same sudo relaunch behavior as terminal mode.

## History tracking

By default, every parsed traffic sample is written to SQLite:

```text
~/.local/state/netpulse/history.sqlite3
```

Customize or disable history:

```bash
./netpulse.py --history-db ~/.cache/netpulse.sqlite3 --history-retention-hours 72
```

```bash
./netpulse.py --no-history
```

Retention applies to detailed samples. Use `--history-retention-hours 0` to keep all samples. The repository `.gitignore` excludes local SQLite databases, WAL/SHM sidecars, and logs because history can contain process names, PIDs, UIDs, and app usage patterns from your machine.

## Common commands

Very sensitive, low threshold:

```bash
./netpulse.py --up-kb 4 --down-kb 4
```

Less noisy:

```bash
./netpulse.py --up-kb 64 --down-kb 128 --samples 3 --cooldown 60
```

Print every parsed rate line:

```bash
./netpulse.py --verbose
```

Monitor a specific interface:

```bash
ip -br link
./netpulse.py --device enp5s0
```

For Wi-Fi the interface might be something like `wlp4s0`. For Ethernet it might be `enp5s0`, `eno1`, or similar. If you use a VPN, try both your physical interface and the VPN interface, often `tun0` or a WireGuard-style interface, because attribution can differ depending on where packets are observed.

Parser smoke test without running `nethogs`:

```bash
./netpulse.py --dry-run
```

## Optional install helper

```bash
./install.sh
```

This installs dependencies and symlinks `netpulse.py` to `/usr/local/bin/netpulse`.

Then run:

```bash
netpulse --up-kb 8 --down-kb 8
```

Or launch the GUI:

```bash
netpulse --gui
```

## Running at login

For interactive desktop alerts, the simplest reliable method is to start it from a terminal after login:

```bash
netpulse --gui --up-kb 8 --down-kb 8
```

A root systemd service is included as an example in `netpulse.service.example`, but GUI notifications from root services are inherently annoying. For a service, consider using `--no-notify` and reading alerts with `journalctl`.

## Limitations

- Requires Linux and `nethogs`.
- GUI mode requires Tk (`python3-tk` on Debian/Ubuntu/Mint).
- Requires root privileges for packet/process attribution.
- Process attribution may be imperfect for very short bursts.
- Browser traffic will usually show under the browser process, not the individual tab.
- VPNs can make attribution look different depending on which interface is monitored.
- This is an alerting and visibility tool, not a firewall or blocker.

## Suggested first run

```bash
./netpulse.py --gui --up-kb 8 --down-kb 8 --samples 2 --cooldown 20 --verbose
```

Then download a file or run a speed test and watch which process gets reported in the table, graph, overlay, and alert log.
