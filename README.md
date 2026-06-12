# net-pulse

A tiny Linux utility that alerts when a process is uploading or downloading above a small threshold.

It wraps `nethogs` because Linux does not expose clean, reliable per-process bandwidth counters through plain `/proc`. `nethogs` does the privileged network/process attribution; this script adds thresholds, cooldowns, and desktop notifications.

## What it does

- Watches per-process upload and download rates.
- Alerts when a process stays above your configured threshold.
- Uses desktop notifications through `notify-send`, with terminal output as a fallback.
- Lets you tune threshold, sample interval, consecutive samples, cooldown, and network interface.

Default behavior: alert when a process uploads or downloads at `16 KiB/s` or more for `2` consecutive samples, with a `30s` per-process cooldown.

## Install on Linux Mint / Ubuntu / Debian

```bash
sudo apt update
sudo apt install nethogs libnotify-bin python3
```

Then from this repo:

```bash
chmod +x netpulse.py
./netpulse.py
```

The script will relaunch itself through `sudo -E` because `nethogs` needs root privileges.

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

## Running at login

For interactive desktop alerts, the simplest reliable method is to start it from a terminal after login:

```bash
netpulse --up-kb 8 --down-kb 8
```

A root systemd service is included as an example in `netpulse.service.example`, but GUI notifications from root services are inherently annoying. For a service, consider using `--no-notify` and reading alerts with `journalctl`.

## Limitations

- Requires Linux and `nethogs`.
- Requires root privileges for packet/process attribution.
- Process attribution may be imperfect for very short bursts.
- Browser traffic will usually show under the browser process, not the individual tab.
- VPNs can make attribution look different depending on which interface is monitored.
- This is an alerting tool, not a firewall or blocker.

## Suggested first run

```bash
./netpulse.py --up-kb 8 --down-kb 8 --samples 2 --cooldown 20 --verbose
```

Then download a file or run a speed test and watch which process gets reported.
