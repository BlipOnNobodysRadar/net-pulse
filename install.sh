#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if command -v apt >/dev/null 2>&1; then
  sudo apt update
  sudo apt install -y nethogs libnotify-bin python3 python3-tk
else
  echo "apt not found. Install nethogs, libnotify/notify-send, and python3 with your distro package manager."
fi

chmod +x netpulse.py netpulse_live.py
sudo ln -sf "$PWD/netpulse.py" /usr/local/bin/netpulse
sudo ln -sf "$PWD/netpulse_live.py" /usr/local/bin/netpulse-live

echo "Installed symlinks: /usr/local/bin/netpulse and /usr/local/bin/netpulse-live"
echo "Try: netpulse-live --gui --up-kb 8 --down-kb 8"
