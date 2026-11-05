#!/usr/bin/env bash
# Install the claude-ip-control guard as a boot-time systemd service.
# Usage: sudo deploy/linux/install.sh [guard.json]   (run from the repository after `go build`)
# With a config argument it is installed (the previous one is backed up).
# Without one, an existing /etc/claude-ip-control/guard.json is kept and the
# placeholder example is only installed when none exists.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
bin="$repo/claude-ip-control"
[ -x "$bin" ] || { echo "build first: go build -o claude-ip-control ./cmd/claude-ip-control" >&2; exit 1; }
command -v nft >/dev/null || { echo "nft (nftables) is required" >&2; exit 1; }

echo "== remove the earlier test setup (transient unit + legacy test table), if present"
systemctl stop claude-ip-control.service 2>/dev/null || true
systemctl reset-failed claude-ip-control.service 2>/dev/null || true
if nft list table inet claude_ip_control >/dev/null 2>&1; then
  "$bin" clear
fi

echo "== install files"
install -D -m 0755 "$bin" /usr/local/bin/claude-ip-control
install -d -m 0755 /etc/claude-ip-control
dest=/etc/claude-ip-control/guard.json
if [ -n "${1:-}" ]; then
  [ -f "$1" ] || { echo "config not found: $1" >&2; exit 1; }
  "$bin" guard render-verge-script --config "$1" >/dev/null   # validates the file
  if [ -e "$dest" ] && ! cmp -s "$1" "$dest"; then
    cp -p "$dest" "$dest.bak-$(date +%Y%m%d%H%M%S)"
    echo "backed up the previous guard.json"
  fi
  install -m 0644 "$1" "$dest"
elif [ -e "$dest" ]; then
  echo "keeping existing $dest"
else
  install -m 0644 "$here/guard.example.json" "$dest"
  echo "installed the placeholder example; edit $dest before relying on it" >&2
fi
install -m 0644 "$here/claude-ip-control.service" /etc/systemd/system/claude-ip-control.service
install -m 0644 "$here/claude-ip-control.logrotate" /etc/logrotate.d/claude-ip-control

echo "== enable at boot and start"
systemctl daemon-reload
systemctl enable claude-ip-control.service
systemctl restart claude-ip-control.service
sleep 4
systemctl --no-pager --lines=0 status claude-ip-control.service || true
journalctl -u claude-ip-control.service --no-pager -n 15
echo "== nftables guard table"
nft list table inet claude_ip_guard
echo "== timezone"
timedatectl | grep 'Time zone'
