#!/usr/bin/env bash
# Remove the guard service and its nftables table. Anthropic traffic is no
# longer gated afterwards. Config and logs are kept unless --purge is given.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }
systemctl disable --now claude-ip-control.service 2>/dev/null || true
/usr/local/bin/claude-ip-control guard clear 2>/dev/null || nft delete table inet claude_ip_guard 2>/dev/null || true
rm -f /etc/systemd/system/claude-ip-control.service /etc/logrotate.d/claude-ip-control /usr/local/bin/claude-ip-control
systemctl daemon-reload
if [ "${1:-}" = "--purge" ]; then
  rm -rf /etc/claude-ip-control /var/log/claude-ip-control
fi
echo "removed. Also restore the Clash Verge global Script (Script.js.bak-* next to profiles/Script.js), then quit and reopen Clash Verge."
