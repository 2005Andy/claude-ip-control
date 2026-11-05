#!/usr/bin/env bash
# Render the Clash Verge global Script from a guard config and install it.
# Run as the desktop user (not root). Afterwards quit and reopen Clash Verge:
# restarting only the core does not run the global Script.
# Usage: deploy/linux/install-verge-script.sh [guard.json]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
cfg="${1:-$here/guard.local.json}"
bin="$repo/claude-ip-control"
data="${CLASH_VERGE_DIR:-$HOME/.local/share/io.github.clash-verge-rev.clash-verge-rev}"
[ "$(id -u)" -ne 0 ] || { echo "run as your desktop user, not root" >&2; exit 1; }
[ -x "$bin" ] || { echo "build first: go build -o claude-ip-control ./cmd/claude-ip-control" >&2; exit 1; }
[ -f "$cfg" ] || { echo "config not found: $cfg" >&2; exit 1; }
[ -d "$data/profiles" ] || { echo "Clash Verge data dir not found: $data" >&2; exit 1; }

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
"$bin" guard render-verge-script --config "$cfg" -o "$tmp"
target="$data/profiles/Script.js"
if [ -f "$target" ] && ! cmp -s "$tmp" "$target"; then
  cp -p "$target" "$target.bak-$(date +%Y%m%d%H%M%S)"
  echo "backed up previous Script.js"
fi
install -m 0644 "$tmp" "$target"
echo "installed $target"
echo "next: quit Clash Verge from the tray and reopen it, then run: sudo $here/selftest.sh"
