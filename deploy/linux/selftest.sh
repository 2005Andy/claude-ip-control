#!/usr/bin/env bash
# End-to-end check of the installed guard. Usage: sudo deploy/linux/selftest.sh
# Briefly blocks Anthropic traffic during the mismatch step (~15s).
set -uo pipefail
export LC_ALL=C
[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }
BIN=/usr/local/bin/claude-ip-control
CFG=/etc/claude-ip-control/guard.json
EXP=$(python3 -c "import json;print(json.load(open('$CFG'))['expected_egress_ip'])")
SOCK=$(python3 -c "import json;print(json.load(open('$CFG'))['mihomo']['socket'])")
PROXY=http://127.0.0.1:7890
TRACE=https://api.anthropic.com/cdn-cgi/trace
pass=0; fail=0
ok(){ echo "  PASS: $*"; pass=$((pass+1)); }
bad(){ echo "  FAIL: $*"; fail=$((fail+1)); }
mh(){ curl -s --noproxy '*' --unix-socket "$SOCK" "$@"; }
group_now(){ mh http://x/proxies/Claude-Guard | python3 -c 'import json,sys;print(json.load(sys.stdin).get("now",""))' 2>/dev/null; }
wait_allowed(){ for _ in $(seq 1 40); do grep -q '"allowed": true' /run/claude-ip-control/status.json 2>/dev/null && return 0; sleep 1; done; return 1; }
trace_ip(){ curl -s --max-time 8 "$@" "$TRACE" | sed -n 's/^ip=//p'; }

echo "== 0. precheck: guard loaded in mihomo"
pre=$(mh http://x/proxies | python3 -c '
import json,sys
cfg=json.load(open(sys.argv[1])); m=cfg["mihomo"]; p=json.load(sys.stdin)["proxies"]
g=p.get(m["guard_group"]); e=p.get(m["pinned_proxy"])
errs=[]
if not g: errs.append("group %s missing: the Clash Verge global Script is not applied (run install-verge-script.sh, then quit and reopen Clash Verge)" % m["guard_group"])
elif sorted(g.get("all",[]))!=sorted(["REJECT",m["pinned_proxy"]]): errs.append("guard group members are %r" % g.get("all"))
if not e: errs.append("exit group %s missing" % m["pinned_proxy"])
else: print("  exit group %s = %s (now: %s)" % (m["pinned_proxy"], e.get("all"), e.get("now")), file=sys.stderr)
print("\n".join(errs))' "$CFG")
if [ -n "$pre" ]; then echo "$pre" | sed 's/^/  BLOCKER: /'; echo "== aborted before mismatch/tamper tests"; exit 2; fi
ok "guard group and exit group loaded"

echo "== 1. allowed path (egress verified)"
wait_allowed && ok "daemon reports allowed" || bad "daemon never reported allowed"
echo "  group now: $(group_now)"
ip1=$(trace_ip -x "$PROXY"); [ "$ip1" = "$EXP" ] && ok "via proxy port Anthropic sees $ip1" || bad "via proxy port got '$ip1'"
ip2=$(trace_ip --noproxy '*'); [ "$ip2" = "$EXP" ] && ok "via TUN Anthropic sees $ip2" || bad "via TUN got '$ip2'"

ipo=$(curl -s --max-time 8 -x "$PROXY" https://www.cloudflare.com/cdn-cgi/trace | sed -n 's/^ip=//p')
echo "  other traffic (Out-Default) exits via: ${ipo:-unreachable}"

echo "== 2. kernel layer: direct (non-TUN) connection to Anthropic IP"
NIC=$(ip route show table main default | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
out=$(curl -sS --max-time 5 --noproxy '*' --interface "$NIC" -o /dev/null https://160.79.104.10/ 2>&1); rc=$?
[ "$rc" -eq 7 ] && ok "direct via $NIC refused immediately (curl exit 7)" || bad "direct via $NIC: rc=$rc $out"

echo "== 3. egress mismatch -> blocked"
systemctl stop claude-ip-control.service
tmp=$(mktemp -d); sed 's/"expected_egress_ip": *"[^"]*"/"expected_egress_ip": "203.0.113.99"/' "$CFG" > "$tmp/guard.json"
"$BIN" guard once --config "$tmp/guard.json" | grep -E '"(allowed|observed_ip|group_now|probe_error)"'
rm -rf "$tmp"
[ "$(group_now)" = REJECT ] && ok "group switched to REJECT" || bad "group is '$(group_now)'"
out=$(curl -sS --max-time 8 -x "$PROXY" -o /dev/null -w '%{http_code}' "$TRACE" 2>&1); [ "${out: -3}" != 200 ] && ok "Anthropic via proxy blocked ($out)" || bad "Anthropic reachable during mismatch"
out=$(curl -sS --max-time 8 --noproxy '*' -o /dev/null -w '%{http_code}' "$TRACE" 2>&1); [ "${out: -3}" != 200 ] && ok "Anthropic via TUN blocked ($out)" || bad "Anthropic reachable via TUN during mismatch"
code=$(curl -s --max-time 8 -x "$PROXY" -o /dev/null -w '%{http_code}' https://www.cloudflare.com/cdn-cgi/trace); [ "$code" = 200 ] && ok "non-Anthropic traffic unaffected" || bad "non-Anthropic traffic got $code"
systemctl start claude-ip-control.service
wait_allowed && [ "$(trace_ip -x "$PROXY")" = "$EXP" ] && ok "restored after daemon restart" || bad "not restored"

echo "== 4. mode tamper: switch to global"
mh -X PATCH -d '{"mode":"global"}' http://x/configs >/dev/null; sleep 2
mode=$(mh http://x/configs | python3 -c 'import json,sys;print(json.load(sys.stdin)["mode"])')
[ "$mode" = rule ] && ok "daemon restored rule mode" || bad "mode is $mode"

echo "== journal (last 12)"
journalctl -u claude-ip-control.service --no-pager -n 12 -o cat
echo "== result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
