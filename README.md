# claude-ip-control

`claude-ip-control` is a small cross-platform command-line firewall manager for Windows, macOS, and Linux. It resolves only the domains listed in the configuration, compares their current IPv4/IPv6 addresses with an explicit allowlist, and installs outbound block rules for the target addresses that are not allowed. The firewall's default policy remains unchanged, so unrelated traffic is left alone.

If `expected_egress_ip` is set, `apply` and `run` first query `egress_check_url` and refuse to install or refresh rules unless the observed public source IP matches exactly. This is a guardrail, not a VPN or NAT mechanism: the program cannot turn the machine's source address into an IP it does not already use.

The project is intentionally destination-IP based. It does not decrypt HTTPS and it does not inspect process contents. A shared CDN address can serve more than one hostname; blocking that address can therefore affect other services that use the same address. Keep the target list and allowlist narrow, and review the output of `check` before applying rules.

## Install

Build from source with Go 1.22 or newer:

```text
go build -o claude-ip-control ./cmd/claude-ip-control
```

On Windows the output is `claude-ip-control.exe`. Cross-compile examples:

```text
GOOS=windows GOARCH=amd64 go build -o dist/claude-ip-control-windows-amd64.exe ./cmd/claude-ip-control
GOOS=darwin GOARCH=arm64 go build -o dist/claude-ip-control-macos-arm64 ./cmd/claude-ip-control
GOOS=linux GOARCH=amd64 go build -o dist/claude-ip-control-linux-amd64 ./cmd/claude-ip-control
```

## Configure

Create a starter file in the platform's user config directory:

```text
claude-ip-control init
```

Edit the generated JSON before applying anything. `allowlist` accepts individual IPs or CIDR ranges. `targets` accepts DNS names and/or fixed IPs. A target address that is not in any allowlist entry is blocked.

Preview the exact addresses that would be blocked:

```text
claude-ip-control check --config path/to/config.json
```

## Apply and refresh

Firewall changes require elevation:

```text
# Windows: run PowerShell or Command Prompt as Administrator
claude-ip-control apply --config path/to/config.json

# macOS/Linux: run with sudo
sudo ./claude-ip-control apply --config path/to/config.json
```

To refresh DNS-derived rules periodically, run:

```text
sudo ./claude-ip-control run --config path/to/config.json
```

The daemon keeps the last successful rules when a later DNS refresh fails. Rules intentionally remain installed after the process exits; remove them explicitly:

```text
claude-ip-control clear
```

Inspect the managed rules with `claude-ip-control status`.

## Platform backends

- Windows: Windows Defender Firewall outbound rules, grouped as `Claude IP Control`.
- Linux: a dedicated `inet claude_ip_control` nftables table with an output chain whose policy is `accept`.
- macOS: a dedicated pf anchor and a marked line in `/etc/pf.conf`.

`clear` removes only rules and configuration markers created by this tool. It does not reset the system firewall or change unrelated rules.

## Safety and limitations

- DNS is resolved at apply time and on each `run` refresh. If any configured domain cannot be resolved, that refresh fails without replacing the previous rule set.
- The allowlist is an explicit security boundary. An empty allowlist blocks every resolved address for every configured target.
- A destination IP can be shared by multiple hostnames, especially behind CDNs. IP-only filtering cannot distinguish those HTTPS flows.
- The tool does not automatically discover every AI service. Add the domains you intend to control to `targets` and keep the allowlist current.
- Use `check` first, then test the affected applications before making the daemon a system service.

## Guard mode (Linux + mihomo / Clash Verge)

`apply`/`run` only filter destination IPs. When every connection leaves through a local mihomo core (TUN or proxy port), the kernel never sees the real destination of proxied traffic, so a destination-IP filter cannot tell Anthropic traffic apart. `guard` answers a narrower question: block Anthropic/Claude official destinations unless they leave from the expected egress IP. It uses three layers, all driven by one config file (`guard.json`).

**1. mihomo routing.** `guard render-verge-script` generates the Clash Verge *global* Script, which applies to every profile. Given `verge.exit_proxy` (the node with the expected egress IP) and `verge.upper_proxy` (the node it is chained through), it builds:

| Traffic | Route |
| --- | --- |
| guarded domains (`DOMAIN-SUFFIX`) and Anthropic CIDRs (`IP-CIDR`), first in the rule list | `Claude-Guard` (select) = `[REJECT, Claude-142]` |
| `Claude-142` | fallback `[exit chained via upper, exit direct]`. Both leave from the expected IP. |
| `verge.upper_domains` (sites the exit cannot serve) and, with `udp_via_upper`, all UDP | `upper_proxy` |
| everything else | `Out-Default` = fallback `[exit chained via upper, upper_proxy]` |

The chained copy of the exit node is created by the Script, so it survives config regeneration. You don't need Clash Verge's runtime-only chain proxy feature. TLS/HTTP sniffing is enabled so connections to raw IPs still match by SNI. A probe listener (`probe_proxy`, default `127.0.0.1:17891`) is bound to `Claude-142`, so the daemon measures exactly the path guarded traffic takes.

**2. daemon** (`guard run`). Every `probe_interval` it reads the public IP seen through the probe listener from neutral endpoints (Cloudflare trace, ipify), never from an Anthropic host. Every `state_interval` it selects `Claude-142` only if all of these hold:

- the probe is fresh and equals `expected_egress_ip`
- the guard rules are first in the running rule list
- mihomo is in rule mode

Otherwise it selects `REJECT` and closes guarded connections that are not on the verified path. If the guard rules are missing (Clash Verge did not run the Script), it pins `GLOBAL` to `mihomo.degraded_global_proxy` and switches to global mode, so the profile's own rules cannot route guarded traffic to another node. When the rules return, it switches back to rule mode.

**3. kernel** (`inet claude_ip_guard` nftables table, output and forward hooks). Packets to Anthropic's published ranges and to resolved `kernel_resolve_hosts` addresses are rejected (TCP reset) unless they leave through `lo` or the mihomo TUN device. This catches traffic that bypasses mihomo: mihomo down, TUN off, or a `DIRECT` rule.

The table and the last group selection stay in place when the daemon stops, so a crash does not unblock anything. Starting the daemon selects `REJECT` until the first successful probe. A fresh core also starts on `REJECT`, because it is the first member of `Claude-Guard`.

Every field, the order for applying list changes, and how the service stays resident: [`docs/guard-config.md`](docs/guard-config.md).

Install (Linux, systemd):

```text
go build -o claude-ip-control ./cmd/claude-ip-control
cp deploy/linux/guard.example.json deploy/linux/guard.local.json   # fill in node names and IP; *.local.json is git-ignored
deploy/linux/install-verge-script.sh deploy/linux/guard.local.json  # as your user; backs up the old Script.js
sudo deploy/linux/install.sh deploy/linux/guard.local.json           # /usr/local/bin, /etc/claude-ip-control, systemd, logrotate
# quit and reopen Clash Verge (restarting only the core does not run the global Script)
sudo deploy/linux/selftest.sh                                        # precheck, allowed path, kernel block, mismatch, mode tamper
claude-ip-control guard status                                       # status JSON from /run/claude-ip-control/status.json
journalctl -u claude-ip-control                                      # logs (also /var/log/claude-ip-control/guard.log)
```

Other commands:

- `guard once --config FILE [--no-kernel]` runs one probe and enforcement pass and prints the status.
- `guard render-verge-script --config FILE [-o FILE]` prints the Script.
- `guard clear` removes the nftables table.
- `deploy/linux/uninstall.sh [--purge]` removes the service.

Limits:

- A change of the exit node's own IP is caught at the next probe (`probe_interval`, default 10s).
- A manual switch to global mode is undone on the next state pass (`state_interval`, default 1s).
- mihomo `fallback` groups switch on health-check failure. They cannot retry a single site on another node, so sites the exit cannot reach must be listed in `upper_domains`.
- The kernel layer cannot inspect proxied traffic, and hosts on shared CDN addresses (the Datadog intake hosts) are only covered by the mihomo rules.

## Development

```text
go test ./...
go vet ./...
```

GitHub Actions builds and tests the CLI on Linux, Windows, and macOS.
