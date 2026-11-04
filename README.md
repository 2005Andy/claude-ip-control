# claude-ip-control

`claude-ip-control` is a small cross-platform command-line firewall manager for Windows, macOS, and Linux. It resolves only the domains listed in the configuration, compares their current IPv4/IPv6 addresses with an explicit allowlist, and installs outbound block rules for the target addresses that are not allowed. The firewall's default policy remains unchanged, so unrelated traffic is left alone.

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

## Development

```text
go test ./...
go vet ./...
```

GitHub Actions builds and tests the CLI on Linux, Windows, and macOS.
