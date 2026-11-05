# Guard configuration reference

`claude-ip-control guard` reads a single JSON file. The daemon enforces it, and
`guard render-verge-script` turns it into the Clash Verge global Script. Keep one
file and render the Script from it every time it changes.

| Location | Role |
| --- | --- |
| `deploy/linux/guard.example.json` | committed template with placeholders |
| `deploy/linux/guard.local.json` | your real values (git-ignored, `*.local.json`) |
| `/etc/claude-ip-control/guard.json` | the copy the systemd service reads, installed by `install.sh` |
| `<clash-verge data>/profiles/Script.js` | rendered Script, installed by `install-verge-script.sh` |

## Fields

### Egress check

| Field | Default | Meaning |
| --- | --- | --- |
| `expected_egress_ip` | required | The only public IP guarded traffic may leave from. |
| `probe_proxy` | required | HTTP proxy URL of the probe listener the Script creates, for example `http://127.0.0.1:17891`. It is bound to the exit group, so the probe takes the same path as guarded traffic. |
| `probe_urls` | required | Neutral endpoints that report the caller's IP: Cloudflare `/cdn-cgi/trace`, ipify JSON, or plain text. The first success wins. A URL on a guarded domain is rejected, because the probe must not reach Anthropic. |
| `probe_interval` | `10s` | How often the egress is measured. A result older than 3 intervals counts as failed. |
| `state_interval` | `1s` | How often mode, rules, group selection and connections are enforced. |

### mihomo

| Field | Default | Meaning |
| --- | --- | --- |
| `mihomo.socket` / `mihomo.url` + `mihomo.secret` | one required | External controller: unix socket (Clash Verge service mode: `/run/clash-verge-service/users/<uid>/verge-mihomo.sock`), or HTTP URL plus secret. |
| `mihomo.guard_group` | required | Select group with exactly `[REJECT, <exit group>]`. Usually `Claude-Guard`. |
| `mihomo.pinned_proxy` | required | Name of the exit group the Script creates, for example `Claude-142`. It must not be the node itself. |
| `mihomo.enforce_mode` | empty | Set to `rule` to switch back from global/direct mode. The daemon does this only while the guard rules are loaded. |
| `mihomo.degraded_global_proxy` | empty | Node to pin on `GLOBAL` (in global mode) while the guard rules are missing, so profile rules cannot route guarded traffic to another node. Use the exit node itself. |

### Guarded destinations

| Field | Meaning |
| --- | --- |
| `domains` | Suffix match. Allowed **only** through the exit group, and blocked otherwise. Put any site that must use the expected egress here (Anthropic and Claude by default; add for example `openai.com`, `chatgpt.com`, `oaistatic.com`, `oaiusercontent.com`). |
| `cidrs` | Address ranges routed to the guard group, and also rejected by the kernel layer outside lo/TUN. Only use ranges owned by the service. Shared CDN ranges would break other sites. |
| `kernel_resolve_hosts` | Hosts resolved over DoH (through the probe listener) every `resolve_interval` (default `10m`) and added to the kernel set as /32 or /128 addresses. Use only for hosts on dedicated addresses. |
| `doh_url` | DNS-over-HTTPS JSON endpoint, default Cloudflare. |
| `kernel_exempt_ifnames` | Interfaces that bypass the kernel reject, default `["lo", "Mihomo"]` (the TUN device). |

### Clash Verge Script (`verge`)

| Field | Default | Meaning |
| --- | --- | --- |
| `verge.exit_proxy` | required | Node whose egress is `expected_egress_ip`. |
| `verge.upper_proxy` | required | Node or group the exit is chained through, and the fallback for other traffic. |
| `verge.chain_exit` | `false` | Add `<exit> [chain]` (`dialer-proxy: upper_proxy`). The exit group then becomes fallback `[chained, direct]`. Both members leave from the same IP. |
| `verge.default_group` | `Out-Default` | Fallback group for unlisted traffic: `[chained exit, upper_proxy]`. |
| `verge.other_traffic` | `fallback` | `fallback` sends unlisted traffic to `default_group`. `profile` keeps the profile's own rules after the guard rules. |
| `verge.upper_domains` | `[]` | Suffixes always sent to `upper_proxy`, for sites the exit cannot serve. Guard rules come first, so a guarded domain here still goes to the guard group. |
| `verge.udp_via_upper` | `false` | Send all non-guarded UDP to `upper_proxy`. Turn this on when the exit is an HTTP proxy, which cannot carry UDP. |
| `verge.health_url` / `verge.health_interval_seconds` | `http://cp.cloudflare.com/generate_204`, `60` | Health check for both fallback groups. |
| `verge.probe_listen` / `verge.probe_port` | taken from `probe_proxy` | Probe listener address. |

`log_file` (optional) duplicates the log to a file. The systemd unit creates
`/var/log/claude-ip-control/`, and logrotate keeps 8 weekly files.

## Changing the lists

Apply changes in this order, so the daemon never runs with a config whose rules are not
loaded yet:

```text
$EDITOR deploy/linux/guard.local.json
deploy/linux/install-verge-script.sh deploy/linux/guard.local.json   # as your user
# quit Clash Verge from the tray and reopen it (a core restart does not run the Script)
sudo deploy/linux/install.sh deploy/linux/guard.local.json            # installs config, restarts the service
claude-ip-control guard status
curl -s -x http://127.0.0.1:7890 https://<site>/cdn-cgi/trace | grep '^ip='   # Cloudflare-fronted sites
```

If the daemon starts first with a domain the running rules lack, it reports
`guard rules not loaded`. It then pins `GLOBAL` to `degraded_global_proxy`, holds
global mode, and closes guarded connections until the Script is loaded.

## Staying resident

- `claude-ip-control.service` is `enabled` with `Restart=always`, `RestartSec=3` and
  `StartLimitIntervalSec=0`, so systemd never stops restarting it.
- The nftables table and the last group selection survive a daemon stop or crash.
  A fresh mihomo core starts on `REJECT`, the first member of the guard group.
- The guard needs the mihomo core, which Clash Verge starts. Turn on Clash Verge
  auto-launch (Settings → 开机自启) and service mode. Until a user session starts Verge,
  guarded traffic fails closed at the kernel layer, and other traffic goes direct.
- Keep TUN on. Without it, apps that ignore proxy settings bypass the mihomo rules.
  Only the kernel layer still covers them.
