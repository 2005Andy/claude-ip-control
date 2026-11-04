//go:build windows

package firewall

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

const windowsGroup = "Claude IP Control"

type windowsBackend struct{}

func newPlatformBackend() Backend { return windowsBackend{} }

func (windowsBackend) Name() string { return "windows-defender-firewall" }

func (windowsBackend) Apply(ctx context.Context, blocked []net.IP) error {
	if err := deleteWindowsRules(ctx); err != nil {
		return err
	}
	for index, ip := range blocked {
		name := fmt.Sprintf("Claude IP Control %03d %s", index+1, ip.String())
		args := []string{"advfirewall", "firewall", "add", "rule", `name="` + name + `"`, `group="` + windowsGroup + `"`, "dir=out", "action=block", "remoteip=" + ip.String(), "enable=yes", "profile=any"}
		if output, err := exec.CommandContext(ctx, "netsh", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("add Windows firewall rule for %s (run as Administrator): %w: %s", ip, err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func (windowsBackend) Clear(ctx context.Context) error { return deleteWindowsRules(ctx) }

func (windowsBackend) Status(ctx context.Context) (string, error) {
	output, err := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "show", "rule", `group="`+windowsGroup+`"`).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("read Windows firewall status: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func deleteWindowsRules(ctx context.Context) error {
	output, err := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", `group="`+windowsGroup+`"`).CombinedOutput()
	if err != nil && !strings.Contains(strings.ToLower(string(output)), "no rules match") {
		return fmt.Errorf("delete Windows firewall rules: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
