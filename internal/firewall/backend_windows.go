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
		script := fmt.Sprintf("$ErrorActionPreference='Stop'; New-NetFirewallRule -DisplayName '%s' -Group '%s' -Direction Outbound -Action Block -RemoteAddress '%s' -Profile Any -Enabled True -Description 'managed by claude-ip-control' | Out-Null", name, windowsGroup, ip.String())
		if output, err := runPowerShell(ctx, script); err != nil {
			return fmt.Errorf("add Windows firewall rule for %s (run as Administrator): %w: %s", ip, err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func (windowsBackend) Clear(ctx context.Context) error { return deleteWindowsRules(ctx) }

func (windowsBackend) Status(ctx context.Context) (string, error) {
	script := fmt.Sprintf("$ErrorActionPreference='Stop'; $rules=@(Get-NetFirewallRule -Group '%s' -ErrorAction SilentlyContinue); if ($rules.Count -eq 0) { Write-Output 'no managed Windows firewall rules'; exit 0 }; $rules | Select-Object DisplayName,Enabled,Action,Direction,Profile | Format-Table -AutoSize | Out-String", windowsGroup)
	output, err := runPowerShell(ctx, script)
	if err != nil {
		return "", fmt.Errorf("read Windows firewall status: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func deleteWindowsRules(ctx context.Context) error {
	script := fmt.Sprintf("$ErrorActionPreference='Stop'; $rules=@(Get-NetFirewallRule -Group '%s' -ErrorAction SilentlyContinue); if ($rules.Count -gt 0) { $rules | Remove-NetFirewallRule -Confirm:$false -ErrorAction Stop }; exit 0", windowsGroup)
	output, err := runPowerShell(ctx, script)
	if err != nil {
		return fmt.Errorf("delete Windows firewall rules: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func runPowerShell(ctx context.Context, script string) ([]byte, error) {
	return exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script).CombinedOutput()
}
