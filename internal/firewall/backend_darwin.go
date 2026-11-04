//go:build darwin

package firewall

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	pfAnchor     = "com.claude-ip-control"
	pfAnchorFile = "/etc/pf.anchors/com.claude-ip-control"
	pfConfig     = "/etc/pf.conf"
	pfMarker     = `anchor "com.claude-ip-control" # managed by claude-ip-control`
)

type darwinBackend struct{}

func newPlatformBackend() Backend { return darwinBackend{} }

func (darwinBackend) Name() string { return "pf" }

func (darwinBackend) Apply(ctx context.Context, blocked []net.IP) error {
	if err := ensurePFAnchor(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(pfAnchorFile), 0o755); err != nil {
		return fmt.Errorf("create pf anchor directory: %w", err)
	}
	if err := os.WriteFile(pfAnchorFile, []byte(buildPFRules(blocked)), 0o600); err != nil {
		return fmt.Errorf("write pf anchor: %w", err)
	}
	if output, err := exec.CommandContext(ctx, "pfctl", "-f", pfConfig).CombinedOutput(); err != nil {
		return fmt.Errorf("reload pf rules (run as root): %w: %s", err, strings.TrimSpace(string(output)))
	}
	if output, err := exec.CommandContext(ctx, "pfctl", "-E").CombinedOutput(); err != nil {
		return fmt.Errorf("enable pf: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (darwinBackend) Clear(ctx context.Context) error {
	_ = os.Remove(pfAnchorFile)
	if err := removePFAnchor(); err != nil {
		return err
	}
	if output, err := exec.CommandContext(ctx, "pfctl", "-f", pfConfig).CombinedOutput(); err != nil {
		return fmt.Errorf("reload pf rules: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (darwinBackend) Status(ctx context.Context) (string, error) {
	output, err := exec.CommandContext(ctx, "pfctl", "-a", pfAnchor, "-sr").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("read pf status: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func ensurePFAnchor() error {
	data, err := os.ReadFile(pfConfig)
	if err != nil {
		return fmt.Errorf("read %s: %w", pfConfig, err)
	}
	if strings.Contains(string(data), pfMarker) {
		return nil
	}
	content := strings.TrimRight(string(data), "\n") + "\n" + pfMarker + "\n"
	if err := os.WriteFile(pfConfig, []byte(content), 0o600); err != nil {
		return fmt.Errorf("update %s: %w", pfConfig, err)
	}
	return nil
}

func removePFAnchor() error {
	data, err := os.ReadFile(pfConfig)
	if err != nil {
		return fmt.Errorf("read %s: %w", pfConfig, err)
	}
	lines := strings.Split(string(data), "\n")
	filtered := lines[:0]
	for _, line := range lines {
		if strings.TrimSpace(line) != pfMarker {
			filtered = append(filtered, line)
		}
	}
	if err := os.WriteFile(pfConfig, []byte(strings.Join(filtered, "\n")), 0o600); err != nil {
		return fmt.Errorf("update %s: %w", pfConfig, err)
	}
	return nil
}

func buildPFRules(blocked []net.IP) string {
	v4, v6 := make([]string, 0), make([]string, 0)
	for _, ip := range blocked {
		if four := ip.To4(); four != nil {
			v4 = append(v4, four.String())
		} else if six := ip.To16(); six != nil {
			v6 = append(v6, six.String())
		}
	}
	var b strings.Builder
	if len(v4) > 0 {
		fmt.Fprintf(&b, "block drop out quick inet to { %s }\n", strings.Join(v4, ", "))
	}
	if len(v6) > 0 {
		fmt.Fprintf(&b, "block drop out quick inet6 to { %s }\n", strings.Join(v6, ", "))
	}
	return b.String()
}
