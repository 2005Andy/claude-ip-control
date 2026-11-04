//go:build linux

package firewall

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
)

const nftTable = "claude_ip_control"

type linuxBackend struct{}

func newPlatformBackend() Backend { return linuxBackend{} }

func (linuxBackend) Name() string { return "nftables" }

func (linuxBackend) Apply(ctx context.Context, blocked []net.IP) error {
	if err := deleteNftTable(ctx); err != nil {
		return err
	}
	script := buildNftScript(blocked)
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("apply nftables rules (run as root): %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (linuxBackend) Clear(ctx context.Context) error { return deleteNftTable(ctx) }

func (linuxBackend) Status(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "nft", "list", "table", "inet", nftTable)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if len(output) == 0 {
			return "no managed nftables table", nil
		}
		return "", fmt.Errorf("read nftables status: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func deleteNftTable(ctx context.Context) error {
	list := exec.CommandContext(ctx, "nft", "list", "table", "inet", nftTable)
	if err := list.Run(); err != nil {
		return nil
	}
	cmd := exec.CommandContext(ctx, "nft", "delete", "table", "inet", nftTable)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("delete nftables rules: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func buildNftScript(blocked []net.IP) string {
	v4, v6 := splitIPs(blocked)
	var b bytes.Buffer
	fmt.Fprintf(&b, "add table inet %s\n", nftTable)
	fmt.Fprintf(&b, "add chain inet %s output { type filter hook output priority 0; policy accept; }\n", nftTable)
	if len(v4) > 0 {
		fmt.Fprintf(&b, "add set inet %s blocked_v4 { type ipv4_addr; flags interval; elements = { %s } }\n", nftTable, strings.Join(v4, ", "))
		fmt.Fprintf(&b, "add rule inet %s output ip daddr @blocked_v4 counter drop\n", nftTable)
	}
	if len(v6) > 0 {
		fmt.Fprintf(&b, "add set inet %s blocked_v6 { type ipv6_addr; flags interval; elements = { %s } }\n", nftTable, strings.Join(v6, ", "))
		fmt.Fprintf(&b, "add rule inet %s output ip6 daddr @blocked_v6 counter drop\n", nftTable)
	}
	return b.String()
}

func splitIPs(blocked []net.IP) ([]string, []string) {
	v4, v6 := make([]string, 0), make([]string, 0)
	for _, ip := range blocked {
		if four := ip.To4(); four != nil {
			v4 = append(v4, four.String())
		} else if six := ip.To16(); six != nil {
			v6 = append(v6, six.String())
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6
}
