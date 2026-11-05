//go:build linux

package firewall

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

type nftGuardKernel struct{}

func newGuardKernel() GuardKernel { return nftGuardKernel{} }

func (nftGuardKernel) Install(ctx context.Context, networks []*net.IPNet, exempt []string) error {
	script := BuildGuardNftScript(networks, exempt, guardTableExists(ctx))
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("install guard nftables rules (run as root): %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (nftGuardKernel) Clear(ctx context.Context) error {
	if !guardTableExists(ctx) {
		return nil
	}
	out, err := exec.CommandContext(ctx, "nft", "delete", "table", "inet", GuardTable).CombinedOutput()
	if err != nil {
		return fmt.Errorf("delete guard nftables table: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (nftGuardKernel) Status(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "nft", "list", "table", "inet", GuardTable).CombinedOutput()
	if err != nil {
		if len(out) == 0 || strings.Contains(string(out), "No such file") {
			return "no guard nftables table", nil
		}
		return "", fmt.Errorf("read guard nftables status: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func guardTableExists(ctx context.Context) bool {
	return exec.CommandContext(ctx, "nft", "list", "table", "inet", GuardTable).Run() == nil
}

// BuildGuardNftScript returns an nft script that atomically (re)creates the
// guard table. The whole script is one transaction, so there is no window in
// which the old table is gone and the new one is not yet installed.
func BuildGuardNftScript(networks []*net.IPNet, exempt []string, replace bool) string {
	v4, v6 := splitNetworks(networks)
	var b bytes.Buffer
	if replace {
		fmt.Fprintf(&b, "delete table inet %s\n", GuardTable)
	}
	fmt.Fprintf(&b, "table inet %s {\n", GuardTable)
	writeSet(&b, "guard_v4", "ipv4_addr", v4)
	writeSet(&b, "guard_v6", "ipv6_addr", v6)
	ifnames := make([]string, 0, len(exempt))
	for _, name := range exempt {
		ifnames = append(ifnames, strconv.Quote(name))
	}
	for _, hook := range []string{"output", "forward"} {
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook %s priority filter; policy accept;\n", hook, hook)
		if len(ifnames) > 0 {
			fmt.Fprintf(&b, "\t\toifname { %s } accept\n", strings.Join(ifnames, ", "))
		}
		if len(v4) > 0 {
			fmt.Fprintf(&b, "\t\tip daddr @guard_v4 meta l4proto tcp counter reject with tcp reset\n")
			fmt.Fprintf(&b, "\t\tip daddr @guard_v4 counter reject with icmpx admin-prohibited\n")
		}
		if len(v6) > 0 {
			fmt.Fprintf(&b, "\t\tip6 daddr @guard_v6 meta l4proto tcp counter reject with tcp reset\n")
			fmt.Fprintf(&b, "\t\tip6 daddr @guard_v6 counter reject with icmpx admin-prohibited\n")
		}
		b.WriteString("\t}\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func writeSet(b *bytes.Buffer, name, typ string, elems []string) {
	fmt.Fprintf(b, "\tset %s {\n\t\ttype %s\n\t\tflags interval\n\t\tauto-merge\n", name, typ)
	if len(elems) > 0 {
		fmt.Fprintf(b, "\t\telements = { %s }\n", strings.Join(elems, ", "))
	}
	b.WriteString("\t}\n")
}

func splitNetworks(networks []*net.IPNet) ([]string, []string) {
	v4, v6 := []string{}, []string{}
	seen := map[string]bool{}
	for _, n := range networks {
		if n == nil || seen[n.String()] {
			continue
		}
		seen[n.String()] = true
		if n.IP.To4() != nil {
			v4 = append(v4, n.String())
		} else {
			v6 = append(v6, n.String())
		}
	}
	return v4, v6
}
