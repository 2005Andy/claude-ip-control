//go:build linux

package firewall

import (
	"net"
	"strings"
	"testing"
)

func TestBuildNftScriptOnlyCreatesRulesForBlockedAddresses(t *testing.T) {
	script := buildNftScript([]net.IP{net.ParseIP("203.0.113.7"), net.ParseIP("2001:db8::7")})
	for _, want := range []string{
		"add table inet claude_ip_control",
		"add set inet claude_ip_control blocked_v4",
		"ip daddr @blocked_v4 counter drop",
		"add set inet claude_ip_control blocked_v6",
		"ip6 daddr @blocked_v6 counter drop",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script does not contain %q:\n%s", want, script)
		}
	}
}

func TestBuildNftScriptLeavesEmptySetsOut(t *testing.T) {
	script := buildNftScript(nil)
	if strings.Contains(script, "blocked_v4") || strings.Contains(script, "blocked_v6") {
		t.Fatalf("empty plan should not create address sets:\n%s", script)
	}
}
