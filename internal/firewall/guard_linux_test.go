//go:build linux

package firewall

import (
	"net"
	"strings"
	"testing"
)

func TestBuildGuardNftScript(t *testing.T) {
	_, a, _ := net.ParseCIDR("160.79.104.0/21")
	_, b, _ := net.ParseCIDR("2607:6bc0::/48")
	script := BuildGuardNftScript([]*net.IPNet{a, b, a}, []string{"lo", "Mihomo"}, true)
	for _, want := range []string{
		"delete table inet claude_ip_guard\n",
		"elements = { 160.79.104.0/21 }",
		"elements = { 2607:6bc0::/48 }",
		`oifname { "lo", "Mihomo" } accept`,
		"chain output {",
		"chain forward {",
		"ip daddr @guard_v4 meta l4proto tcp counter reject with tcp reset",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q:\n%s", want, script)
		}
	}
	if strings.Count(script, "160.79.104.0/21") != 1 {
		t.Errorf("duplicate network not removed:\n%s", script)
	}
	if strings.Contains(BuildGuardNftScript([]*net.IPNet{a}, nil, false), "delete table") {
		t.Error("fresh install must not delete a missing table")
	}
}
