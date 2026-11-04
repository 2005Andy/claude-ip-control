package config

import (
	"net"
	"testing"
	"time"
)

func TestParseNormalizesTargetsAndAllowlist(t *testing.T) {
	parsed, err := Parse(Config{
		RefreshInterval: "5m",
		Targets:         []Target{{Name: " Claude ", Domains: []string{"Example.COM."}, IPs: []string{"192.0.2.10"}}},
		Allowlist:       []string{"192.0.2.0/24", "2001:db8::1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.RefreshInterval != 5*time.Minute || parsed.Targets[0].Name != "Claude" || parsed.Targets[0].Domains[0] != "example.com" {
		t.Fatalf("unexpected parsed config: %#v", parsed)
	}
	if !parsed.Allowlist[0].Contains(net.ParseIP("192.0.2.20")) || !parsed.Allowlist[1].Contains(net.ParseIP("2001:db8::1")) {
		t.Fatalf("allowlist was not parsed correctly: %#v", parsed.Allowlist)
	}
}

func TestParseRejectsTargetWithoutSources(t *testing.T) {
	_, err := Parse(Config{Targets: []Target{{Name: "empty"}}})
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestParseUsesDefaultRefreshInterval(t *testing.T) {
	parsed, err := Parse(Config{Targets: []Target{{Name: "ip", IPs: []string{"192.0.2.1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.RefreshInterval != DefaultRefreshInterval {
		t.Fatalf("got %s, want %s", parsed.RefreshInterval, DefaultRefreshInterval)
	}
}
