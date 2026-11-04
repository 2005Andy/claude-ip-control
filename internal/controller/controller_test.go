package controller

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/2005Andy/claude-ip-control/internal/config"
)

type fakeResolver map[string][]net.IP

func (r fakeResolver) LookupIP(_ context.Context, _ string, host string) ([]net.IP, error) {
	ips, ok := r[host]
	if !ok {
		return nil, errors.New("lookup failed")
	}
	return ips, nil
}

func TestBuildPlanBlocksOnlyNonAllowlistedTargetIPs(t *testing.T) {
	cfg, err := config.Parse(config.Config{
		Targets:   []config.Target{{Name: "ai", Domains: []string{"ai.example"}, IPs: []string{"198.51.100.3"}}},
		Allowlist: []string{"198.51.100.0/24", "2001:db8::/32"},
	})
	if err != nil {
		t.Fatal(err)
	}
	c := &Controller{Resolver: fakeResolver{"ai.example": {net.ParseIP("198.51.100.3"), net.ParseIP("203.0.113.7"), net.ParseIP("2001:db8::7")}}}
	plan, err := c.BuildPlan(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Checked != 4 || len(plan.Blocked) != 1 || plan.Blocked[0].String() != "203.0.113.7" {
		t.Fatalf("unexpected plan: %#v", plan)
	}
}

func TestBuildPlanFailsClosedOnDNSFailureWithoutReturningRules(t *testing.T) {
	cfg, err := config.Parse(config.Config{Targets: []config.Target{{Name: "ai", Domains: []string{"missing.example"}}}})
	if err != nil {
		t.Fatal(err)
	}
	c := &Controller{Resolver: fakeResolver{}}
	if _, err := c.BuildPlan(context.Background(), cfg); err == nil {
		t.Fatal("expected DNS failure")
	}
}
