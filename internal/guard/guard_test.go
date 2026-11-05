package guard

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

const pinned = "Claude-142"

type fakeMihomo struct {
	mode     string
	modeErr  error
	group    *Group
	rules    []Rule
	conns    []Connection
	closed   []string
	setModes []string
	nodes    map[string]Group
}

func (f *fakeMihomo) Mode(context.Context) (string, error) { return f.mode, f.modeErr }
func (f *fakeMihomo) SetMode(_ context.Context, m string) error {
	f.setModes = append(f.setModes, m)
	f.mode = m
	return nil
}
func (f *fakeMihomo) Group(_ context.Context, name string) (Group, error) {
	if node, ok := f.nodes[name]; ok {
		return node, nil
	}
	if f.group == nil || f.group.Name != name {
		return Group{}, ErrNotFound
	}
	return *f.group, nil
}
func (f *fakeMihomo) Select(_ context.Context, group, proxy string) error {
	if node, ok := f.nodes[group]; ok {
		node.Now = proxy
		f.nodes[group] = node
		return nil
	}
	if f.group == nil || f.group.Name != group {
		return ErrNotFound
	}
	f.group.Now = proxy
	return nil
}
func (f *fakeMihomo) Rules(context.Context) ([]Rule, error)             { return f.rules, nil }
func (f *fakeMihomo) Connections(context.Context) ([]Connection, error) { return f.conns, nil }
func (f *fakeMihomo) CloseConnection(_ context.Context, id string) error {
	f.closed = append(f.closed, id)
	return nil
}

type fakeKernel struct{ installs int }

func (k *fakeKernel) Install(context.Context, []*net.IPNet, []string) error { k.installs++; return nil }
func (k *fakeKernel) Clear(context.Context) error                           { return nil }
func (k *fakeKernel) Status(context.Context) (string, error)                { return "", nil }

func testConfig(t *testing.T) *Config {
	t.Helper()
	cfg := &Config{
		ExpectedEgressIP: "198.51.100.7",
		ProbeProxy:       "http://127.0.0.1:17891",
		ProbeURLs:        []string{"https://www.cloudflare.com/cdn-cgi/trace"},
		Mihomo:           MihomoConfig{Socket: "/x", GuardGroup: "Claude-Guard", PinnedProxy: pinned, EnforceMode: "rule"},
		Domains:          []string{"anthropic.com", "claude.ai"},
		CIDRs:            []string{"160.79.104.0/21", "2607:6bc0::/48"},
	}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func guardRules() []Rule {
	return []Rule{
		{Type: "DomainSuffix", Payload: "anthropic.com", Proxy: "Claude-Guard"},
		{Type: "DomainSuffix", Payload: "claude.ai", Proxy: "Claude-Guard"},
		{Type: "IPCIDR", Payload: "160.79.104.0/21", Proxy: "Claude-Guard"},
		{Type: "IPCIDR6", Payload: "2607:6bc0::/48", Proxy: "Claude-Guard"},
		{Type: "Match", Payload: "", Proxy: "GLOBAL"},
	}
}

func newTestGuard(t *testing.T, m *fakeMihomo, probeIP string, probeErr error) *Guard {
	t.Helper()
	cfg := testConfig(t)
	g, err := New(cfg, m, &fakeKernel{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	g.now = func() time.Time { return now }
	g.probeAt, g.probeIP, g.probeErr = now, probeIP, probeErr
	g.kernelOK = true
	return g
}

func freshMihomo() *fakeMihomo {
	return &fakeMihomo{
		mode:  "rule",
		group: &Group{Name: "Claude-Guard", Type: "Selector", Now: Reject, All: []string{Reject, pinned}},
		rules: guardRules(),
	}
}

func TestMatchingEgressSelectsPinnedNode(t *testing.T) {
	m := freshMihomo()
	st := newTestGuard(t, m, "198.51.100.7", nil).Enforce(context.Background())
	if !st.Allowed || m.group.Now != pinned || len(st.Problems) != 0 {
		t.Fatalf("expected pinned/allowed, got group=%q status=%+v", m.group.Now, st)
	}
}

func TestMismatchRejectsAndClosesConnections(t *testing.T) {
	m := freshMihomo()
	m.group.Now = pinned
	c := Connection{ID: "c1", Chains: []string{pinned, "Claude-Guard"}}
	c.Metadata.Host = "api.anthropic.com"
	other := Connection{ID: "c2", Chains: []string{pinned, "GLOBAL"}}
	other.Metadata.Host = "example.com"
	m.conns = []Connection{c, other}
	st := newTestGuard(t, m, "203.0.113.5", nil).Enforce(context.Background())
	if st.Allowed || m.group.Now != Reject {
		t.Fatalf("expected REJECT, got %q %+v", m.group.Now, st)
	}
	if len(m.closed) != 1 || m.closed[0] != "c1" {
		t.Fatalf("expected only guarded connection closed, got %v", m.closed)
	}
}

func TestProbeFailureAndStaleProbeFailClosed(t *testing.T) {
	m := freshMihomo()
	m.group.Now = pinned
	g := newTestGuard(t, m, "", errors.New("timeout"))
	if st := g.Enforce(context.Background()); st.Allowed || m.group.Now != Reject {
		t.Fatalf("probe error must reject: %q", m.group.Now)
	}
	m.group.Now = pinned
	g.probeErr, g.probeIP = nil, "198.51.100.7"
	g.probeAt = g.now().Add(-time.Hour)
	if st := g.Enforce(context.Background()); st.Allowed || m.group.Now != Reject {
		t.Fatalf("stale probe must reject: %q", m.group.Now)
	}
}

func TestGlobalModeIsRestoredAndLeakedConnectionClosed(t *testing.T) {
	m := freshMihomo()
	m.mode = "global"
	leak := Connection{ID: "leak", Chains: []string{"Other Node", "GLOBAL"}}
	leak.Metadata.DestinationIP = "160.79.104.10"
	m.conns = []Connection{leak}
	st := newTestGuard(t, m, "198.51.100.7", nil).Enforce(context.Background())
	if len(m.setModes) != 1 || m.setModes[0] != "rule" || st.Mode != "rule" {
		t.Fatalf("mode not restored: %v", m.setModes)
	}
	if len(m.closed) != 1 || m.closed[0] != "leak" {
		t.Fatalf("leaked connection not closed: %v", m.closed)
	}
}

func TestMissingRulesLeaveModeAloneAndCloseConnections(t *testing.T) {
	m := freshMihomo()
	m.mode = "global"
	m.group.Now = pinned
	m.rules = []Rule{{Type: "Match", Proxy: "Profile Relay"}}
	c := Connection{ID: "c1", Chains: []string{pinned, "GLOBAL"}}
	c.Metadata.Host = "claude.ai"
	m.conns = []Connection{c}
	st := newTestGuard(t, m, "198.51.100.7", nil).Enforce(context.Background())
	if len(m.setModes) != 0 {
		t.Fatalf("mode must not change without guard rules: %v", m.setModes)
	}
	if st.RulesOK || m.group.Now != Reject || len(m.closed) != 1 {
		t.Fatalf("expected fail closed: rules_ok=%v group=%q closed=%v", st.RulesOK, m.group.Now, m.closed)
	}
}

func TestShadowedRulesFailClosed(t *testing.T) {
	m := freshMihomo()
	m.rules = append([]Rule{{Type: "DomainSuffix", Payload: "anthropic.com", Proxy: "DIRECT"}}, guardRules()...)
	st := newTestGuard(t, m, "198.51.100.7", nil).Enforce(context.Background())
	if st.RulesOK || m.group.Now != Reject {
		t.Fatalf("shadowed rules must reject: rules_ok=%v group=%q", st.RulesOK, m.group.Now)
	}
}

func TestMissingGroupOrControllerDownFailsClosed(t *testing.T) {
	m := freshMihomo()
	m.group = nil
	if st := newTestGuard(t, m, "198.51.100.7", nil).Enforce(context.Background()); st.Allowed {
		t.Fatal("missing guard group must not be allowed")
	}
	down := &fakeMihomo{modeErr: errors.New("dial unix: no such file")}
	if st := newTestGuard(t, down, "198.51.100.7", nil).Enforce(context.Background()); len(st.Problems) == 0 {
		t.Fatal("controller down must be reported")
	}
}

func TestProbeURLMustNotBeGuarded(t *testing.T) {
	cfg := testConfig(t)
	cfg.ProbeURLs = []string{"https://api.anthropic.com/cdn-cgi/trace"}
	if _, err := New(cfg, freshMihomo(), &fakeKernel{}, slog.Default()); err == nil {
		t.Fatal("expected error for guarded probe URL")
	}
}

func TestMatchesHostSuffixOnly(t *testing.T) {
	cfg := testConfig(t)
	for host, want := range map[string]bool{"anthropic.com": true, "api.anthropic.com": true, "notanthropic.com": false, "claude.ai.evil.example": false} {
		if got := cfg.MatchesHost(host); got != want {
			t.Errorf("%s: got %v want %v", host, got, want)
		}
	}
}

func TestMissingRulesWithDegradedProxyPinsGlobal(t *testing.T) {
	m := freshMihomo()
	m.group = nil // Script not applied: no guard group either
	m.mode = "rule"
	m.rules = []Rule{{Type: "GeoSite", Payload: "anthropic", Proxy: "Relay"}, {Type: "Match", Proxy: "Relay"}}
	m.nodes = map[string]Group{"GLOBAL": {Name: "GLOBAL", Type: "Selector", Now: "Relay", All: []string{"Relay", "Exit Node"}}}
	leak := Connection{ID: "c1", Chains: []string{"Relay"}}
	leak.Metadata.Host = "api.anthropic.com"
	m.conns = []Connection{leak}
	g := newTestGuard(t, m, "", errors.New("probe listener missing"))
	g.cfg.Mihomo.DegradedGlobalProxy = "Exit Node"
	st := g.Enforce(context.Background())
	if m.nodes["GLOBAL"].Now != "Exit Node" || m.mode != "global" || st.Mode != "global" {
		t.Fatalf("expected GLOBAL pinned and global mode, got now=%q mode=%q", m.nodes["GLOBAL"].Now, m.mode)
	}
	if len(m.closed) != 1 {
		t.Fatalf("guarded connection must still be closed: %v", m.closed)
	}
	// Once rules are back, the daemon returns to rule mode.
	m.group = &Group{Name: "Claude-Guard", Type: "Selector", Now: Reject, All: []string{Reject, pinned}}
	m.rules = guardRules()
	g.probeIP, g.probeErr = "198.51.100.7", nil
	if st := g.Enforce(context.Background()); st.Mode != "rule" || m.group.Now != pinned {
		t.Fatalf("expected recovery to rule mode: mode=%q group=%q", st.Mode, m.group.Now)
	}
}

func TestRenderVergeScriptUsesConfig(t *testing.T) {
	cfg := testConfig(t)
	cfg.Verge = &VergeConfig{ExitProxy: "Exit Node", UpperProxy: "Upper Node", ChainExit: true, UDPViaUpper: true}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	script, err := RenderVergeScript(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"exit_group": "Claude-142"`, `"exit_proxy": "Exit Node"`, `"upper_proxy": "Upper Node"`, `"probe_port": 17891`, `"160.79.104.0/21"`, `"default_group": "Out-Default"`, "function main(config, profileName)"} {
		if !strings.Contains(script, want) {
			t.Errorf("rendered script missing %s", want)
		}
	}
	if strings.Contains(script, "__GUARD_CONFIG__") {
		t.Error("marker not replaced")
	}
	bad := testConfig(t)
	bad.Verge = &VergeConfig{ExitProxy: "Exit Node", UpperProxy: "Upper Node"}
	bad.Mihomo.PinnedProxy = "Exit Node"
	if err := bad.validate(); err == nil {
		t.Error("pinned_proxy equal to the exit node must be rejected when verge is set")
	}
}
