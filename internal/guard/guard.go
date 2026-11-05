package guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/2005Andy/claude-ip-control/internal/egress"
	"github.com/2005Andy/claude-ip-control/internal/firewall"
)

const Reject = "REJECT"

// Status is the guard's view of the world after one enforcement pass.
type Status struct {
	Updated       time.Time `json:"updated"`
	Allowed       bool      `json:"allowed"`
	ExpectedIP    string    `json:"expected_ip"`
	ObservedIP    string    `json:"observed_ip,omitempty"`
	ProbeError    string    `json:"probe_error,omitempty"`
	ProbeAge      string    `json:"probe_age,omitempty"`
	Mode          string    `json:"mode,omitempty"`
	GroupNow      string    `json:"group_now,omitempty"`
	RulesOK       bool      `json:"rules_ok"`
	KernelOK      bool      `json:"kernel_ok"`
	KernelEntries int       `json:"kernel_entries"`
	Problems      []string  `json:"problems,omitempty"`
}

type ProbeFunc func(ctx context.Context) (string, error)
type ResolveFunc func(ctx context.Context, host string) ([]net.IP, error)

type Guard struct {
	cfg     *Config
	mihomo  Mihomo
	kernel  firewall.GuardKernel
	probe   ProbeFunc
	resolve ResolveFunc
	log     *slog.Logger
	now     func() time.Time

	StatusFile string

	mu         sync.Mutex
	probeAt    time.Time
	probeIP    string
	probeErr   error
	resolved   map[string][]net.IP
	kernelOK   bool
	kernelN    int
	lastSig    string
	lastStatus Status
	lastWrite  time.Time
}

func New(cfg *Config, m Mihomo, k firewall.GuardKernel, log *slog.Logger) (*Guard, error) {
	probeClient, err := proxyClient(cfg.ProbeProxy)
	if err != nil {
		return nil, err
	}
	for _, u := range cfg.ProbeURLs {
		parsed, err := url.Parse(u)
		if err != nil || parsed.Hostname() == "" {
			return nil, fmt.Errorf("probe_urls entry %q is not a URL", u)
		}
		if cfg.MatchesHost(parsed.Hostname()) {
			return nil, fmt.Errorf("probe_urls entry %q is a guarded domain; the probe must not reach Anthropic", u)
		}
	}
	g := &Guard{cfg: cfg, mihomo: m, kernel: k, log: log, now: time.Now, resolved: map[string][]net.IP{}}
	g.probe = func(ctx context.Context) (string, error) {
		var errs []string
		for _, u := range cfg.ProbeURLs {
			ip, err := egress.Observe(ctx, probeClient, u)
			if err == nil {
				return ip, nil
			}
			errs = append(errs, err.Error())
		}
		return "", errors.New(strings.Join(errs, "; "))
	}
	g.resolve = func(ctx context.Context, host string) ([]net.IP, error) {
		return dohResolve(ctx, probeClient, cfg.DoHURL, host)
	}
	return g, nil
}

func proxyClient(proxy string) (*http.Client, error) {
	u, err := url.Parse(proxy)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("probe_proxy %q must be a URL such as http://127.0.0.1:17891", proxy)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: true}
	return &http.Client{Transport: transport, Timeout: 8 * time.Second}, nil
}

// Run starts the background loops and blocks until ctx is cancelled.
func (g *Guard) Run(ctx context.Context) error {
	if err := g.installKernel(ctx); err != nil {
		g.log.Error("kernel layer install failed; will retry", "err", err)
	}
	// Fail closed at startup until the first probe succeeds.
	if err := g.mihomo.Select(ctx, g.cfg.Mihomo.GuardGroup, Reject); err != nil {
		g.log.Warn("initial REJECT selection failed", "err", err)
	}
	go g.loop(ctx, g.cfg.ProbeInterval.Duration, g.probeOnce)
	go g.loop(ctx, g.cfg.ResolveInterval.Duration, g.resolveOnce)
	ticker := time.NewTicker(g.cfg.StateInterval.Duration)
	defer ticker.Stop()
	heartbeat := time.NewTicker(time.Hour)
	defer heartbeat.Stop()
	for {
		st := g.Enforce(ctx)
		g.report(st)
		select {
		case <-ctx.Done():
			return nil
		case <-heartbeat.C:
			g.log.Info("heartbeat", statusAttrs(st)...)
		case <-ticker.C:
		}
	}
}

func (g *Guard) loop(ctx context.Context, every time.Duration, fn func(context.Context)) {
	fn(ctx)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn(ctx)
		}
	}
}

func (g *Guard) probeOnce(ctx context.Context) {
	pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	ip, err := g.probe(pctx)
	g.mu.Lock()
	g.probeAt, g.probeIP, g.probeErr = g.now(), ip, err
	g.mu.Unlock()
}

func (g *Guard) resolveOnce(ctx context.Context) {
	for _, host := range g.cfg.KernelResolveHosts {
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		ips, err := g.resolve(rctx, host)
		cancel()
		if err != nil {
			g.log.Warn("resolve failed; keeping previous addresses", "host", host, "err", err)
			continue
		}
		g.mu.Lock()
		g.resolved[host] = ips
		g.mu.Unlock()
	}
	if err := g.installKernel(ctx); err != nil {
		g.log.Error("kernel layer install failed", "err", err)
	}
}

func (g *Guard) installKernel(ctx context.Context) error {
	networks := append([]*net.IPNet{}, g.cfg.parsedCIDRs...)
	g.mu.Lock()
	hosts := make([]string, 0, len(g.resolved))
	for h := range g.resolved {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		for _, ip := range g.resolved[h] {
			if g.cfg.MatchesIP(ip) {
				continue
			}
			bits := 128
			if ip.To4() != nil {
				ip, bits = ip.To4(), 32
			}
			networks = append(networks, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	g.mu.Unlock()
	err := g.kernel.Install(ctx, networks, g.cfg.KernelExemptIfnames)
	g.mu.Lock()
	g.kernelOK, g.kernelN = err == nil, len(networks)
	g.mu.Unlock()
	return err
}

// Enforce runs one pass: verdict -> mode -> rules -> group selection -> sweep.
func (g *Guard) Enforce(ctx context.Context) Status {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	g.mu.Lock()
	st := Status{Updated: g.now(), ExpectedIP: g.cfg.expectedIP.String(), ObservedIP: g.probeIP, KernelOK: g.kernelOK, KernelEntries: g.kernelN}
	probeAt, probeErr := g.probeAt, g.probeErr
	g.mu.Unlock()

	maxAge := 3 * g.cfg.ProbeInterval.Duration
	switch {
	case probeAt.IsZero():
		st.ProbeError = "no probe result yet"
	case g.now().Sub(probeAt) > maxAge:
		st.ProbeError = fmt.Sprintf("probe result is stale (%s old)", g.now().Sub(probeAt).Round(time.Second))
	case probeErr != nil:
		st.ProbeError = probeErr.Error()
	case net.ParseIP(st.ObservedIP).Equal(g.cfg.expectedIP):
		st.Allowed = true
	default:
		st.ProbeError = fmt.Sprintf("egress IP mismatch: observed %s", st.ObservedIP)
	}
	if !probeAt.IsZero() {
		st.ProbeAge = g.now().Sub(probeAt).Round(time.Second).String()
	}
	if !st.KernelOK {
		st.Problems = append(st.Problems, "kernel layer not installed")
	}

	mode, err := g.mihomo.Mode(ctx)
	if err != nil {
		st.Problems = append(st.Problems, "mihomo controller unreachable: "+err.Error())
		return st // mihomo down: TUN is down too, kernel layer rejects direct Anthropic traffic.
	}
	st.Mode = mode
	// Rules first: forcing rule mode without the guard rules loaded would send
	// Anthropic traffic through whatever the profile's own rules choose.
	rules, err := g.mihomo.Rules(ctx)
	if err != nil {
		st.Problems = append(st.Problems, "read rules failed: "+err.Error())
	} else {
		var reason string
		st.RulesOK, reason = verifyRules(g.cfg, rules)
		if !st.RulesOK {
			st.Problems = append(st.Problems, "guard rules not loaded, closing all guarded connections: "+reason)
		}
	}
	if rulesKnownMissing := err == nil && !st.RulesOK; rulesKnownMissing && g.cfg.Mihomo.DegradedGlobalProxy != "" {
		g.degrade(ctx, &st)
	}
	if want := g.cfg.Mihomo.EnforceMode; want != "" && mode != want && st.RulesOK {
		if err := g.mihomo.SetMode(ctx, want); err != nil {
			st.Problems = append(st.Problems, fmt.Sprintf("mode is %s and switching to %s failed: %v", mode, want, err))
		} else {
			g.log.Warn("mihomo mode changed; restored", "from", mode, "to", want)
			st.Mode = want
		}
	}

	desired := Reject
	group, err := g.mihomo.Group(ctx, g.cfg.Mihomo.GuardGroup)
	switch {
	case err != nil:
		st.Problems = append(st.Problems, fmt.Sprintf("guard group %q unavailable: %v", g.cfg.Mihomo.GuardGroup, err))
		st.Allowed = false
	case !contains(group.All, Reject):
		st.Problems = append(st.Problems, "guard group has no REJECT member")
		st.Allowed = false
	case st.Allowed && !contains(group.All, g.cfg.Mihomo.PinnedProxy):
		st.Problems = append(st.Problems, fmt.Sprintf("pinned proxy %q is not in the guard group", g.cfg.Mihomo.PinnedProxy))
		st.Allowed = false
	}
	if st.Allowed && st.RulesOK && st.Mode == "rule" {
		desired = g.cfg.Mihomo.PinnedProxy
	}
	if err == nil {
		st.GroupNow = group.Now
		if group.Now != desired {
			if serr := g.mihomo.Select(ctx, g.cfg.Mihomo.GuardGroup, desired); serr != nil {
				st.Problems = append(st.Problems, fmt.Sprintf("select %s failed: %v", desired, serr))
			} else {
				g.log.Info("guard group switched", "from", group.Now, "to", desired, "observed_ip", st.ObservedIP, "reason", firstNonEmpty(st.ProbeError, "egress verified"))
				st.GroupNow = desired
			}
		}
	}
	g.sweep(ctx, st.GroupNow == g.cfg.Mihomo.PinnedProxy && desired == g.cfg.Mihomo.PinnedProxy, &st)
	return st
}

// degrade pins GLOBAL to the degraded proxy and switches to global mode, so
// that without the guard rules the profile's rules cannot route guarded
// traffic to another node. GLOBAL is selected first, then the mode changes.
func (g *Guard) degrade(ctx context.Context, st *Status) {
	want := g.cfg.Mihomo.DegradedGlobalProxy
	global, err := g.mihomo.Group(ctx, "GLOBAL")
	if err != nil {
		st.Problems = append(st.Problems, "degraded: read GLOBAL failed: "+err.Error())
		return
	}
	if global.Now != want {
		if !contains(global.All, want) {
			st.Problems = append(st.Problems, fmt.Sprintf("degraded: %q is not a GLOBAL member", want))
			return
		}
		if err := g.mihomo.Select(ctx, "GLOBAL", want); err != nil {
			st.Problems = append(st.Problems, "degraded: select GLOBAL failed: "+err.Error())
			return
		}
		g.log.Warn("guard rules missing; GLOBAL pinned", "proxy", want, "was", global.Now)
	}
	if st.Mode != "global" {
		if err := g.mihomo.SetMode(ctx, "global"); err != nil {
			st.Problems = append(st.Problems, "degraded: switch to global failed: "+err.Error())
			return
		}
		g.log.Warn("guard rules missing; switched to global mode", "from", st.Mode, "global", want)
		st.Mode = "global"
	}
	st.Problems = append(st.Problems, "degraded: guard rules not loaded, mihomo held in global mode on "+want)
}

// verifyRules checks that the first rules route every guarded domain/CIDR to
// the guard group before any non-guard rule can match.
func verifyRules(cfg *Config, rules []Rule) (bool, string) {
	want := map[string]bool{}
	for _, d := range cfg.Domains {
		want["domainsuffix:"+d] = true
	}
	for _, c := range cfg.parsedCIDRs {
		want["ipcidr:"+c.String()] = true
	}
	for _, r := range rules {
		if r.Proxy != cfg.Mihomo.GuardGroup {
			break // first non-guard rule: everything wanted must already be seen
		}
		typ := strings.ToLower(strings.ReplaceAll(r.Type, "-", ""))
		if typ == "ipcidr6" {
			typ = "ipcidr"
		}
		payload := strings.ToLower(strings.TrimSpace(r.Payload))
		if typ == "ipcidr" {
			if _, n, err := net.ParseCIDR(payload); err == nil {
				payload = n.String()
			}
		}
		delete(want, typ+":"+payload)
	}
	if len(want) == 0 {
		return true, ""
	}
	missing := make([]string, 0, len(want))
	for k := range want {
		missing = append(missing, k)
	}
	sort.Strings(missing)
	return false, "not at top of rule list: " + strings.Join(missing, ", ")
}

// sweep closes guarded connections that are not on the verified path.
func (g *Guard) sweep(ctx context.Context, pinnedOK bool, st *Status) {
	conns, err := g.mihomo.Connections(ctx)
	if err != nil {
		st.Problems = append(st.Problems, "list connections failed: "+err.Error())
		return
	}
	for _, c := range conns {
		host := firstNonEmpty(c.Metadata.SniffHost, c.Metadata.Host)
		if !g.cfg.MatchesHost(c.Metadata.Host) && !g.cfg.MatchesHost(c.Metadata.SniffHost) && !g.cfg.MatchesIP(net.ParseIP(c.Metadata.DestinationIP)) {
			continue
		}
		onPath := contains(c.Chains, g.cfg.Mihomo.GuardGroup) && contains(c.Chains, g.cfg.Mihomo.PinnedProxy)
		if pinnedOK && onPath {
			continue
		}
		if err := g.mihomo.CloseConnection(ctx, c.ID); err != nil {
			st.Problems = append(st.Problems, "close connection failed: "+err.Error())
			continue
		}
		g.log.Warn("closed guarded connection", "host", host, "dst", c.Metadata.DestinationIP, "chains", strings.Join(c.Chains, " <- "), "rule", c.Rule)
	}
}

func (g *Guard) report(st Status) {
	sig := fmt.Sprintf("%v|%s|%s|%s|%v|%v|%s", st.Allowed, st.ObservedIP, st.Mode, st.GroupNow, st.RulesOK, st.KernelOK, strings.Join(st.Problems, ";"))
	errSig := st.ProbeError
	if i := strings.Index(errSig, ":"); i > 0 && !strings.HasPrefix(errSig, "egress IP mismatch") {
		errSig = errSig[:i] // avoid re-logging every tick for changing error text
	}
	sig += "|" + errSig
	g.mu.Lock()
	changed := sig != g.lastSig
	g.lastSig, g.lastStatus = sig, st
	write := changed || g.now().Sub(g.lastWrite) > 10*time.Second
	if write {
		g.lastWrite = g.now()
	}
	g.mu.Unlock()
	if changed {
		level := slog.LevelInfo
		if !st.Allowed || len(st.Problems) > 0 {
			level = slog.LevelWarn
		}
		g.log.Log(context.Background(), level, "state", statusAttrs(st)...)
	}
	if write && g.StatusFile != "" {
		if err := writeStatus(g.StatusFile, st); err != nil && changed {
			g.log.Warn("write status file failed", "err", err)
		}
	}
}

func statusAttrs(st Status) []any {
	attrs := []any{"allowed", st.Allowed, "expected", st.ExpectedIP, "observed", st.ObservedIP, "mode", st.Mode, "group", st.GroupNow, "rules_ok", st.RulesOK, "kernel_ok", st.KernelOK, "kernel_entries", st.KernelEntries}
	if st.ProbeError != "" {
		attrs = append(attrs, "probe_error", st.ProbeError)
	}
	if len(st.Problems) > 0 {
		attrs = append(attrs, "problems", strings.Join(st.Problems, "; "))
	}
	return attrs
}

func writeStatus(path string, st Status) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// dohResolve queries a DNS-over-HTTPS JSON endpoint for A and AAAA records.
func dohResolve(ctx context.Context, client *http.Client, endpoint, host string) ([]net.IP, error) {
	var ips []net.IP
	for _, typ := range []string{"A", "AAAA"} {
		u := endpoint + "?name=" + url.QueryEscape(host) + "&type=" + typ
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/dns-json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("doh %s %s: %w", typ, host, err)
		}
		var out struct {
			Status int `json:"Status"`
			Answer []struct {
				Type int    `json:"type"`
				Data string `json:"data"`
			} `json:"Answer"`
		}
		err = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("doh %s %s: decode: %w", typ, host, err)
		}
		if out.Status != 0 {
			return nil, fmt.Errorf("doh %s %s: rcode %d", typ, host, out.Status)
		}
		for _, a := range out.Answer {
			if a.Type != 1 && a.Type != 28 {
				continue
			}
			if ip := net.ParseIP(a.Data); ip != nil {
				ips = append(ips, ip)
			}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("doh %s: no A/AAAA records", host)
	}
	return ips, nil
}

// Once runs a single synchronous probe, kernel install and enforcement pass.
func (g *Guard) Once(ctx context.Context) Status {
	g.probeOnce(ctx)
	g.resolveOnce(ctx)
	st := g.Enforce(ctx)
	g.report(st)
	return st
}
