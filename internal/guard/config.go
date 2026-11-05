// Package guard blocks traffic to Anthropic/Claude destinations unless the
// observed egress IP of the pinned mihomo node equals the expected IP.
package guard

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ExpectedEgressIP    string       `json:"expected_egress_ip"`
	ProbeProxy          string       `json:"probe_proxy"`
	ProbeURLs           []string     `json:"probe_urls"`
	ProbeInterval       Duration     `json:"probe_interval"`
	StateInterval       Duration     `json:"state_interval"`
	ResolveInterval     Duration     `json:"resolve_interval"`
	Mihomo              MihomoConfig `json:"mihomo"`
	Domains             []string     `json:"domains"`
	CIDRs               []string     `json:"cidrs"`
	KernelResolveHosts  []string     `json:"kernel_resolve_hosts"`
	DoHURL              string       `json:"doh_url"`
	KernelExemptIfnames []string     `json:"kernel_exempt_ifnames"`
	LogFile             string       `json:"log_file"`
	Verge               *VergeConfig `json:"verge,omitempty"`
	parsedCIDRs         []*net.IPNet `json:"-"`
	expectedIP          net.IP       `json:"-"`
}

type MihomoConfig struct {
	Socket      string `json:"socket"`
	URL         string `json:"url"`
	Secret      string `json:"secret"`
	GuardGroup  string `json:"guard_group"`
	PinnedProxy string `json:"pinned_proxy"`
	// DegradedGlobalProxy, if set, is used when the guard rules are not loaded
	// (Clash Verge did not run the Script): the daemon selects it on GLOBAL and
	// switches mihomo to global mode, so the profile's own rules cannot send
	// guarded traffic elsewhere. Guarded connections are still closed.
	DegradedGlobalProxy string `json:"degraded_global_proxy,omitempty"`
	EnforceMode         string `json:"enforce_mode"`
}

// VergeConfig describes the routing the generated Clash Verge Script builds.
type VergeConfig struct {
	// ExitProxy is the node whose egress IP is expected (the 142 node).
	ExitProxy string `json:"exit_proxy"`
	// UpperProxy is the node the exit is chained through, and the fallback
	// for non-guarded traffic when the chained exit is unreachable.
	UpperProxy string `json:"upper_proxy"`
	// ChainExit adds a "<exit> [chain]" copy dialed via UpperProxy. Guarded
	// traffic uses the chain first, then the direct exit; both leave from the
	// same egress IP.
	ChainExit bool `json:"chain_exit"`
	// DefaultGroup is the fallback group for all other traffic:
	// [chained exit, UpperProxy]. Set OtherTraffic to "profile" to keep the
	// profile's own rules instead.
	DefaultGroup string   `json:"default_group"`
	OtherTraffic string   `json:"other_traffic"`
	UpperDomains []string `json:"upper_domains"`
	UDPViaUpper  bool     `json:"udp_via_upper"`
	HealthURL    string   `json:"health_url"`
	HealthEvery  int      `json:"health_interval_seconds"`
	ProbeListen  string   `json:"probe_listen"`
	ProbePort    int      `json:"probe_port"`
}

// Duration accepts Go duration strings such as "10s" in JSON.
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string such as \"10s\"")
	}
	v, err := time.ParseDuration(s)
	if err != nil || v <= 0 {
		return fmt.Errorf("invalid duration %q", s)
	}
	d.Duration = v
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read guard config %q: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse guard config %q: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("guard config %q: %w", path, err)
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	c.expectedIP = net.ParseIP(strings.TrimSpace(c.ExpectedEgressIP))
	if c.expectedIP == nil {
		return fmt.Errorf("expected_egress_ip must be a valid IP")
	}
	if strings.TrimSpace(c.ProbeProxy) == "" {
		return fmt.Errorf("probe_proxy must be set (mihomo listener pinned to the guarded node)")
	}
	if len(c.ProbeURLs) == 0 {
		return fmt.Errorf("probe_urls must contain at least one URL")
	}
	if c.Mihomo.Socket == "" && c.Mihomo.URL == "" {
		return fmt.Errorf("mihomo.socket or mihomo.url must be set")
	}
	if c.Mihomo.GuardGroup == "" || c.Mihomo.PinnedProxy == "" {
		return fmt.Errorf("mihomo.guard_group and mihomo.pinned_proxy must be set")
	}
	if len(c.Domains) == 0 && len(c.CIDRs) == 0 {
		return fmt.Errorf("domains or cidrs must be set")
	}
	for i, d := range c.Domains {
		c.Domains[i] = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	}
	for _, s := range c.CIDRs {
		_, n, err := net.ParseCIDR(strings.TrimSpace(s))
		if err != nil {
			return fmt.Errorf("cidrs entry %q: %w", s, err)
		}
		c.parsedCIDRs = append(c.parsedCIDRs, n)
	}
	if c.ProbeInterval.Duration == 0 {
		c.ProbeInterval.Duration = 10 * time.Second
	}
	if c.StateInterval.Duration == 0 {
		c.StateInterval.Duration = time.Second
	}
	if c.ResolveInterval.Duration == 0 {
		c.ResolveInterval.Duration = 10 * time.Minute
	}
	if c.DoHURL == "" {
		c.DoHURL = "https://cloudflare-dns.com/dns-query"
	}
	if v := c.Verge; v != nil {
		if v.ExitProxy == "" || v.UpperProxy == "" {
			return fmt.Errorf("verge.exit_proxy and verge.upper_proxy must be set")
		}
		if v.DefaultGroup == "" {
			v.DefaultGroup = "Out-Default"
		}
		switch v.OtherTraffic {
		case "":
			v.OtherTraffic = "fallback"
		case "fallback", "profile":
		default:
			return fmt.Errorf("verge.other_traffic must be fallback or profile")
		}
		if v.HealthURL == "" {
			v.HealthURL = "http://cp.cloudflare.com/generate_204"
		}
		if v.HealthEvery == 0 {
			v.HealthEvery = 60
		}
		if v.ProbeListen == "" || v.ProbePort == 0 {
			u, err := url.Parse(c.ProbeProxy)
			if err != nil || u.Port() == "" {
				return fmt.Errorf("probe_proxy %q must include host:port", c.ProbeProxy)
			}
			port, _ := strconv.Atoi(u.Port())
			v.ProbeListen, v.ProbePort = u.Hostname(), port
		}
		if c.Mihomo.PinnedProxy == v.ExitProxy || c.Mihomo.PinnedProxy == c.Mihomo.GuardGroup {
			return fmt.Errorf("with verge set, mihomo.pinned_proxy names the exit group the Script creates (for example \"Claude-142\"), not the node or the guard group")
		}
	}
	if len(c.KernelExemptIfnames) == 0 {
		c.KernelExemptIfnames = []string{"lo", "Mihomo"}
	}
	return nil
}

// MatchesHost reports whether host equals or is a subdomain of a guarded domain.
func (c *Config) MatchesHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return false
	}
	for _, d := range c.Domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// MatchesIP reports whether ip is inside a guarded CIDR.
func (c *Config) MatchesIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range c.parsedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
