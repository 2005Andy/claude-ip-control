package guard

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed verge_script.js.tmpl
var vergeScriptTemplate string

// RenderVergeScript returns the Clash Verge global Script for cfg. Domains,
// CIDRs, group names and the probe listener come from the same config the
// daemon enforces, so the two cannot drift apart.
func RenderVergeScript(cfg *Config) (string, error) {
	v := cfg.Verge
	if v == nil {
		return "", fmt.Errorf("guard config has no \"verge\" section")
	}
	nonNil := func(list []string) []string {
		if list == nil {
			return []string{}
		}
		return list
	}
	upper := nonNil(v.UpperDomains)
	payload := map[string]any{
		"guard_group":             cfg.Mihomo.GuardGroup,
		"exit_group":              cfg.Mihomo.PinnedProxy,
		"exit_proxy":              v.ExitProxy,
		"upper_proxy":             v.UpperProxy,
		"chain_exit":              v.ChainExit,
		"default_group":           v.DefaultGroup,
		"other_traffic":           v.OtherTraffic,
		"upper_domains":           upper,
		"udp_via_upper":           v.UDPViaUpper,
		"health_url":              v.HealthURL,
		"health_interval_seconds": v.HealthEvery,
		"probe_listen":            v.ProbeListen,
		"probe_port":              v.ProbePort,
		"domains":                 nonNil(cfg.Domains),
		"cidrs":                   nonNil(cfg.CIDRs),
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", err
	}
	if !strings.Contains(vergeScriptTemplate, "__GUARD_CONFIG__") {
		return "", fmt.Errorf("script template has no __GUARD_CONFIG__ marker")
	}
	return strings.Replace(vergeScriptTemplate, "__GUARD_CONFIG__", string(data), 1), nil
}
