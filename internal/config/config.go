package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const DefaultRefreshInterval = 10 * time.Minute

type Config struct {
	RefreshInterval  string   `json:"refresh_interval"`
	ExpectedEgressIP string   `json:"expected_egress_ip,omitempty"`
	EgressCheckURL   string   `json:"egress_check_url,omitempty"`
	Targets          []Target `json:"targets"`
	Allowlist        []string `json:"allowlist"`
}

type Target struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains,omitempty"`
	IPs     []string `json:"ips,omitempty"`
}

type Parsed struct {
	RefreshInterval  time.Duration
	ExpectedEgressIP string
	EgressCheckURL   string
	Targets          []Target
	Allowlist        []*net.IPNet
}

func Load(path string) (Parsed, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Parsed{}, fmt.Errorf("read config %q: %w", path, err)
	}
	var raw Config
	if err := json.Unmarshal(data, &raw); err != nil {
		return Parsed{}, fmt.Errorf("parse config %q: %w", path, err)
	}
	return Parse(raw)
}

func Parse(raw Config) (Parsed, error) {
	if len(raw.Targets) == 0 {
		return Parsed{}, fmt.Errorf("targets must contain at least one entry")
	}
	interval := DefaultRefreshInterval
	if strings.TrimSpace(raw.RefreshInterval) != "" {
		parsed, err := time.ParseDuration(raw.RefreshInterval)
		if err != nil || parsed <= 0 {
			return Parsed{}, fmt.Errorf("refresh_interval must be a positive duration such as 10m")
		}
		interval = parsed
	}
	expectedEgressIP := strings.TrimSpace(raw.ExpectedEgressIP)
	if expectedEgressIP != "" && net.ParseIP(expectedEgressIP) == nil {
		return Parsed{}, fmt.Errorf("expected_egress_ip must be a valid IP address")
	}
	egressCheckURL := strings.TrimSpace(raw.EgressCheckURL)
	if egressCheckURL == "" {
		egressCheckURL = "https://api.ipify.org?format=json"
	}

	allowlist := make([]*net.IPNet, 0, len(raw.Allowlist))
	for _, entry := range raw.Allowlist {
		cidr, err := parseCIDROrIP(entry)
		if err != nil {
			return Parsed{}, fmt.Errorf("allowlist entry %q: %w", entry, err)
		}
		allowlist = append(allowlist, cidr)
	}

	targets := make([]Target, 0, len(raw.Targets))
	for i, target := range raw.Targets {
		name := strings.TrimSpace(target.Name)
		if name == "" {
			return Parsed{}, fmt.Errorf("targets[%d].name must not be empty", i)
		}
		if len(target.Domains) == 0 && len(target.IPs) == 0 {
			return Parsed{}, fmt.Errorf("targets[%d] must define domains or ips", i)
		}
		clean := Target{Name: name}
		for _, domain := range target.Domains {
			domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
			if domain == "" {
				return Parsed{}, fmt.Errorf("targets[%d] contains an empty domain", i)
			}
			clean.Domains = append(clean.Domains, domain)
		}
		for _, address := range target.IPs {
			ip := net.ParseIP(strings.TrimSpace(address))
			if ip == nil {
				return Parsed{}, fmt.Errorf("targets[%d].ips entry %q is not an IP address", i, address)
			}
			clean.IPs = append(clean.IPs, ip.String())
		}
		targets = append(targets, clean)
	}

	return Parsed{RefreshInterval: interval, ExpectedEgressIP: expectedEgressIP, EgressCheckURL: egressCheckURL, Targets: targets, Allowlist: allowlist}, nil
}

func parseCIDROrIP(value string) (*net.IPNet, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("must not be empty")
	}
	if ip := net.ParseIP(value); ip != nil {
		bits := 128
		if ip.To4() != nil {
			ip = ip.To4()
			bits = 32
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
	}
	_, cidr, err := net.ParseCIDR(value)
	if err != nil {
		return nil, fmt.Errorf("must be an IP or CIDR")
	}
	return cidr, nil
}

func DefaultPath() string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "claude-ip-control", "config.json")
	}
	return "config.json"
}
