package controller

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/2005Andy/claude-ip-control/internal/config"
	"github.com/2005Andy/claude-ip-control/internal/firewall"
)

type Resolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
}

type Controller struct {
	Resolver Resolver
	Firewall firewall.Backend
	LastPlan Plan
}

type Plan struct {
	Blocked []net.IP
	Checked int
	Sources []string
}

type NetResolver struct{}

func (NetResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, network, host)
}

func New(fw firewall.Backend) *Controller {
	return &Controller{Resolver: NetResolver{}, Firewall: fw}
}

func (c *Controller) BuildPlan(ctx context.Context, cfg config.Parsed) (Plan, error) {
	if c.Resolver == nil {
		return Plan{}, fmt.Errorf("resolver is not configured")
	}
	seen := make(map[string]net.IP)
	sources := make([]string, 0)
	checked := 0
	for _, target := range cfg.Targets {
		for _, address := range target.IPs {
			ip := net.ParseIP(address)
			if ip == nil {
				return Plan{}, fmt.Errorf("target %q contains invalid IP %q", target.Name, address)
			}
			checked++
			if !isAllowed(ip, cfg.Allowlist) {
				seen[ip.String()] = ip
			}
		}
		for _, domain := range target.Domains {
			ips, err := c.Resolver.LookupIP(ctx, "ip", domain)
			if err != nil {
				return Plan{}, fmt.Errorf("resolve %s (%s): %w", domain, target.Name, err)
			}
			if len(ips) == 0 {
				return Plan{}, fmt.Errorf("resolve %s (%s): no addresses returned", domain, target.Name)
			}
			sources = append(sources, domain)
			for _, ip := range ips {
				if ip == nil {
					continue
				}
				checked++
				if !isAllowed(ip, cfg.Allowlist) {
					seen[ip.String()] = ip
				}
			}
		}
	}

	blocked := make([]net.IP, 0, len(seen))
	for _, ip := range seen {
		blocked = append(blocked, ip)
	}
	sort.Slice(blocked, func(i, j int) bool { return blocked[i].String() < blocked[j].String() })
	return Plan{Blocked: blocked, Checked: checked, Sources: sources}, nil
}

func (c *Controller) Apply(ctx context.Context, cfg config.Parsed) (Plan, error) {
	plan, err := c.BuildPlan(ctx, cfg)
	if err != nil {
		return Plan{}, err
	}
	if err := c.Firewall.Apply(ctx, plan.Blocked); err != nil {
		return Plan{}, err
	}
	c.LastPlan = plan
	return plan, nil
}

func (c *Controller) Clear(ctx context.Context) error {
	if err := c.Firewall.Clear(ctx); err != nil {
		return err
	}
	c.LastPlan = Plan{}
	return nil
}

func isAllowed(ip net.IP, allowlist []*net.IPNet) bool {
	for _, network := range allowlist {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func FormatPlan(plan Plan) string {
	addresses := make([]string, 0, len(plan.Blocked))
	for _, ip := range plan.Blocked {
		addresses = append(addresses, ip.String())
	}
	if len(addresses) == 0 {
		return fmt.Sprintf("checked %d target addresses; nothing to block", plan.Checked)
	}
	return fmt.Sprintf("checked %d target addresses; blocking %d: %s", plan.Checked, len(addresses), strings.Join(addresses, ", "))
}
