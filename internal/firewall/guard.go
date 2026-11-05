package firewall

import (
	"context"
	"net"
)

// GuardTable is the nftables table owned by the guard daemon. It is separate
// from the legacy apply/run table so the two modes never clobber each other.
const GuardTable = "claude_ip_guard"

// GuardKernel installs a fail-closed rule set: packets to the guarded
// networks are rejected unless they leave through an exempt interface
// (loopback or the mihomo TUN device, where mihomo applies the guard group).
type GuardKernel interface {
	Install(ctx context.Context, networks []*net.IPNet, exemptIfnames []string) error
	Clear(ctx context.Context) error
	Status(ctx context.Context) (string, error)
}

func NewGuardKernel() GuardKernel { return newGuardKernel() }
