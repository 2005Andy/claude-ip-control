//go:build !linux

package firewall

import (
	"context"
	"fmt"
	"net"
	"runtime"
)

type unsupportedGuardKernel struct{}

func newGuardKernel() GuardKernel { return unsupportedGuardKernel{} }

func (unsupportedGuardKernel) Install(context.Context, []*net.IPNet, []string) error {
	return fmt.Errorf("guard kernel layer is only implemented for Linux nftables (running on %s)", runtime.GOOS)
}

func (unsupportedGuardKernel) Clear(context.Context) error { return nil }

func (unsupportedGuardKernel) Status(context.Context) (string, error) {
	return "guard kernel layer not supported on " + runtime.GOOS, nil
}
