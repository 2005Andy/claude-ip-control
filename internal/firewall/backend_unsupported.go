//go:build !windows && !linux && !darwin

package firewall

import (
	"context"
	"net"
	"runtime"
)

type windowsBackend struct{}
type linuxBackend struct{}
type darwinBackend struct{}

func newPlatformBackend() Backend { return unsupportedBackend{os: runtime.GOOS} }

func (windowsBackend) Name() string                           { return "unsupported" }
func (windowsBackend) Apply(context.Context, []net.IP) error  { return nil }
func (windowsBackend) Clear(context.Context) error            { return nil }
func (windowsBackend) Status(context.Context) (string, error) { return "unsupported", nil }
func (linuxBackend) Name() string                             { return "unsupported" }
func (linuxBackend) Apply(context.Context, []net.IP) error    { return nil }
func (linuxBackend) Clear(context.Context) error              { return nil }
func (linuxBackend) Status(context.Context) (string, error)   { return "unsupported", nil }
func (darwinBackend) Name() string                            { return "unsupported" }
func (darwinBackend) Apply(context.Context, []net.IP) error   { return nil }
func (darwinBackend) Clear(context.Context) error             { return nil }
func (darwinBackend) Status(context.Context) (string, error)  { return "unsupported", nil }
