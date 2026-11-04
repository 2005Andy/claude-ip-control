package firewall

import (
	"context"
	"fmt"
	"net"
)

type Backend interface {
	Name() string
	Apply(context.Context, []net.IP) error
	Clear(context.Context) error
	Status(context.Context) (string, error)
}

func New() Backend {
	return newPlatformBackend()
}

type unsupportedBackend struct{ os string }

func (b unsupportedBackend) Name() string { return "unsupported" }
func (b unsupportedBackend) Apply(context.Context, []net.IP) error {
	return fmt.Errorf("unsupported operating system: %s", b.os)
}
func (b unsupportedBackend) Clear(context.Context) error {
	return fmt.Errorf("unsupported operating system: %s", b.os)
}
func (b unsupportedBackend) Status(context.Context) (string, error) {
	return "unsupported operating system: " + b.os, nil
}
