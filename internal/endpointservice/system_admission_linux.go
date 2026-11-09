//go:build linux

package endpointservice

import (
	"context"
	"errors"
	"path/filepath"
)

// Linux admission does not claim ownership of a WireGuard interface.
type LinuxAdmissionSystem struct{}

func (*LinuxAdmissionSystem) Apply(context.Context, TunnelPlan) error {
	return errors.New("Linux native VPN is unavailable in this build")
}
func (*LinuxAdmissionSystem) Readback(context.Context) (TunnelReadback, error) {
	return TunnelReadback{}, nil
}
func (*LinuxAdmissionSystem) Disable(context.Context) error { return nil }
func (*LinuxAdmissionSystem) CheckVPNHealth(context.Context) error {
	return errors.New("Linux native VPN is unavailable in this build")
}
func ValidateLinuxServiceFile(path string) error {
	if filepath.Dir(path) != LinuxStateDirectory {
		return errors.New("Linux service files must use the protected state directory")
	}
	return linuxEAPProtected(path, true)
}
