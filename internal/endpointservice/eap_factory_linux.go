//go:build linux

package endpointservice

import (
	"context"
	"time"
)

func NativeEAPSupported() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	o, err := newNMDBusOps(ctx)
	if err != nil {
		return false
	}
	defer o.Close()
	c, err := o.Capability(ctx)
	return err == nil && (c.TLS || c.TTLSPAP)
}
func NewNativeEAPSystem(c Config) (EAPSystem, error) {
	return newLinuxEAPSystem(c.StateDirectory, c.DeviceID)
}
