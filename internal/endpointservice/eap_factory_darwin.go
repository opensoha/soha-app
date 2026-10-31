//go:build darwin && cgo

package endpointservice

import "errors"

func NativeEAPSupported() bool { return true }

func NewNativeEAPSystem(config Config) (EAPSystem, error) {
	if config.AllowedUserUID == nil {
		return nil, errors.New("macOS EAP requires a desktop user UID")
	}
	return NewDarwinEAPSystem(config.StateDirectory, config.DeviceID, *config.AllowedUserUID)
}
