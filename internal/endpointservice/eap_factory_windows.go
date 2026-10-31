//go:build windows

package endpointservice

func NativeEAPSupported() bool { return true }

func NewNativeEAPSystem(config Config) (EAPSystem, error) {
	return NewWindowsEAPSystem(config.StateDirectory, config.DeviceID, config.AllowedUserSID)
}
