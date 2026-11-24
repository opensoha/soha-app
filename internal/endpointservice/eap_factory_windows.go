//go:build windows

package endpointservice

func NativeEAPSupported() bool { return true }

func NewNativeEAPSystem(config Config) (EAPSystem, error) {
	system, err := NewWindowsEAPSystem(config.StateDirectory, config.DeviceID, config.AllowedUserSID)
	if err != nil {
		return nil, err
	}
	system.requireTPM = config.RequireWindowsEAPTPM
	return system, nil
}
