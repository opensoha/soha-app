//go:build darwin && !cgo

package endpointservice

import "errors"

func newNativeInterceptionPlatform(Config, *UIProcessPresence) (nativePlatform, error) {
	return nil, errors.New("macOS native interception requires cgo and SystemConfiguration")
}
