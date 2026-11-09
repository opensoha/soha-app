//go:build !windows && !darwin

package endpointservice

import "errors"

func newNativeInterceptionPlatform(Config, *UIProcessPresence) (nativePlatform, error) {
	return nil, errors.New("native interception is unavailable on this platform")
}
