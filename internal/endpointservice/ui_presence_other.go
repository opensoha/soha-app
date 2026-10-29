//go:build (!darwin && !windows) || (darwin && !cgo)

package endpointservice

import "errors"

func NewUIProcessPresence(config Config) (*UIProcessPresence, error) {
	if config.UIExecutable != "" || config.UICodeIdentity != "" {
		return nil, errors.New("trusted native UI presence is unavailable on this build")
	}
	return nil, nil
}
