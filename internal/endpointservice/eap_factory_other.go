//go:build (!darwin && !windows) || (darwin && !cgo)

package endpointservice

import "errors"

func NativeEAPSupported() bool { return false }
func NewNativeEAPSystem(Config) (EAPSystem, error) {
	return nil, errors.New("native EAP is unavailable in this service build")
}
