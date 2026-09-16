//go:build darwin && !cgo

package endpointservice

import "errors"

type darwinDNS struct{}

func openDarwinDNS(string, []string, []string) (*darwinDNS, error) {
	return nil, errors.New("macOS VPN DNS requires a native CGO build")
}
func (*darwinDNS) matches() bool { return false }
func (*darwinDNS) close() error  { return nil }
