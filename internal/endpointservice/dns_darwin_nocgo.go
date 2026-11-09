//go:build darwin && !cgo

package endpointservice

import "errors"

type darwinDNS struct {
	serviceID string
	calls     *darwinDNSCalls
}

func openDarwinDNS(string, []string, []string) (*darwinDNS, error) {
	return nil, errors.New("macOS VPN DNS requires a native CGO build")
}
func (*darwinDNS) matches() bool { return false }
func (*darwinDNS) close() error  { return nil }

func (*darwinDNS) currentServers() ([]string, error) {
	return nil, errors.New("macOS VPN DNS requires a native CGO build")
}
func (*darwinDNS) compareServers([]string, []string) (string, error) {
	return "not_applied", errors.New("macOS VPN DNS requires a native CGO build")
}
