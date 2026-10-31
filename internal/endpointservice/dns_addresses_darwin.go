package endpointservice

import (
	"errors"
	"net/netip"
)

// SystemConfiguration uses distinct address properties and service entities
// for IPv4 and IPv6, including when both belong to the same tunnel interface.
func splitDarwinDNSAddresses(addresses []string) (ipv4, ipv6 []string, err error) {
	if len(addresses) == 0 {
		return nil, nil, errors.New("macOS VPN DNS requires a tunnel address")
	}
	for _, text := range addresses {
		address, parseErr := netip.ParseAddr(text)
		if parseErr != nil || address.Is4In6() || address.Zone() != "" || !address.IsGlobalUnicast() {
			return nil, nil, errors.New("macOS VPN DNS tunnel address is invalid")
		}
		if address.Is4() {
			ipv4 = append(ipv4, address.String())
		} else {
			ipv6 = append(ipv6, address.String())
		}
	}
	return ipv4, ipv6, nil
}
