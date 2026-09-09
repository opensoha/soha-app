package endpointservice

import (
	"fmt"
	"net/netip"
	"strings"
)

func renderWireGuardConfig(plan TunnelPlan) []byte {
	var config strings.Builder
	fmt.Fprintf(&config, "[Interface]\nPrivateKey = %s\nAddress = %s\n", plan.PrivateKey, strings.Join(plan.Addresses, ", "))
	if len(plan.DNSServers) != 0 {
		fmt.Fprintf(&config, "DNS = %s\n", strings.Join(plan.DNSServers, ", "))
	}
	fmt.Fprintf(&config, "MTU = %d\n\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\nEndpoint = %s\nPersistentKeepalive = %d\n", plan.MTU, plan.Peer.PublicKey, strings.Join(plan.Peer.AllowedIPs, ", "), plan.Peer.Endpoint, plan.Peer.PersistentKeepaliveSeconds)
	return []byte(config.String())
}

func verifyRouteSet(actual []netip.Prefix, required, allowedExtras []string) error {
	allowed := make(map[string]struct{}, len(required)+len(allowedExtras))
	missing := make(map[string]struct{}, len(required))
	for _, raw := range required {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return fmt.Errorf("invalid expected route %q", raw)
		}
		value := prefix.Masked().String()
		allowed[value], missing[value] = struct{}{}, struct{}{}
	}
	for _, raw := range allowedExtras {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return fmt.Errorf("invalid allowed route %q", raw)
		}
		allowed[prefix.Masked().String()] = struct{}{}
	}
	for _, prefix := range actual {
		prefix = prefix.Masked()
		if prefix.Addr().IsMulticast() || prefix == netip.MustParsePrefix("255.255.255.255/32") {
			continue
		}
		value := prefix.String()
		if _, ok := allowed[value]; !ok {
			return fmt.Errorf("WireGuard interface has unexpected route %s", value)
		}
		delete(missing, value)
	}
	for route := range missing {
		return fmt.Errorf("WireGuard route %s was not installed", route)
	}
	return nil
}
