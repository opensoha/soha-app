//go:build windows || darwin

package endpointservice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
)

func interfaceIPv4Addresses(adapter *net.Interface) ([]string, error) {
	values, err := adapter.Addrs()
	if err != nil {
		return nil, fmt.Errorf("read WireGuard addresses: %w", err)
	}
	addresses := make([]string, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value.String())
		if err == nil && prefix.Addr().Is4() {
			addresses = append(addresses, prefix.Masked().String())
		}
	}
	slices.Sort(addresses)
	return slices.Compact(addresses), nil
}

func allowedIPv4Prefixes(values []net.IPNet) ([]string, error) {
	result := make([]string, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value.String())
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() == 0 {
			return nil, errors.New("WireGuard AllowedIPs contain an unsafe route")
		}
		result = append(result, prefix.Masked().String())
	}
	slices.Sort(result)
	return slices.Compact(result), nil
}

func endpointMatches(ctx context.Context, expected string, actual *net.UDPAddr) bool {
	host, portRaw, err := net.SplitHostPort(expected)
	if err != nil || actual == nil {
		return false
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil || actual.Port != port {
		return false
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Unmap() == netip.MustParseAddr(actual.IP.String()).Unmap()
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return false
	}
	actualAddress, ok := netip.AddrFromSlice(actual.IP)
	if !ok {
		return false
	}
	for _, address := range addresses {
		if address.Unmap() == actualAddress.Unmap() {
			return true
		}
	}
	return false
}

func cloneTunnelPlan(plan TunnelPlan) TunnelPlan {
	plan.Addresses = slices.Clone(plan.Addresses)
	plan.Routes = slices.Clone(plan.Routes)
	plan.DNSServers = slices.Clone(plan.DNSServers)
	plan.Peer.AllowedIPs = slices.Clone(plan.Peer.AllowedIPs)
	return plan
}
