package endpointservice

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
)

func darwinNativePlan(s nativeSnapshot, p nativeInterceptionPlan, routeFlags uint32) ([]nativeChange, error) {
	fail := errors.New("invalid macOS native interception plan")
	var changes []nativeChange
	if p.SystemProxy {
		if !p.ProxyEndpoint.IsValid() || !p.ProxyEndpoint.Addr().IsLoopback() || p.ProxyEndpoint.Port() == 0 || s.PrimaryServiceID == "" {
			return nil, fail
		}
		required := map[string]nativeProxyValue{"HTTPEnable": {Bool: true}, "HTTPSEnable": {Bool: true}, "HTTPProxy": {Text: p.ProxyEndpoint.Addr().String()}, "HTTPSProxy": {Text: p.ProxyEndpoint.Addr().String()}, "HTTPPort": {Number: uint32(p.ProxyEndpoint.Port())}, "HTTPSPort": {Number: uint32(p.ProxyEndpoint.Port())}, "ProxyAutoConfigEnable": {}, "ProxyAutoDiscoveryEnable": {}}
		seen := map[string]bool{}
		for _, c := range s.Settings {
			if c.Kind == "proxy" && c.Scope.ServiceID == s.PrimaryServiceID {
				v, ok := required[c.Field]
				if !ok || seen[c.Field] {
					return nil, fail
				}
				seen[c.Field] = true
				c.After = nativeValue{Present: true, Proxy: &v}
				if !reflect.DeepEqual(c.Before, c.After) {
					changes = append(changes, c)
				}
			}
		}
		if len(seen) != len(required) {
			return nil, fail
		}
	}
	if p.TUN {
		if p.TUNInterface.ID == "" || p.TUNInterface.Index == 0 || p.TUNInterface.Kind != "tunnel" || len(p.CapturePrefixes) == 0 || len(p.CapturePrefixes) > nativeMaxCapturePrefixes || len(p.ExclusionRoutes) > 256 || len(p.DNSServers) == 0 || len(p.DNSServers) > 2 {
			return nil, fail
		}
		for _, a := range p.DNSServers {
			if !a.IsLoopback() {
				return nil, fail
			}
		}
		count := 0
		for _, c := range s.Settings {
			if c.Kind == "dns" && c.Scope.ServiceID == s.PrimaryServiceID {
				count++
				c.After = nativeValue{Present: true, DNS: &nativeDNSConfig{Servers: slices.Clone(p.DNSServers)}}
				if !reflect.DeepEqual(c.Before, c.After) {
					changes = append(changes, c)
				}
			}
		}
		if count != 1 {
			return nil, fail
		}
		routes := slices.Clone(p.ExclusionRoutes)
		for _, prefix := range p.CapturePrefixes {
			if !prefix.IsValid() || prefix != prefix.Masked() {
				return nil, fail
			}
			routes = append(routes, nativeRoute{Destination: prefix, Interface: p.TUNInterface, Flags: routeFlags})
		}
		for _, r := range routes {
			if !r.Destination.IsValid() || r.Interface.ID == "" || r.Interface.Index == 0 {
				return nil, fail
			}
			for _, existing := range s.Routes {
				if existing.Destination == r.Destination && existing.Interface.Index == r.Interface.Index {
					return nil, fail
				}
			}
			c := nativeChange{ID: fmt.Sprintf("darwin:route:%s:%s", r.Interface.ID, r.Destination), Kind: "route", Scope: nativeScope{Interface: r.Interface, Family: 6}, After: nativeValue{Present: true, Route: &r}}
			if r.Destination.Addr().Is4() {
				c.Scope.Family = 4
			}
			changes = append(changes, c)
		}
	}
	return changes, nil
}
func darwinNativeChooseExit(dest netip.Addr, s nativeSnapshot, wg TunnelReadback, up, bad uint32) (nativeExit, error) {
	fail := errors.New("macOS native exit is ambiguous or unverified")
	var authorized []netip.Prefix
	for _, raw := range wg.Routes {
		v, err := netip.ParsePrefix(raw)
		if err != nil {
			return nativeExit{}, fail
		}
		authorized = append(authorized, v)
	}
	var addresses []netip.Prefix
	for _, raw := range wg.Addresses {
		v, err := netip.ParsePrefix(raw)
		if err != nil {
			return nativeExit{}, fail
		}
		addresses = append(addresses, v)
	}
	wgDest := wg.PublicKey != "" && wg.Peer.PublicKey != "" && slices.ContainsFunc(authorized, func(v netip.Prefix) bool { return v.Contains(dest) })
	candidates := make([]nativeRoute, 0)
	for _, r := range s.Routes {
		if !r.Destination.Contains(dest) || r.Flags&up == 0 || r.Flags&bad != 0 {
			continue
		}
		isWG := wgDest && r.Interface.Kind == "tunnel" && len(addresses) > 0 && slices.Equal(r.Interface.Addresses, addresses) && slices.Contains(authorized, r.Destination)
		if wgDest {
			if isWG {
				candidates = append(candidates, r)
			}
		} else if r.Interface.Kind == "physical" {
			candidates = append(candidates, r)
		}
	}
	if len(candidates) == 0 {
		return nativeExit{}, fail
	}
	best := candidates[0]
	for _, r := range candidates[1:] {
		if r.Destination.Bits() > best.Destination.Bits() || r.Destination.Bits() == best.Destination.Bits() && r.Metric < best.Metric {
			best = r
		}
	}
	for _, r := range candidates {
		if r.Destination.Bits() == best.Destination.Bits() && r.Metric == best.Metric && !reflect.DeepEqual(r, best) {
			return nativeExit{}, fail
		}
	}
	var sources []netip.Addr
	for _, a := range best.Interface.Addresses {
		ip := a.Addr()
		if ip.Is4() == dest.Is4() && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLoopback() && (dest.IsLinkLocalUnicast() || !ip.IsLinkLocalUnicast()) {
			sources = append(sources, ip)
		}
	}
	// Source selection must be explicit rather than guessing among multiple addresses.
	if len(sources) != 1 {
		return nativeExit{}, fail
	}
	return nativeExit{Generation: s.Generation, Interface: best.Interface, Source: sources[0], Gateway: best.Gateway, ViaWG: wgDest, Route: best}, nil
}
