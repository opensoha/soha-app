package endpointservice

import (
	"context"
	"errors"
	"net/netip"
	"slices"
)

func nativeSplit(p netip.Prefix) (netip.Prefix, netip.Prefix, error) {
	if !p.IsValid() || p.Bits() >= p.Addr().BitLen() {
		return netip.Prefix{}, netip.Prefix{}, errors.New("route cannot be split")
	}
	a := p.Masked().Addr()
	bytes := a.AsSlice()
	bit := p.Bits()
	bytes[bit/8] |= 1 << uint(7-bit%8)
	b, ok := netip.AddrFromSlice(bytes)
	if !ok {
		return netip.Prefix{}, netip.Prefix{}, errors.New("invalid route address")
	}
	return netip.PrefixFrom(a, bit+1), netip.PrefixFrom(b, bit+1), nil
}
func nativeSubtract(prefixes []netip.Prefix, exclude netip.Prefix) ([]netip.Prefix, error) {
	result := []netip.Prefix{}
	pending := slices.Clone(prefixes)
	for len(pending) > 0 {
		p := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if !p.Overlaps(exclude) {
			result = append(result, p)
		} else if exclude.Bits() > p.Bits() {
			a, b, err := nativeSplit(p)
			if err != nil {
				return nil, err
			}
			pending = append(pending, a, b)
		}
		if len(result)+len(pending) > nativeMaxCapturePrefixes {
			return nil, errors.New("native route partition limit exceeded")
		}
	}
	return result, nil
}
func nativeSubtractAll(prefixes, exceptions []netip.Prefix) ([]netip.Prefix, error) {
	var err error
	for _, p := range exceptions {
		prefixes, err = nativeSubtract(prefixes, p)
		if err != nil {
			return nil, err
		}
	}
	return prefixes, nil
}
func nativePlanCaptures(s nativeSnapshot, wg TunnelReadback, controls []netip.Addr) ([]netip.Prefix, []netip.Prefix, error) {
	exceptions := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	for _, raw := range wg.Routes {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, nil, err
		}
		exceptions = append(exceptions, p)
	}
	add := func(a netip.Addr) {
		if a.IsValid() && !a.IsUnspecified() && !a.IsMulticast() {
			a = a.WithZone("")
			exceptions = append(exceptions, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	for _, i := range s.Interfaces {
		for _, p := range i.Addresses {
			add(p.Addr())
		}
	}
	for _, r := range s.Routes {
		if r.Interface.Kind == "physical" && r.Destination.Bits() == 0 {
			add(r.Gateway)
		}
	}
	for _, scope := range s.Resolvers {
		for _, a := range scope.Servers {
			add(a)
		}
	}
	for _, a := range controls {
		add(a)
	}
	slices.SortFunc(exceptions, func(a, b netip.Prefix) int {
		if a.Bits() != b.Bits() {
			return a.Bits() - b.Bits()
		}
		return a.Addr().Compare(b.Addr())
	})
	exceptions = slices.Compact(exceptions)
	if len(exceptions) > 256 {
		return nil, nil, errors.New("native route exception limit exceeded")
	}
	captures, err := nativeSubtractAll([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}, exceptions)
	if err != nil {
		return nil, nil, err
	}
	for _, r := range s.Routes {
		if !r.Destination.IsValid() || r.Destination.Bits() == 0 || r.Interface.Kind == "loopback" {
			continue
		}
		remaining, err := nativeSubtractAll([]netip.Prefix{r.Destination}, exceptions)
		if err != nil {
			return nil, nil, err
		}
		if len(remaining) == 0 {
			continue
		}
		if r.Interface.Kind != "physical" {
			return nil, nil, errors.New("unowned network route conflicts with native TUN")
		}
		for _, p := range remaining {
			if p.Bits() <= r.Destination.Bits() {
				a, b, err := nativeSplit(p)
				if err != nil {
					return nil, nil, errors.New("foreign host route cannot be safely captured")
				}
				captures = append(captures, a, b)
			} else {
				captures = append(captures, p)
			}
		}
	}
	slices.SortFunc(captures, func(a, b netip.Prefix) int {
		if a.Addr() != b.Addr() {
			return a.Addr().Compare(b.Addr())
		}
		return a.Bits() - b.Bits()
	})
	captures = slices.Compact(captures)
	if len(captures) == 0 || len(captures) > nativeMaxCapturePrefixes {
		return nil, nil, errors.New("native capture plan exceeds bounds")
	}
	return captures, exceptions, nil
}
func verifyNativeCoverage(s nativeSnapshot, iface nativeInterface, captures, exceptions []netip.Prefix) error {
	for _, foreign := range s.Routes {
		if foreign.Interface.ID == iface.ID || foreign.Interface.Kind == "loopback" {
			continue
		}
		remaining, err := nativeSubtractAll([]netip.Prefix{foreign.Destination}, exceptions)
		if err != nil {
			return err
		}
		if len(remaining) == 0 {
			continue
		}
		for _, p := range captures {
			if p.Bits() > foreign.Destination.Bits() {
				remaining, err = nativeSubtract(remaining, p)
				if err != nil {
					return err
				}
			}
		}
		if len(remaining) > 0 {
			return errors.New("native TUN is shadowed by an existing route")
		}
	}
	return nil
}
func nativeControlAddresses(ctx context.Context, dns *nativeDNSProxy, hosts []string) ([]netip.Addr, error) {
	var addresses []netip.Addr
	for _, host := range hosts {
		if ip, err := netip.ParseAddr(host); err == nil {
			addresses = append(addresses, ip)
			continue
		}
		values, err := dns.lookup(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, values...)
	}
	if len(addresses) > 64 {
		return nil, errors.New("control endpoint address limit exceeded")
	}
	return addresses, nil
}
