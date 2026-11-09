package endpointservice

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"
)

func winNativeEqual(a, b nativeValue) bool { return reflect.DeepEqual(a, b) }
func winNativeValidate(c nativeChange) error {
	if c.Kind != "route" && c.Kind != "dns" && c.Kind != "proxy" {
		return errors.New("unknown native kind")
	}
	if c.Kind != "proxy" && c.Field != "" {
		return errors.New("unexpected native field")
	}
	if c.Kind == "proxy" && !reflect.DeepEqual(c.Scope, nativeScope{}) {
		return errors.New("invalid proxy scope")
	}
	if c.Kind == "proxy" && c.Field != "flags" && c.Field != "server" && c.Field != "pac" && c.Field != "bypass" {
		return errors.New("unknown proxy property")
	}
	if c.Kind == "dns" && (c.Scope.Interface.ID == "" || c.Scope.Interface.Index == 0 || (c.Scope.Family != 4 && c.Scope.Family != 6)) {
		return errors.New("invalid DNS scope")
	}
	if c.ID == "" || len(c.ID) > 512 {
		return errors.New("invalid native change identity")
	}
	for _, v := range []nativeValue{c.Before, c.After} {
		n := 0
		if v.Proxy != nil {
			n++
		}
		if v.Route != nil {
			n++
		}
		if v.DNS != nil {
			n++
		}
		if !v.Present {
			if n != 0 {
				return errors.New("absent value carries data")
			}
			continue
		}
		if n != 1 {
			return errors.New("invalid native value union")
		}
		switch c.Kind {
		case "proxy":
			if v.Proxy == nil || v.Proxy.Bool || len(v.Proxy.Strings) != 0 || len(v.Proxy.Text) > 32768 || strings.ContainsRune(v.Proxy.Text, 0) {
				return errors.New("invalid proxy value")
			}
			switch c.Field {
			case "flags":
				if v.Proxy.Text != "" || v.Proxy.Number > 15 {
					return errors.New("invalid proxy flags")
				}
			case "server", "bypass", "pac":
				if v.Proxy.Number != 0 {
					return errors.New("invalid proxy text")
				}
			default:
				return errors.New("unknown proxy field")
			}
		case "dns":
			if v.DNS == nil || c.Scope.Interface.ID == "" || c.Scope.Interface.Index == 0 || (c.Scope.Family != 4 && c.Scope.Family != 6) || len(v.DNS.Servers) > 16 || v.DNS.Automatic && len(v.DNS.Servers) > 0 {
				return errors.New("invalid DNS config")
			}
			for _, a := range v.DNS.Servers {
				if !a.IsValid() || a.Is4In6() || a.Is4() != (c.Scope.Family == 4) {
					return errors.New("DNS family mismatch")
				}
			}
		case "route":
			r := v.Route
			if r == nil || !r.Destination.IsValid() || r.Destination != r.Destination.Masked() || r.Interface.ID == "" || r.Interface.Index == 0 || !reflect.DeepEqual(r.Interface, c.Scope.Interface) || !r.Gateway.IsValid() || r.Gateway.Is4() != r.Destination.Addr().Is4() {
				return errors.New("invalid route identity")
			}
		default:
			return errors.New("unknown native change kind")
		}
	}
	if c.Kind == "route" && c.Before.Present && c.After.Present {
		a, b := c.Before.Route, c.After.Route
		if a.Destination != b.Destination || a.Gateway != b.Gateway || !reflect.DeepEqual(a.Interface, b.Interface) {
			return errors.New("route key changed")
		}
	}
	return nil
}
func winNativeProxyServer(previous string, endpoint netip.AddrPort) (string, error) {
	if !endpoint.IsValid() || !endpoint.Addr().IsLoopback() || endpoint.Port() == 0 {
		return "", errors.New("proxy listener must be loopback")
	}
	kept := []string{}
	for _, part := range strings.Split(previous, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, _, ok := strings.Cut(part, "=")
		if !ok {
			return "", errors.New("unqualified proxy server is ambiguous")
		}
		switch strings.ToLower(k) {
		case "http", "https":
		default:
			kept = append(kept, part)
		}
	}
	kept = append(kept, "http="+endpoint.String(), "https="+endpoint.String())
	return strings.Join(kept, ";"), nil
}
func winNativePlan(s nativeSnapshot, p nativeInterceptionPlan) ([]nativeChange, error) {
	out := []nativeChange{}
	if p.TUN && (len(p.CapturePrefixes) == 0 || len(p.CapturePrefixes) > nativeMaxCapturePrefixes || len(p.ExclusionRoutes) > 256 || len(p.DNSServers) == 0 || len(p.DNSServers) > 2) {
		return nil, errors.New("invalid native TUN plan bounds")
	}
	dnsCount := 0

	if p.SystemProxy {
		fields := map[string]bool{}
		for _, c := range s.Settings {
			if c.Kind == "proxy" {
				if fields[c.Field] {
					return nil, errors.New("duplicate proxy baseline")
				}
				fields[c.Field] = true
			}
		}
		for _, f := range []string{"flags", "server", "bypass", "pac"} {
			if !fields[f] {
				return nil, errors.New("incomplete proxy baseline")
			}
		}
	}

	for _, c := range s.Settings {
		c.After = c.Before
		if c.Kind == "proxy" && p.SystemProxy {
			v := nativeProxyValue{}
			if c.Before.Present {
				if c.Before.Proxy == nil {
					return nil, errors.New("invalid proxy baseline")
				}
				v = *c.Before.Proxy
			}
			switch c.Field {
			case "flags":
				v.Number = (v.Number &^ uint32(12)) | 3
			case "server":
				var err error
				v.Text, err = winNativeProxyServer(v.Text, p.ProxyEndpoint)
				if err != nil {
					return nil, err
				}
			case "pac":
				v.Text = ""
			case "bypass":
				v.Text = "localhost;127.0.0.1;[::1]"
			default:
				return nil, errors.New("unknown proxy baseline")
			}
			c.After = nativeValue{Present: true, Proxy: &v}
		} else if c.Kind == "dns" && p.TUN {
			dnsCount++
			servers := []netip.Addr{}
			for _, a := range p.DNSServers {
				if !a.IsLoopback() {
					return nil, errors.New("owned DNS must be loopback")
				}
				if a.Is4() == (c.Scope.Family == 4) {
					servers = append(servers, a)
				}
			}
			if len(servers) == 0 {
				return nil, errors.New("owned DNS family missing")
			}
			c.After = nativeValue{Present: true, DNS: &nativeDNSConfig{Servers: servers}}
		} else {
			continue
		}
		if err := winNativeValidate(c); err != nil {
			return nil, err
		}
		if !winNativeEqual(c.Before, c.After) {
			out = append(out, c)
		}
	}
	if p.TUN {
		if dnsCount == 0 {
			return nil, errors.New("no eligible DNS interface")
		}
		if p.TUNInterface.ID == "" || p.TUNInterface.Kind != "tunnel" {
			return nil, errors.New("owned TUN identity missing")
		}
		routes := append([]nativeRoute{}, p.ExclusionRoutes...)
		for _, prefix := range p.CapturePrefixes {
			gateway := netip.IPv6Unspecified()
			if prefix.Addr().Is4() {
				gateway = netip.IPv4Unspecified()
			}
			routes = append(routes, nativeRoute{Destination: prefix, Gateway: gateway, Interface: p.TUNInterface, Metric: 1, Flags: 0x08000003})
		}
		for _, r := range routes {
			c := nativeChange{ID: fmt.Sprintf("route/%s/%s/%s", r.Interface.ID, r.Destination, r.Gateway), Kind: "route", Scope: nativeScope{Interface: r.Interface}, After: nativeValue{Present: true, Route: &r}}
			for _, old := range s.Routes {
				if old.Destination == r.Destination && old.Interface.ID == r.Interface.ID && old.Gateway == r.Gateway {
					o := old
					c.Before = nativeValue{Present: true, Route: &o}
				}
			}
			if err := winNativeValidate(c); err != nil {
				return nil, err
			}
			if !winNativeEqual(c.Before, c.After) {
				out = append(out, c)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Field != "flags" && out[j].Field == "flags"
	})
	return out, nil
}

// Shared value engine is executable without OS setters in deterministic tests.
func winNativeCompare(ctx context.Context, s nativeSession, c nativeChange, restore bool, read func() (nativeValue, error), write func(nativeValue, nativeValue) error) (nativeReceipt, error) {
	r := nativeReceipt{ChangeID: c.ID, Outcome: "not_applied"}
	if err := winNativeValidate(c); err != nil {
		return r, err
	}
	if s == nil {
		return r, errors.New("missing native session")
	}
	if err := s.Validate(ctx, restore); err != nil {
		return r, err
	}
	before, after := c.Before, c.After
	if restore {
		before, after = after, before
	}
	current, err := read()
	r.Current = current
	if err != nil {
		return r, err
	}
	if !winNativeEqual(current, before) {
		r.Outcome = "conflict"
		return r, errors.New("native setting changed externally")
	}
	if err := s.Validate(ctx, restore); err != nil {
		return r, err
	}
	r.Outcome = "unknown"
	if err := write(before, after); err != nil {
		return r, err
	}
	if err := s.Validate(ctx, restore); err != nil {
		return r, err
	}
	current, err = read()
	r.Current = current
	if err != nil {
		return r, err
	}
	if !winNativeEqual(current, after) {
		return r, errors.New("native write readback differs")
	}
	r.Outcome = "applied"
	return r, nil
}

func winNativeSelectExit(ctx context.Context, d netip.Addr, s nativeSnapshot, wg TunnelReadback, check func(nativeInterface) error, best func(nativeInterface, netip.Addr) (nativeRoute, netip.Addr, error)) (nativeExit, error) {
	if err := ctx.Err(); err != nil {
		return nativeExit{}, err
	}
	var candidates []nativeExit
	authorizedWG := false
	for _, raw := range wg.Routes {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nativeExit{}, err
		}
		if prefix.Contains(d) {
			authorizedWG = true
		}
	}
	for _, i := range s.Interfaces {
		isWG := i.Name == endpointInterfaceName
		if authorizedWG {
			if !isWG || wg.PublicKey == "" {
				continue
			}
			if len(i.Addresses) != len(wg.Addresses) {
				continue
			}
			matched := true
			for _, a := range wg.Addresses {
				v, err := netip.ParsePrefix(a)
				if err != nil || !containsNativePrefix(i.Addresses, v) {
					matched = false
				}
			}
			if !matched {
				continue
			}
		} else if i.Kind != "physical" {
			continue
		}
		if err := check(i); err != nil {
			return nativeExit{}, err
		}
		route, source, err := best(i, d)
		if err != nil {
			continue
		}
		if authorizedWG {
			found := false
			for _, r := range s.Routes {
				if r.Interface.ID == i.ID && r.Destination.Contains(d) && reflect.DeepEqual(r, route) {
					for _, raw := range wg.Routes {
						if r.Destination.String() == raw {
							allowed := false
							for _, p := range wg.Peer.AllowedIPs {
								if p == raw {
									allowed = true
								}
							}
							if !allowed {
								continue
							}
							found = true
						}
					}
				}
			}
			if !found {
				continue
			}
		}
		candidates = append(candidates, nativeExit{Generation: s.Generation, Interface: i, Source: source, Gateway: route.Gateway, Route: route, ViaWG: authorizedWG})
	}
	if len(candidates) != 1 {
		return nativeExit{}, errors.New("native egress is unavailable or ambiguous")
	}
	return candidates[0], nil
}
func containsNativePrefix(a []netip.Prefix, b netip.Prefix) bool {
	for _, v := range a {
		if v == b {
			return true
		}
	}
	return false
}

func winNativeGuardControl(exit nativeExit, target netip.AddrPort, raw syscall.RawConn, check func(nativeInterface) error, best func(nativeInterface, netip.Addr) (nativeRoute, netip.Addr, error), bind func(uintptr) error) error {
	if !target.IsValid() || raw == nil {
		return errors.New("invalid native socket target")
	}
	if err := check(exit.Interface); err != nil {
		return err
	}
	verify := func() error {
		route, source, err := best(exit.Interface, target.Addr())
		if err != nil {
			return err
		}
		if source != exit.Source || !reflect.DeepEqual(route, exit.Route) {
			return errors.New("native route or source changed")
		}
		return nil
	}
	if err := verify(); err != nil {
		return err
	}
	var inner error
	if err := raw.Control(func(fd uintptr) { inner = bind(fd) }); err != nil {
		return err
	}
	if inner != nil {
		return inner
	}
	if err := check(exit.Interface); err != nil {
		return err
	}
	return verify()
}

type winNativeListener struct {
	Endpoint netip.AddrPort
	PID      uint32
}

func winNativeListenerOwned(listeners []winNativeListener, endpoint netip.AddrPort, pid uint32) error {
	if !endpoint.IsValid() || !endpoint.Addr().IsLoopback() || endpoint.Port() == 0 || pid == 0 {
		return errors.New("invalid owned loopback listener")
	}
	found := false
	for _, l := range listeners {
		if l.Endpoint.Port() != endpoint.Port() || l.Endpoint.Addr().Is4() != endpoint.Addr().Is4() {
			continue
		}
		if l.Endpoint.Addr().IsUnspecified() {
			return errors.New("wildcard listener conflicts with private loopback")
		}
		if l.Endpoint == endpoint {
			if l.PID != pid {
				return errors.New("loopback listener belongs to another process")
			}
			found = true
		}
	}
	if !found {
		return errors.New("owned loopback listener not found")
	}
	return nil
}

func winNativeParseListeners(buf []byte, tcp, ipv4 bool) ([]winNativeListener, error) {
	if len(buf) < 4 {
		return nil, errors.New("truncated listener table")
	}
	count := binary.LittleEndian.Uint32(buf)
	stride, portOffset, pidOffset := 28, 20, 24
	if ipv4 {
		stride, portOffset, pidOffset = 12, 4, 8
	}
	if tcp {
		stride, portOffset, pidOffset = 56, 20, 52
		if ipv4 {
			stride, portOffset, pidOffset = 24, 8, 20
		}
	}
	if uint64(count)*uint64(stride) > uint64(len(buf)-4) {
		return nil, errors.New("listener count exceeds buffer")
	}
	out := make([]winNativeListener, 0, count)
	for n := uint32(0); n < count; n++ {
		row := buf[4+int(n)*stride : 4+(int(n)+1)*stride]
		start := 0
		if tcp && ipv4 {
			start = 4
		}
		var addr netip.Addr
		if ipv4 {
			addr = netip.AddrFrom4([4]byte(row[start : start+4]))
		} else {
			addr = netip.AddrFrom16([16]byte(row[:16]))
		}
		port := binary.BigEndian.Uint16(row[portOffset : portOffset+2])
		pid := binary.LittleEndian.Uint32(row[pidOffset : pidOffset+4])
		out = append(out, winNativeListener{Endpoint: netip.AddrPortFrom(addr, port), PID: pid})
	}
	return out, nil
}

func winNativeFlush(ctx context.Context, s nativeSession, run func(context.Context) error) error {
	if s == nil {
		return errors.New("missing native restore session")
	}
	if err := s.Validate(ctx, true); err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return err
	}
	if err := run(bounded); err != nil {
		return errors.New("DNS resolver cache flush did not complete")
	}
	if err := bounded.Err(); err != nil {
		return err
	}
	return s.Validate(ctx, true)
}
