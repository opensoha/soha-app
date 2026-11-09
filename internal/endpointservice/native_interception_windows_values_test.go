package endpointservice

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

type winNativeTestSession struct {
	restoreOnly, denied bool
	calls               int
	failAt              int
}

func (s *winNativeTestSession) Owner() nativeOwner {
	return nativeOwner{UserID: "original", SessionID: "1"}
}
func (s *winNativeTestSession) Close() error { return nil }
func (s *winNativeTestSession) Validate(ctx context.Context, restore bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.calls++
	if s.denied || s.restoreOnly && !restore || s.calls == s.failAt {
		return errors.New("session changed")
	}
	return nil
}
func TestWinNativeCompareOwnership(t *testing.T) {
	old := nativeValue{Present: true, Proxy: &nativeProxyValue{Text: "original"}}
	written := nativeValue{Present: true, Proxy: &nativeProxyValue{Text: "owned"}}
	external := nativeValue{Present: true, Proxy: &nativeProxyValue{Text: "external"}}
	change := nativeChange{ID: "proxy/server", Kind: "proxy", Field: "server", Before: old, After: written}
	for _, tt := range []struct {
		name    string
		session winNativeTestSession
		restore bool
		current nativeValue
		want    string
		writes  int
	}{
		{"apply", winNativeTestSession{}, false, old, "applied", 1},
		{"false peer", winNativeTestSession{denied: true}, false, old, "not_applied", 0},
		{"restore-only enable", winNativeTestSession{restoreOnly: true}, false, old, "not_applied", 0},
		{"restore original SID", winNativeTestSession{restoreOnly: true}, true, written, "applied", 1},
		{"external field", winNativeTestSession{}, true, external, "conflict", 0},
		{"switch before write", winNativeTestSession{failAt: 2}, false, old, "not_applied", 0},
		{"switch after write", winNativeTestSession{failAt: 3}, false, old, "unknown", 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			writes := 0
			current := tt.current
			r, _ := winNativeCompare(context.Background(), &tt.session, change, tt.restore, func() (nativeValue, error) { return current, nil }, func(_, after nativeValue) error { writes++; current = after; return nil })
			if r.Outcome != tt.want || writes != tt.writes {
				t.Fatalf("receipt=%s writes=%d", r.Outcome, writes)
			}
		})
	}
	writes := 0
	r, err := winNativeCompare(context.Background(), &winNativeTestSession{}, change, false, func() (nativeValue, error) { return old, nil }, func(_, after nativeValue) error { writes++; return errors.New("unknown OS result") })
	if err == nil || r.Outcome != "unknown" || writes != 1 {
		t.Fatal("unknown write was retried or misreported")
	}
}
func TestWinNativePlanAndValidation(t *testing.T) {
	settings := []nativeChange{}
	for _, field := range []string{"flags", "server", "pac", "bypass"} {
		v := &nativeProxyValue{}
		if field == "flags" {
			v.Number = 13
		}
		if field == "server" {
			v.Text = "socks=old:1080;http=old:80"
		}
		settings = append(settings, nativeChange{ID: field, Kind: "proxy", Field: field, Before: nativeValue{Present: true, Proxy: v}})
	}
	plan := nativeInterceptionPlan{SystemProxy: true, ProxyEndpoint: netip.MustParseAddrPort("127.0.0.1:7890")}
	changes, err := winNativePlan(nativeSnapshot{Settings: settings}, plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range changes {
		if c.Field == "bypass" && strings.Contains(c.After.Proxy.Text, "<local>") {
			t.Fatal("non-loopback local names bypassed proxy")
		}
		if c.Field == "server" && !strings.Contains(c.After.Proxy.Text, "socks=old:1080") {
			t.Fatal("unrelated proxy scheme lost")
		}
		if c.Field == "flags" && c.After.Proxy.Number != 3 {
			t.Fatal("PAC/autodiscovery remained active")
		}
	}
	plan.ProxyEndpoint = netip.MustParseAddrPort("192.0.2.1:7890")
	if _, err := winNativePlan(nativeSnapshot{Settings: settings}, plan); err == nil {
		t.Fatal("external listener accepted")
	}
	i := nativeInterface{ID: "GUID", Index: 4, Kind: "physical"}
	dns := nativeChange{ID: "dns", Kind: "dns", Scope: nativeScope{Interface: i, Family: 4}, Before: nativeValue{Present: true, DNS: &nativeDNSConfig{Automatic: true}}, After: nativeValue{Present: true, DNS: &nativeDNSConfig{Servers: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}}}
	if err := winNativeValidate(dns); err != nil {
		t.Fatal(err)
	}
	if winNativeEqual(dns.Before, dns.After) {
		t.Fatal("automatic and manual DNS conflated")
	}
	if winNativeEqual(nativeValue{}, nativeValue{Present: true, DNS: &nativeDNSConfig{}}) {
		t.Fatal("absent conflated with empty")
	}
	route := nativeRoute{Destination: netip.MustParsePrefix("0.0.0.0/1"), Gateway: netip.IPv4Unspecified(), Interface: i, Metric: 1, Flags: 3}
	before := nativeValue{Present: true, Route: &route}
	changed := route
	changed.Metric++
	if winNativeEqual(before, nativeValue{Present: true, Route: &changed}) {
		t.Fatal("route metric ignored")
	}
	changed = route
	changed.Interface.ID = "reused index"
	if winNativeEqual(before, nativeValue{Present: true, Route: &changed}) {
		t.Fatal("GUID ignored")
	}
	c := nativeChange{ID: "route", Kind: "route", Scope: nativeScope{Interface: i}, Before: before, After: nativeValue{Present: true, Route: &changed}}
	if winNativeValidate(c) == nil {
		t.Fatal("changed route identity accepted")
	}
	for _, field := range []string{"registryPath", "command", ""} {
		c := nativeChange{ID: "bad", Kind: "proxy", Field: field, Before: nativeValue{Present: true, Proxy: &nativeProxyValue{}}}
		if winNativeValidate(c) == nil {
			t.Fatalf("unrecognized field %s", field)
		}
	}
}

func TestWinNativeSelectExit(t *testing.T) {
	physical := nativeInterface{ID: "physical-GUID", Name: "Ethernet", Index: 4, Kind: "physical", Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")}}
	other := physical
	other.ID = "other-GUID"
	other.Index = 5
	tun := nativeInterface{ID: "owned-tun", Name: "soha-native", Index: 8, Kind: "tunnel"}
	d := netip.MustParseAddr("203.0.113.5")
	s := nativeSnapshot{Generation: 1, Interfaces: []nativeInterface{physical, tun}}
	check := func(nativeInterface) error { return nil }
	best := func(i nativeInterface, _ netip.Addr) (nativeRoute, netip.Addr, error) {
		if i.Kind != "physical" {
			t.Fatal("owned TUN selected")
		}
		return nativeRoute{Interface: i, Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.0.2.1")}, i.Addresses[0].Addr(), nil
	}
	if exit, err := winNativeSelectExit(context.Background(), d, s, TunnelReadback{}, check, best); err != nil || exit.Interface.ID != physical.ID {
		t.Fatal("physical selection failed", err)
	}
	s.Interfaces = append(s.Interfaces, other)
	if _, err := winNativeSelectExit(context.Background(), d, s, TunnelReadback{}, check, best); err == nil {
		t.Fatal("multiple exits accepted")
	}
	s.Interfaces = []nativeInterface{physical, tun}
	if _, err := winNativeSelectExit(context.Background(), d, s, TunnelReadback{}, func(nativeInterface) error { return errors.New("reused index") }, best); err == nil {
		t.Fatal("changed GUID accepted")
	}
	if _, err := winNativeSelectExit(context.Background(), d, s, TunnelReadback{}, check, func(nativeInterface, netip.Addr) (nativeRoute, netip.Addr, error) {
		return nativeRoute{}, netip.Addr{}, errors.New("GetBestRoute2 failed")
	}); err == nil {
		t.Fatal("route failure fell back")
	}
	wg := TunnelReadback{PublicKey: "verified", Routes: []string{"203.0.113.0/24"}}
	if _, err := winNativeSelectExit(context.Background(), d, s, wg, check, best); err == nil {
		t.Fatal("WG authorized route fell back to physical")
	}
}

func TestWinNativeTUNPlan(t *testing.T) {
	physical := nativeInterface{ID: "physical", Index: 4, Kind: "physical"}
	tun := nativeInterface{ID: "owned", Index: 8, Kind: "tunnel"}
	s := nativeSnapshot{Settings: []nativeChange{{ID: "dns", Kind: "dns", Scope: nativeScope{Interface: physical, Family: 4}, Before: nativeValue{Present: true, DNS: &nativeDNSConfig{Automatic: true}}}}}
	p := nativeInterceptionPlan{TUN: true, TUNInterface: tun, DNSServers: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, CapturePrefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}}
	changes, err := winNativePlan(s, p)
	if err != nil || len(changes) != 3 {
		t.Fatal("TUN plan incomplete", err, len(changes))
	}
	for _, c := range changes {
		if c.Kind == "route" && (c.Before.Present || c.After.Route.Interface.ID != tun.ID) {
			t.Fatal("capture route scope differs")
		}
	}
	p.DNSServers = []netip.Addr{netip.MustParseAddr("8.8.8.8")}
	if _, err := winNativePlan(s, p); err == nil {
		t.Fatal("unowned DNS accepted")
	}
	p.DNSServers = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	if _, err := winNativePlan(nativeSnapshot{}, p); err == nil {
		t.Fatal("missing DNS baseline accepted")
	}
}

type winNativeTestRaw struct{ err error }

func (r winNativeTestRaw) Control(fn func(uintptr)) error {
	if r.err != nil {
		return r.err
	}
	fn(1)
	return nil
}
func (r winNativeTestRaw) Read(func(uintptr) bool) error  { return errors.New("unexpected read") }
func (r winNativeTestRaw) Write(func(uintptr) bool) error { return errors.New("unexpected write") }
func TestWinNativeControlFailures(t *testing.T) {
	i := nativeInterface{ID: "GUID", Index: 4, Kind: "physical"}
	route := nativeRoute{Interface: i, Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.0.2.1"), Metric: 1}
	source := netip.MustParseAddr("192.0.2.2")
	exit := nativeExit{Interface: i, Source: source, Route: route}
	target := netip.MustParseAddrPort("203.0.113.1:443")
	check := func(nativeInterface) error { return nil }
	best := func(nativeInterface, netip.Addr) (nativeRoute, netip.Addr, error) { return route, source, nil }
	binds := 0
	bind := func(uintptr) error { binds++; return nil }
	if err := winNativeGuardControl(exit, target, winNativeTestRaw{}, check, best, bind); err != nil || binds != 1 {
		t.Fatal("guard failed", err)
	}
	if err := winNativeGuardControl(exit, target, winNativeTestRaw{err: errors.New("raw control failed")}, check, best, bind); err == nil {
		t.Fatal("raw failure ignored")
	}
	if err := winNativeGuardControl(exit, target, winNativeTestRaw{}, check, best, func(uintptr) error { return errors.New("IP_UNICAST_IF failed") }); err == nil {
		t.Fatal("setsockopt failure ignored")
	}
	bad := route
	bad.Metric++
	if err := winNativeGuardControl(exit, target, winNativeTestRaw{}, check, func(nativeInterface, netip.Addr) (nativeRoute, netip.Addr, error) { return bad, source, nil }, bind); err == nil {
		t.Fatal("changed route metric accepted")
	}
	count := 0
	if err := winNativeGuardControl(exit, target, winNativeTestRaw{}, check, func(nativeInterface, netip.Addr) (nativeRoute, netip.Addr, error) {
		count++
		if count > 1 {
			return bad, source, nil
		}
		return route, source, nil
	}, bind); err == nil {
		t.Fatal("post-bind change ignored")
	}
}

func TestWinNativeListenerOwnership(t *testing.T) {
	endpoint := netip.MustParseAddrPort("127.0.0.1:53")
	own := winNativeListener{Endpoint: endpoint, PID: 42}
	if err := winNativeListenerOwned([]winNativeListener{own}, endpoint, 42); err != nil {
		t.Fatal(err)
	}
	other := own
	other.PID = 43
	if winNativeListenerOwned([]winNativeListener{own, other}, endpoint, 42) == nil {
		t.Fatal("conflicting PID accepted")
	}
	wildcard := own
	wildcard.Endpoint = netip.MustParseAddrPort("0.0.0.0:53")
	if winNativeListenerOwned([]winNativeListener{wildcard}, endpoint, 42) == nil {
		t.Fatal("wildcard LAN listener accepted")
	}
	if winNativeListenerOwned(nil, endpoint, 42) == nil {
		t.Fatal("missing listener accepted")
	}
	for _, tc := range []struct {
		tcp, ipv4              bool
		size, port, pid, start int
	}{{false, true, 12, 4, 8, 0}, {true, true, 24, 8, 20, 4}, {false, false, 28, 20, 24, 0}, {true, false, 56, 20, 52, 0}} {
		buf := make([]byte, 4+tc.size)
		binary.LittleEndian.PutUint32(buf, 1)
		row := buf[4:]
		if tc.ipv4 {
			copy(row[tc.start:], []byte{127, 0, 0, 1})
		} else {
			row[15] = 1
		}
		binary.BigEndian.PutUint16(row[tc.port:], 53)
		binary.LittleEndian.PutUint32(row[tc.pid:], 42)
		records, err := winNativeParseListeners(buf, tc.tcp, tc.ipv4)
		if err != nil || len(records) != 1 || records[0].PID != 42 || records[0].Endpoint.Port() != 53 {
			t.Fatal("native owner table decode failed", err)
		}
		if _, err := winNativeParseListeners(buf[:len(buf)-1], tc.tcp, tc.ipv4); err == nil {
			t.Fatal("truncated table accepted")
		}
	}
}

func TestWinNativeVerifiedWGExit(t *testing.T) {
	i := nativeInterface{ID: "WG-GUID", Name: endpointInterfaceName, Index: 9, Kind: "tunnel", Addresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}}
	route := nativeRoute{Destination: netip.MustParsePrefix("10.20.0.0/16"), Gateway: netip.IPv4Unspecified(), Interface: i, Metric: 1, Flags: 3}
	s := nativeSnapshot{Generation: 7, Interfaces: []nativeInterface{i}, Routes: []nativeRoute{route}}
	wg := TunnelReadback{PublicKey: "verified-readback", Addresses: []string{"10.0.0.2/32"}, Routes: []string{"10.20.0.0/16"}, Peer: TunnelPeer{AllowedIPs: []string{"10.20.0.0/16"}}}
	best := func(nativeInterface, netip.Addr) (nativeRoute, netip.Addr, error) {
		return route, netip.MustParseAddr("10.0.0.2"), nil
	}
	check := func(nativeInterface) error { return nil }
	exit, err := winNativeSelectExit(context.Background(), netip.MustParseAddr("10.20.1.1"), s, wg, check, best)
	if err != nil || !exit.ViaWG || exit.Route.Metric != route.Metric {
		t.Fatal("verified WG was not selected", err)
	}
	changed := route
	changed.Metric++
	if _, err := winNativeSelectExit(context.Background(), netip.MustParseAddr("10.20.1.1"), s, wg, check, func(nativeInterface, netip.Addr) (nativeRoute, netip.Addr, error) {
		return changed, netip.MustParseAddr("10.0.0.2"), nil
	}); err == nil {
		t.Fatal("actual route mismatch accepted")
	}
	wg.Peer.AllowedIPs = nil
	if _, err := winNativeSelectExit(context.Background(), netip.MustParseAddr("10.20.1.1"), s, wg, check, best); err == nil {
		t.Fatal("WG peer authorization mismatch accepted")
	}
}
