package endpointservice

import (
	"net/netip"
	"testing"
)

func TestDarwinNativePlanValues(t *testing.T) {
	snap := nativeSnapshot{PrimaryServiceID: "service"}
	for _, field := range []string{"HTTPEnable", "HTTPProxy", "HTTPPort", "HTTPSEnable", "HTTPSProxy", "HTTPSPort", "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"} {
		snap.Settings = append(snap.Settings, nativeChange{Kind: "proxy", Field: field, Scope: nativeScope{ServiceID: "service"}})
	}
	snap.Settings = append(snap.Settings, nativeChange{Kind: "dns", Scope: nativeScope{ServiceID: "service"}, Before: nativeValue{DNS: &nativeDNSConfig{Automatic: true}}})
	tun := nativeInterface{ID: "tun-incarnation", Name: "utun9", Index: 9, Kind: "tunnel"}
	plan := nativeInterceptionPlan{SystemProxy: true, TUN: true, ProxyEndpoint: netip.MustParseAddrPort("127.0.0.1:7890"), DNSServers: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, TUNInterface: tun, CapturePrefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("8000::/1")}}
	changes, err := darwinNativePlan(snap, plan, 1)
	if err != nil || len(changes) != 11 {
		t.Fatalf("dual-stack plan: %d %v", len(changes), err)
	}
	for _, c := range changes {
		if c.Kind == "proxy" && c.Field == "ProxyAutoConfigEnable" && c.After.Proxy.Bool {
			t.Fatal("PAC left active")
		}
	}
	plan.DNSServers = []netip.Addr{netip.MustParseAddr("8.8.8.8")}
	if _, err = darwinNativePlan(snap, plan, 1); err == nil {
		t.Fatal("unowned resolver accepted")
	}
	plan.DNSServers = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	plan.TUNInterface.ID = ""
	if _, err = darwinNativePlan(snap, plan, 1); err == nil {
		t.Fatal("unknown TUN identity accepted")
	}
}
func TestDarwinNativeExitValues(t *testing.T) {
	iface := nativeInterface{ID: "physical", Name: "en0", Index: 4, Kind: "physical", Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24"), netip.MustParsePrefix("2001:db8::2/64")}}
	snap := nativeSnapshot{Generation: 4, Routes: []nativeRoute{{Destination: netip.MustParsePrefix("0.0.0.0/0"), Interface: iface, Flags: 1}, {Destination: netip.MustParsePrefix("::/0"), Interface: iface, Flags: 1}}}
	for _, raw := range []string{"198.51.100.1", "2001:db8:1::1"} {
		exit, err := darwinNativeChooseExit(netip.MustParseAddr(raw), snap, TunnelReadback{}, 1, 2)
		if err != nil || exit.Interface.ID != "physical" {
			t.Fatal(err)
		}
	}
	other := snap.Routes[0]
	other.Interface.ID = "other"
	snap.Routes = append(snap.Routes, other)
	if _, err := darwinNativeChooseExit(netip.MustParseAddr("198.51.100.1"), snap, TunnelReadback{}, 1, 2); err == nil {
		t.Fatal("ambiguous physical exit accepted")
	}
	snap.Routes = snap.Routes[:2]
	snap.Routes[0].Interface.Kind = "unknown"
	if _, err := darwinNativeChooseExit(netip.MustParseAddr("198.51.100.1"), snap, TunnelReadback{}, 1, 2); err == nil {
		t.Fatal("unknown VPN classified physical")
	}
}

func TestDarwinNativeWGExitValues(t *testing.T) {
	iface := nativeInterface{ID: "owned-wg", Name: "utun4", Index: 4, Kind: "tunnel", Addresses: []netip.Prefix{netip.MustParsePrefix("10.7.0.2/32")}}
	wg := TunnelReadback{PublicKey: "local", Peer: TunnelPeer{PublicKey: "peer"}, Addresses: []string{"10.7.0.2/32"}, Routes: []string{"10.10.0.0/16"}}
	snapshot := nativeSnapshot{Routes: []nativeRoute{{Destination: netip.MustParsePrefix("10.10.0.0/16"), Interface: iface, Flags: 1}}}
	exit, err := darwinNativeChooseExit(netip.MustParseAddr("10.10.1.1"), snapshot, wg, 1, 2)
	if err != nil || !exit.ViaWG {
		t.Fatalf("WG authorization: %v", err)
	}

	original := snapshot.Routes[0].Destination
	snapshot.Routes[0].Destination = netip.MustParsePrefix("0.0.0.0/0")
	if _, err = darwinNativeChooseExit(netip.MustParseAddr("10.10.1.1"), snapshot, wg, 1, 2); err == nil {
		t.Fatal("WG route outside authorized readback accepted")
	}
	snapshot.Routes[0].Destination = original
	wg.Addresses = []string{"10.7.0.3/32"}
	if _, err = darwinNativeChooseExit(netip.MustParseAddr("10.10.1.1"), snapshot, wg, 1, 2); err == nil {
		t.Fatal("unrelated tunnel accepted")
	}
	wg.Addresses = []string{"10.7.0.2/32"}
	snapshot.Routes[0].Interface.Addresses = nil
	if _, err = darwinNativeChooseExit(netip.MustParseAddr("10.10.1.1"), snapshot, wg, 1, 2); err == nil {
		t.Fatal("missing source family accepted")
	}
}
