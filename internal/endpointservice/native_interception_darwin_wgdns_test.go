//go:build darwin && cgo

package endpointservice

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"testing"
)

type darwinWGFixture struct {
	system       *DarwinSystem
	session      *darwinNativeSession
	current      []string
	writes       int
	metadata     bool
	writeFailure string
}

func newDarwinWGFixture(t *testing.T) *darwinWGFixture {
	t.Helper()
	_, session := nativeDarwinFixture()
	f := &darwinWGFixture{session: session, current: []string{"10.7.0.53"}, metadata: true}
	plan := &TunnelPlan{PublicKey: "public", Peer: TunnelPeer{PublicKey: "peer", Endpoint: "vpn.example.test:51820", AllowedIPs: []string{"10.8.0.0/16"}}, Addresses: []string{"10.7.0.2/32"}, Routes: []string{"10.8.0.0/16"}, DNSServers: []string{"10.7.0.53"}}
	iface := nativeInterface{ID: "original-incarnation", Name: "utun7", Index: 7, Kind: "tunnel", Addresses: []netip.Prefix{netip.MustParsePrefix("10.7.0.2/32")}}
	f.system = &DarwinSystem{name: iface.Name, expected: plan, peerEndpoint: netip.MustParseAddrPort("192.0.2.9:51820")}
	f.system.nativeDNSInterfaces = func() ([]nativeInterface, error) { return []nativeInterface{iface}, nil }
	f.system.nativeDNSAbsent = func(nativeChange) (bool, error) { return false, nil }
	f.system.nativeDNSVerifyEndpoint = func(context.Context, string, netip.AddrPort) bool { return true }
	f.system.nativeDNSReadback = func(ctx context.Context) (TunnelReadback, error) {
		if err := ctx.Err(); err != nil {
			return TunnelReadback{}, err
		}
		state := f.system.expected.Readback()
		state.DNSServers = slices.Clone(f.current)
		return state, nil
	}
	f.system.dns = &darwinDNS{serviceID: "com.opensoha.vpn.fixture", calls: &darwinDNSCalls{read: func() ([]string, error) {
		if !f.metadata {
			return nil, errDarwinWGDNS
		}
		return slices.Clone(f.current), nil
	}, matches: func() bool { return f.metadata }, cas: func(before, after []string) (string, error) {
		f.writes++
		if !slices.Equal(before, f.current) {
			return "conflict", errDarwinWGDNS
		}
		if f.writeFailure != "" {
			if f.writeFailure == "unknown" {
				f.current = slices.Clone(after)
			}
			return f.writeFailure, errors.New("test write acknowledgement failed")
		}
		f.current = slices.Clone(after)
		return "applied", nil
	}}}
	return f
}
func (f *darwinWGFixture) prepare(t *testing.T) nativeChange {
	t.Helper()
	steps, err := f.system.PrepareNativeDNS(context.Background(), f.session, []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()})
	if err != nil || len(steps) != 1 {
		t.Fatalf("prepare: %v", err)
	}
	if f.writes != 0 {
		t.Fatal("prepare wrote DNS")
	}
	return steps[0]
}
func TestDarwinNativeWGDNSActualAfterAndRelease(t *testing.T) {
	f := newDarwinWGFixture(t)
	c := f.prepare(t)
	ctx := context.Background()
	grant := f.system.expected.Readback()
	r, err := f.system.CompareNativeDNS(ctx, f.session, c, false)
	if err != nil || r.Outcome != "applied" {
		t.Fatalf("apply: %s %v", r.Outcome, err)
	}
	v, err := f.system.ReadNativeDNS(ctx, f.session, c)
	if err != nil || !reflect.DeepEqual(v, c.After) {
		t.Fatalf("real After: %v", err)
	}
	actual, _ := f.system.wgNativeReadback(ctx)
	if !slices.Equal(actual.DNSServers, []string{"127.0.0.1", "::1"}) || !darwinWGReadbackMatches(actual, grant, f.system.nativeDNSDelegate) {
		t.Fatal("actual After was hidden")
	}
	if !reflect.DeepEqual(f.system.expected.Readback(), grant) {
		t.Fatal("original grant overwritten")
	}
	if f.system.ReleaseNativeDNS(ctx, f.session, []nativeChange{c}) == nil {
		t.Fatal("released before restoring DNS")
	}
	restore, _ := f.session.platform.AcquireRestoreSession(ctx, f.session.Owner())
	r, err = f.system.CompareNativeDNS(ctx, restore, c, true)
	if err != nil || r.Outcome != "applied" {
		t.Fatalf("restore: %s %v", r.Outcome, err)
	}
	if f.system.nativeDNSDelegate == nil || !f.system.nativeDNSDelegate.restored {
		t.Fatal("restore epoch prematurely lost")
	}
	f.system.nativeDNSVerifyEndpoint = func(context.Context, string, netip.AddrPort) bool { return false }
	if f.system.ReleaseNativeDNS(ctx, restore, []nativeChange{c}) == nil || f.system.nativeDNSDelegate == nil {
		t.Fatal("failed strict hostname validation released epoch")
	}
	if _, err = f.system.CompareNativeDNS(ctx, f.session, c, false); err == nil {
		t.Fatal("cleanup epoch reauthorized apply")
	}
	f.system.nativeDNSVerifyEndpoint = func(context.Context, string, netip.AddrPort) bool { return true }
	if err = f.system.ReleaseNativeDNS(ctx, restore, []nativeChange{c}); err != nil || f.system.nativeDNSDelegate != nil || f.system.peerEndpoint.IsValid() {
		t.Fatalf("release: %v", err)
	}
	if f.writes != 2 {
		t.Fatal("release performed a setter")
	}
}
func TestDarwinNativeWGDNSExternalAndChangedGrant(t *testing.T) {
	for _, which := range []string{"dns", "handle", "interface", "grant", "actualgrant", "metadata"} {
		t.Run(which, func(t *testing.T) {
			f := newDarwinWGFixture(t)
			c := f.prepare(t)
			switch which {
			case "dns":
				f.current = []string{"192.0.2.53"}
			case "handle":
				f.system.dns.serviceID = "com.opensoha.vpn.replaced"
			case "interface":
				f.system.nativeDNSInterfaces = func() ([]nativeInterface, error) {
					return []nativeInterface{{ID: "reused-index", Name: "utun7", Index: 7, Kind: "tunnel"}}, nil
				}
			case "grant":
				f.system.expected.PublicKey = "different"
			case "actualgrant":
				f.system.nativeDNSReadback = func(context.Context) (TunnelReadback, error) {
					state := f.system.expected.Readback()
					state.MTU++
					return state, nil
				}
			case "metadata":
				f.metadata = false
			}
			_, err := f.system.CompareNativeDNS(context.Background(), f.session, c, false)
			if err == nil || f.writes != 0 {
				t.Fatal("changed scope/grant was written")
			}
		})
	}
	f := newDarwinWGFixture(t)
	c := f.prepare(t)
	_, err := f.system.CompareNativeDNS(context.Background(), f.session, c, false)
	if err != nil {
		t.Fatal(err)
	}
	f.current = []string{"192.0.2.53"}
	before := slices.Clone(f.current)
	r, err := f.system.CompareNativeDNS(context.Background(), f.session, c, true)
	if err == nil || r.Outcome != "conflict" || f.writes != 1 || !slices.Equal(f.current, before) {
		t.Fatal("external restore value overwritten")
	}
}
func TestDarwinNativeWGDNSAbsentOnlyRestore(t *testing.T) {
	f := newDarwinWGFixture(t)
	c := f.prepare(t)
	f.system.dns = nil
	f.system.expected = nil
	f.system.nativeDNSInterfaces = func() ([]nativeInterface, error) { return nil, nil }
	f.system.nativeDNSAbsent = func(nativeChange) (bool, error) { return true, nil }
	r, err := f.system.CompareNativeDNS(context.Background(), f.session, c, true)
	if err != nil || r.Outcome != "absent" || f.writes != 0 {
		t.Fatal("proved old disappearance not accepted")
	}
	r, err = f.system.CompareNativeDNS(context.Background(), f.session, c, false)
	if err == nil || r.Outcome == "absent" || f.writes != 0 {
		t.Fatal("absence authorized new apply")
	}
	f.system.nativeDNSAbsent = func(nativeChange) (bool, error) { return false, errors.New("unreadable scope") }
	r, err = f.system.CompareNativeDNS(context.Background(), f.session, c, true)
	if err == nil || r.Outcome == "absent" {
		t.Fatal("unknown disappearance treated as absent")
	}
}
func TestDarwinNativeWGDNSCancelUnknownRestoreOnly(t *testing.T) {
	f := newDarwinWGFixture(t)
	c := f.prepare(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.system.CompareNativeDNS(ctx, f.session, c, false); err == nil || f.writes != 0 {
		t.Fatal("cancelled write executed")
	}
	restore, _ := f.session.platform.AcquireRestoreSession(context.Background(), f.session.Owner())
	if _, err := f.system.CompareNativeDNS(context.Background(), restore, c, false); err == nil || f.writes != 0 {
		t.Fatal("restore-only authorized apply")
	}
	f.writeFailure = "unknown"
	r, err := f.system.CompareNativeDNS(context.Background(), f.session, c, false)
	if err == nil || r.Outcome != "unknown" || f.writes != 1 || f.system.nativeDNSDelegate == nil {
		t.Fatal("unknown receipt or original grant lost")
	}
	f.writeFailure = ""
	r, err = f.system.CompareNativeDNS(context.Background(), restore, c, true)
	if err != nil || r.Outcome != "applied" || f.writes != 2 {
		t.Fatalf("restore unknown write: %v", err)
	}
}
func TestDarwinNativeWGPeerPinScopedToDelegation(t *testing.T) {
	f := newDarwinWGFixture(t)
	ctx := context.Background()
	pin := f.system.peerEndpoint
	lookups := 0
	f.system.nativeDNSVerifyEndpoint = func(context.Context, string, netip.AddrPort) bool { lookups++; return true }
	if !f.system.verifyDarwinPeer(ctx, pin) || lookups != 1 {
		t.Fatal("ordinary hostname check bypassed")
	}
	c := f.prepare(t)
	f.system.nativeDNSDelegate = &darwinWGDNSEpoch{change: c, grant: f.system.expected.Readback(), owner: f.session.Owner()}
	if !f.system.verifyDarwinPeer(ctx, pin) || lookups != 1 {
		t.Fatal("delegation resolved fake DNS")
	}
	if f.system.verifyDarwinPeer(ctx, netip.MustParseAddrPort("192.0.2.10:51820")) {
		t.Fatal("peer drift accepted")
	}
	f.system.expected.PublicKey = "new-grant"
	if f.system.verifyDarwinPeer(ctx, pin) {
		t.Fatal("new grant inherited old pin")
	}
}

func TestDarwinNativeWGDNSAbsenceRequiresInterfaceAndHandle(t *testing.T) {
	f := newDarwinWGFixture(t)
	c := f.prepare(t)
	calls := 0
	f.system.nativeDNSAbsent = func(nativeChange) (bool, error) { calls++; return true, nil }
	absent, err := f.system.wgNativeAbsent(c)
	if err != nil || absent || calls != 0 {
		t.Fatal("missing keys alone proved absence")
	}
	f.system.nativeDNSInterfaces = func() ([]nativeInterface, error) { return nil, nil }
	f.system.nativeDNSAbsent = func(nativeChange) (bool, error) { return false, nil }
	absent, err = f.system.wgNativeAbsent(c)
	if err != nil || absent {
		t.Fatal("missing interface alone proved absence")
	}
	f.system.nativeDNSAbsent = func(nativeChange) (bool, error) { return false, errors.New("store read failed") }
	absent, err = f.system.wgNativeAbsent(c)
	if err == nil || absent {
		t.Fatal("read failure proved absence")
	}
	f.system.nativeDNSAbsent = func(nativeChange) (bool, error) { return true, nil }
	f.system.nativeDNSDelegate = &darwinWGDNSEpoch{change: c, grant: f.system.expected.Readback(), owner: f.session.Owner()}
	f.system.expected = nil
	f.system.dns = nil
	if err = f.system.ReleaseNativeDNS(context.Background(), f.session, []nativeChange{c}); err != nil || f.system.nativeDNSDelegate != nil {
		t.Fatalf("proved whole old scope absence did not clear old epoch: %v", err)
	}
}
