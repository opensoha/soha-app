package endpointservice

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
)

type winWGFixture struct {
	state         winNativeWGState
	session       winNativeTestSession
	expected, raw TunnelReadback
	iface         nativeInterface
	dns           map[uint8]nativeValue
	writes        int
	exists        bool
	writeErr      error
	applyOnError  bool
	lastPin       string
}

func newWinWGFixture() *winWGFixture {
	f := &winWGFixture{exists: true, dns: map[uint8]nativeValue{4: {Present: true, DNS: &nativeDNSConfig{Servers: []netip.Addr{netip.MustParseAddr("10.0.0.53")}}}, 6: {}}}
	f.iface = nativeInterface{ID: "WG-GUID", Index: 9, Name: endpointInterfaceName, Kind: "tunnel", Addresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}}
	f.raw = TunnelReadback{PublicKey: "own-public", Addresses: []string{"10.0.0.2/32"}, MTU: 1420, Peer: TunnelPeer{PublicKey: "peer-public", Endpoint: "203.0.113.1:51820", AllowedIPs: []string{"10.0.0.0/8"}}, Routes: []string{"10.0.0.0/8"}, DNSServers: []string{"10.0.0.53"}}
	f.expected = f.raw
	f.expected.Peer.Endpoint = "vpn.example.test:51820"
	return f
}
func (f *winWGFixture) ops() winNativeWGOps {
	return winNativeWGOps{read: func(ctx context.Context, pin string) (TunnelReadback, nativeInterface, error) {
		f.lastPin = pin
		raw := f.raw
		raw.DNSServers = nil
		for _, family := range []uint8{4, 6} {
			v := f.dns[family]
			if v.DNS != nil {
				for _, a := range v.DNS.Servers {
					raw.DNSServers = append(raw.DNSServers, a.String())
				}
			}
		}
		slices.Sort(raw.DNSServers)
		return raw, f.iface, ctx.Err()
	}, exists: func(nativeInterface) (bool, error) { return f.exists, nil }, dns: func(s nativeScope) (nativeValue, error) { return f.dns[s.Family], nil }, write: func(s nativeScope, v nativeValue) error {
		f.writes++
		if f.writeErr == nil || f.applyOnError {
			f.dns[s.Family] = v
		}
		return f.writeErr
	}}
}
func (f *winWGFixture) prepare(t *testing.T) []nativeChange {
	t.Helper()
	steps, err := f.state.prepare(context.Background(), &f.session, f.expected, []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}, f.ops())
	if err != nil {
		t.Fatal(err)
	}
	if f.writes != 0 || len(steps) != 2 || steps[1].Before.Present {
		t.Fatal("prepare changed DNS or lost original absence")
	}
	return steps
}
func TestWinNativeWGDNSLifecycle(t *testing.T) {
	f := newWinWGFixture()
	steps := f.prepare(t)
	for _, c := range steps {
		r, err := f.state.compare(context.Background(), &f.session, c, false, f.expected, f.ops())
		if err != nil || r.Outcome != "applied" {
			t.Fatal(r, err)
		}
	}
	value, err := f.state.read(context.Background(), &f.session, steps[0], f.ops())
	if err != nil || !winNativeEqual(value, steps[0].After) {
		t.Fatal("real After not read", err)
	}
	pin, wanted, err := f.state.readbackPlan(f.expected)
	if err != nil || pin != f.raw.Peer.Endpoint || !reflect.DeepEqual(wanted.DNSServers, []string{"127.0.0.1", "::1"}) {
		t.Fatal("actual delegated DNS expectation differs", wanted, err)
	}
	f.session.restoreOnly = true
	for n := len(steps) - 1; n >= 0; n-- {
		r, err := f.state.compare(context.Background(), &f.session, steps[n], true, TunnelReadback{}, f.ops())
		if err != nil || r.Outcome != "applied" {
			t.Fatal(r, err)
		}
	}
	pin, _, err = f.state.readbackPlan(f.expected)
	if err != nil || pin == "" {
		t.Fatal("pin dropped before cache/release")
	}
	calls := 0
	if err := f.state.release(context.Background(), &f.session, steps, f.ops(), func(_ context.Context, p winNativeWGProof) error {
		calls++
		if p.DeclaredEndpoint != f.expected.Peer.Endpoint {
			return errors.New("wrong hostname")
		}
		return nil
	}); err != nil || calls != 1 {
		t.Fatal("release failed", err)
	}
	pin, _, _ = f.state.readbackPlan(f.expected)
	if pin != "" {
		t.Fatal("numeric peer exemption retained after release")
	}
	if f.writes != 4 {
		t.Fatal("release introduced setter")
	}
}
func TestWinNativeWGDNSCounterexamples(t *testing.T) {
	for _, name := range []string{"external DNS", "different grant", "reused index", "restore-only enable", "invalidated"} {
		t.Run(name, func(t *testing.T) {
			f := newWinWGFixture()
			c := f.prepare(t)[0]
			switch name {
			case "external DNS":
				f.dns[4] = nativeValue{Present: true, DNS: &nativeDNSConfig{Servers: []netip.Addr{netip.MustParseAddr("10.0.0.99")}}}
			case "different grant":
				f.raw.Peer.PublicKey = "another-peer"
			case "reused index":
				f.iface.ID = "replacement-guid"
			case "restore-only enable":
				f.session.restoreOnly = true
			case "invalidated":
				f.state.invalidate()
			}
			if r, err := f.state.compare(context.Background(), &f.session, c, false, f.expected, f.ops()); err == nil || r.Outcome == "applied" || f.writes != 0 {
				t.Fatal("counterexample accepted", r, err)
			}
		})
	}
	f := newWinWGFixture()
	c := f.prepare(t)[0]
	f.exists = false
	r, err := f.state.compare(context.Background(), &f.session, c, true, TunnelReadback{}, f.ops())
	if err != nil || r.Outcome != "absent" || f.writes != 0 {
		t.Fatal("proven missing GUID was not absent", r, err)
	}
	f = newWinWGFixture()
	steps := f.prepare(t)
	if err := f.state.release(context.Background(), &f.session, steps, f.ops(), func(context.Context, winNativeWGProof) error { return errors.New("hostname drift") }); err == nil {
		t.Fatal("hostname validation skipped")
	}
	if f.state.binding == nil || !f.state.binding.closing || f.writes != 0 {
		t.Fatal("failed release discarded epoch")
	}
	if _, err := f.state.compare(context.Background(), &f.session, steps[0], false, f.expected, f.ops()); err == nil {
		t.Fatal("release failure authorized reapply")
	}
}
func TestWinNativeWGDNSUnknownAndRestart(t *testing.T) {
	f := newWinWGFixture()
	steps := f.prepare(t)
	f.writeErr = errors.New("unknown setter result")
	f.applyOnError = true
	r, err := f.state.compare(context.Background(), &f.session, steps[0], false, f.expected, f.ops())
	if err == nil || r.Outcome != "unknown" || f.writes != 1 {
		t.Fatal("unknown setter replayed", r, err)
	}
	f.writeErr = nil
	restarted := &winNativeWGState{}
	f.session.restoreOnly = true
	r, err = restarted.compare(context.Background(), &f.session, steps[0], true, TunnelReadback{}, f.ops())
	if err != nil || r.Outcome != "applied" || f.writes != 2 {
		t.Fatal("restart original grant recovery failed", r, err)
	}
	r, err = restarted.compare(context.Background(), &f.session, steps[0], true, TunnelReadback{}, f.ops())
	if err != nil || r.Outcome != "applied" || f.writes != 2 {
		t.Fatal("restored setter was replayed", r, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := restarted.compare(ctx, &f.session, steps[1], true, TunnelReadback{}, f.ops()); err == nil || f.writes != 2 {
		t.Fatal("cancelled restore wrote DNS")
	}
}
func TestWinNativeCacheFlush(t *testing.T) {
	for _, name := range []string{"success", "runner error", "timeout", "session rejected", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s := &winNativeTestSession{restoreOnly: true}
			calls := 0
			if name == "session rejected" {
				s.denied = true
			}
			if name == "cancelled" {
				cancel()
			}
			err := winNativeFlush(ctx, s, func(bounded context.Context) error {
				calls++
				if _, ok := bounded.Deadline(); !ok {
					t.Fatal("flush lacks bound")
				}
				if name == "runner error" {
					return errors.New("non-sensitive failure")
				}
				if name == "timeout" {
					return context.DeadlineExceeded
				}
				return nil
			})
			if (err == nil) != (name == "success") {
				t.Fatal("wrong flush result", err)
			}
			expectedCalls := 1
			if name == "session rejected" || name == "cancelled" {
				expectedCalls = 0
			}
			if calls != expectedCalls {
				t.Fatal("flush replayed")
			}
		})
	}
}

func TestWinNativeWGDNSOriginalRepresentations(t *testing.T) {
	for _, kind := range []string{"absent", "automatic", "manual"} {
		t.Run(kind, func(t *testing.T) {
			f := newWinWGFixture()
			switch kind {
			case "automatic":
				f.dns[6] = nativeValue{Present: true, DNS: &nativeDNSConfig{Automatic: true}}
			case "manual":
				a := netip.MustParseAddr("fd00::53")
				f.dns[6] = nativeValue{Present: true, DNS: &nativeDNSConfig{Servers: []netip.Addr{a}}}
				f.expected.DNSServers = append(slices.Clone(f.expected.DNSServers), a.String())
			}
			steps, err := f.state.prepare(context.Background(), &f.session, f.expected, []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}, f.ops())
			if err != nil {
				t.Fatal(err)
			}
			before := f.dns[6]
			if !winNativeEqual(steps[1].Before, before) {
				t.Fatal("original NameServer representation lost")
			}
			for _, c := range steps {
				if _, err := f.state.compare(context.Background(), &f.session, c, false, f.expected, f.ops()); err != nil {
					t.Fatal(err)
				}
			}
			restart := &winNativeWGState{}
			f.session.restoreOnly = true
			for n := len(steps) - 1; n >= 0; n-- {
				if _, err := restart.compare(context.Background(), &f.session, steps[n], true, TunnelReadback{}, f.ops()); err != nil {
					t.Fatal(err)
				}
			}
			if !winNativeEqual(f.dns[6], before) {
				t.Fatal("original representation not restored")
			}
		})
	}
}
func TestWinNativeWGDNSProofAndAbsence(t *testing.T) {
	f := newWinWGFixture()
	steps := f.prepare(t)
	g := newWinWGFixture()
	other := g.prepare(t)
	if err := f.state.release(context.Background(), &f.session, []nativeChange{steps[0], other[1]}, f.ops(), func(context.Context, winNativeWGProof) error { return nil }); err == nil {
		t.Fatal("mixed proof accepted")
	}
	if err := f.state.release(context.Background(), &f.session, steps[:1], f.ops(), func(context.Context, winNativeWGProof) error { return nil }); err == nil {
		t.Fatal("missing family accepted")
	}
	proof, err := winNativeWGDecode(steps[0].Scope.ServiceID)
	if err != nil {
		t.Fatal(err)
	}
	proof.Version = 2
	raw, _ := json.Marshal(proof)
	if _, err := winNativeWGDecode("soha-wg-dns-v1:" + base64.RawURLEncoding.EncodeToString(raw)); err == nil {
		t.Fatal("unknown version accepted")
	}
	original, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(steps[0].Scope.ServiceID, "soha-wg-dns-v1:"))
	raw = append([]byte(" "), original...)
	if _, err := winNativeWGDecode("soha-wg-dns-v1:" + base64.RawURLEncoding.EncodeToString(raw)); err == nil {
		t.Fatal("noncanonical encoding accepted")
	}
	ops := f.ops()
	ops.exists = func(nativeInterface) (bool, error) { return false, errors.New("permission failure") }
	if r, err := f.state.compare(context.Background(), &f.session, steps[0], true, TunnelReadback{}, ops); err == nil || r.Outcome == "absent" {
		t.Fatal("permission failure was absence")
	}
	f.exists = false
	ops = f.ops()
	ops.read = func(context.Context, string) (TunnelReadback, nativeInterface, error) {
		t.Fatal("absent interface read peer")
		return TunnelReadback{}, nativeInterface{}, nil
	}
	if err := f.state.release(context.Background(), &f.session, steps, ops, func(context.Context, winNativeWGProof) error {
		t.Fatal("absent interface resolved hostname")
		return nil
	}); err != nil || f.state.binding != nil || f.writes != 0 {
		t.Fatal("proven absent release failed", err)
	}
}
func TestWinNativeWGDNSPartialWriteRecovery(t *testing.T) {
	f := newWinWGFixture()
	steps := f.prepare(t)
	f.writeErr = errors.New("lost receipt")
	f.applyOnError = true
	if r, err := f.state.compare(context.Background(), &f.session, steps[0], false, f.expected, f.ops()); err == nil || r.Outcome != "unknown" {
		t.Fatal("first lost receipt not unknown")
	}
	f.applyOnError = false
	if r, err := f.state.compare(context.Background(), &f.session, steps[1], false, f.expected, f.ops()); err == nil || r.Outcome != "unknown" {
		t.Fatal("second failed write not unknown")
	}
	f.writeErr = nil
	restart := &winNativeWGState{}
	f.session.restoreOnly = true
	for n := len(steps) - 1; n >= 0; n-- {
		if _, err := restart.compare(context.Background(), &f.session, steps[n], true, TunnelReadback{}, f.ops()); err != nil {
			t.Fatal(err)
		}
	}
	if f.writes != 3 || !winNativeEqual(f.dns[4], steps[0].Before) || !winNativeEqual(f.dns[6], steps[1].Before) {
		t.Fatal("recovery replayed already-original setter or lost representation")
	}
}

func TestWinNativeWGDNSRejectNewGrantRestore(t *testing.T) {
	f := newWinWGFixture()
	c := f.prepare(t)[0]
	if _, err := f.state.compare(context.Background(), &f.session, c, false, f.expected, f.ops()); err != nil {
		t.Fatal(err)
	}
	beforeWrites := f.writes
	changed := f.expected
	changed.DNSServers = []string{"10.0.0.99"}
	if _, err := f.state.compare(context.Background(), &f.session, c, true, changed, f.ops()); err == nil || f.writes != beforeWrites {
		t.Fatal("old restore wrote into a new DNS-only grant")
	}
}
