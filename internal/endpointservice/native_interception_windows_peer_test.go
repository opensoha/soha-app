package endpointservice

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestWinNativePeerCompleteReadback(t *testing.T) {
	f := newWinWGFixture()
	numeric, err := winNativePeerValue(f.raw, f.expected, "")
	if err != nil || numeric.String() != f.raw.Peer.Endpoint {
		t.Fatal("verified numeric peer lost", err)
	}
	if f.expected.Peer.Endpoint != "vpn.example.test:51820" {
		t.Fatal("hostname compatibility value mutated")
	}
	steps := f.prepare(t)
	for _, c := range steps {
		if _, err := f.state.compare(context.Background(), &f.session, c, false, f.expected, f.ops()); err != nil {
			t.Fatal(err)
		}
	}
	pin, wanted, err := f.state.readbackPlan(f.expected)
	if err != nil {
		t.Fatal(err)
	}
	actual, _, err := f.ops().read(context.Background(), pin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := winNativePeerValue(actual, wanted, pin); err != nil {
		t.Fatal("delegated actual DNS rejected", err)
	}
	for _, name := range []string{"peer drift", "foreign DNS", "different key", "different route", "missing WG", "hostname raw"} {
		t.Run(name, func(t *testing.T) {
			bad := actual
			switch name {
			case "peer drift":
				bad.Peer.Endpoint = "203.0.113.2:51820"
			case "foreign DNS":
				bad.DNSServers = []string{"10.0.0.99"}
			case "different key":
				bad.PublicKey = "foreign"
			case "different route":
				bad.Routes = []string{"192.0.2.0/24"}
			case "missing WG":
				bad = TunnelReadback{}
			case "hostname raw":
				bad.Peer.Endpoint = f.expected.Peer.Endpoint
			}
			if _, err := winNativePeerValue(bad, wanted, pin); err == nil {
				t.Fatal("unverified peer accepted")
			}
		})
	}
}
func TestWinNativePeerSessionAndOneRead(t *testing.T) {
	for _, name := range []string{"success", "restore-only", "denied", "read failure", "switch after read", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			s := &winNativeTestSession{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "restore-only":
				s.restoreOnly = true
			case "denied":
				s.denied = true
			case "switch after read":
				s.failAt = 2
			case "cancelled":
				cancel()
			}
			calls := 0
			peer, err := winNativePeerGuard(ctx, s, func() (netip.AddrPort, error) {
				calls++
				if name == "read failure" {
					return netip.AddrPort{}, errors.New("permission or control read failure")
				}
				return netip.MustParseAddrPort("203.0.113.1:51820"), nil
			})
			if (err == nil) != (name == "success") {
				t.Fatal("session outcome differs", err)
			}
			if err != nil && peer.IsValid() {
				t.Fatal("failed read exposed usable peer")
			}
			expected := 1
			if name == "restore-only" || name == "denied" || name == "cancelled" {
				expected = 0
			}
			if calls != expected {
				t.Fatal("read repeated or preceded authentication", calls)
			}
		})
	}
}
