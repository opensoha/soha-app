package endpointservice

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

func TestWinNativeRecoverySnapshotRestoreOnly(t *testing.T) {
	s := &winNativeTestSession{restoreOnly: true}
	calls := []string{}
	interfaces := []nativeInterface{{ID: "physical", Index: 4, Kind: "physical", Addresses: []netip.Prefix{netip.MustParsePrefix("2001:db8::2/64")}}, {ID: "owned-TUN", Index: 8, Kind: "tunnel", Addresses: []netip.Prefix{netip.MustParsePrefix("fdfe::2/126")}}}
	snap, err := winRecoverySnapshot(context.Background(), s, func(ctx context.Context, s nativeSession, restore bool) error {
		if !restore {
			t.Fatal("recovery requested active authority")
		}
		calls = append(calls, "restore validation")
		return s.Validate(ctx, restore)
	}, func(context.Context) ([]nativeInterface, error) {
		calls = append(calls, "all interfaces")
		return interfaces, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"restore validation", "all interfaces", "restore validation"}) {
		t.Fatal("recovery ordering differs", calls)
	}
	if !reflect.DeepEqual(snap, nativeSnapshot{Interfaces: interfaces}) {
		t.Fatal("recovery queried or returned non-interface settings")
	}
	if !snap.Interfaces[1].Addresses[0].Addr().IsGlobalUnicast() {
		t.Fatal("owned ULA lost")
	}
	if s.Validate(context.Background(), false) == nil {
		t.Fatal("recovery promoted restore-only to active authority")
	}
	interfaces[1].Addresses[0] = netip.MustParsePrefix("fd00::1/128")
	if snap.Interfaces[1].Addresses[0] == interfaces[1].Addresses[0] {
		t.Fatal("snapshot aliases provider memory")
	}
}
func TestWinNativeRecoverySnapshotFailures(t *testing.T) {
	for _, name := range []string{"unknown enumeration", "closed", "foreign", "cancel before", "cancel during", "session lost after"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s := &winNativeTestSession{restoreOnly: true}
			if name == "closed" {
				s.denied = true
			}
			if name == "session lost after" {
				s.failAt = 2
			}
			if name == "cancel before" {
				cancel()
			}
			reads := 0
			snap, err := winRecoverySnapshot(ctx, s, func(ctx context.Context, s nativeSession, restore bool) error {
				if !restore {
					t.Fatal("active session requested")
				}
				if name == "foreign" {
					return errors.New("foreign native session")
				}
				return s.Validate(ctx, restore)
			}, func(context.Context) ([]nativeInterface, error) {
				reads++
				if name == "unknown enumeration" {
					return nil, errors.New("unknown OS interface table")
				}
				if name == "cancel during" {
					cancel()
				}
				return []nativeInterface{{ID: "owned-TUN"}}, nil
			})
			if err == nil || !reflect.DeepEqual(snap, nativeSnapshot{}) {
				t.Fatal("unknown observation accepted as snapshot/absence", err)
			}
			expected := 1
			if name == "closed" || name == "foreign" || name == "cancel before" {
				expected = 0
			}
			if reads != expected {
				t.Fatal("unauthorized or repeated enumeration", reads)
			}
		})
	}
}
func TestWinNativeRecoveryFullInterfaceMerge(t *testing.T) {
	rows := []winRecoveryInterfaceRow{{LUID: 1, Status: 2, Interface: nativeInterface{ID: "down-owned-TUN", Index: 8, Kind: "tunnel"}}, {LUID: 2, Status: 1, Interface: nativeInterface{ID: "other", Index: 4, Kind: "unknown"}}}
	addresses := []winRecoveryAddressRow{{LUID: 1, Addresses: []netip.Prefix{netip.MustParsePrefix("fdfe::2/126")}}}
	all, err := winRecoveryMerge(rows, rows, addresses, addresses)
	if err != nil || len(all) != 2 || all[0].ID != "down-owned-TUN" || len(all[0].Addresses) != 1 {
		t.Fatal("down interface/owned ULA filtered", err)
	}
	changed := append([]winRecoveryInterfaceRow(nil), rows...)
	changed[0].Interface.ID = "replacement"
	if _, err := winRecoveryMerge(rows, changed, addresses, addresses); err == nil {
		t.Fatal("interface replacement accepted")
	}
	if _, err := winRecoveryMerge(rows, rows[:1], addresses, addresses); err == nil {
		t.Fatal("incomplete table accepted as disappearance")
	}
	if _, err := winRecoveryMerge(rows, rows, []winRecoveryAddressRow{{LUID: 99}}, addresses); err == nil {
		t.Fatal("unknown address scope dropped")
	}
}

func TestWinNativeRecoveryCountersAndAddressFence(t *testing.T) {
	before := []winRecoveryInterfaceRow{{LUID: 1, Status: 1, Octets: 100, Interface: nativeInterface{ID: "owned-TUN", Index: 8, Kind: "tunnel"}}}
	after := append([]winRecoveryInterfaceRow(nil), before...)
	after[0].Octets = 999999
	after[0].Status = 2
	addresses := []winRecoveryAddressRow{{LUID: 1, Addresses: []netip.Prefix{netip.MustParsePrefix("fdfe::2/126"), netip.MustParsePrefix("192.0.2.2/24")}}}
	reordered := []winRecoveryAddressRow{{LUID: 1, Addresses: []netip.Prefix{addresses[0].Addresses[1], addresses[0].Addresses[0]}}}
	if _, err := winRecoveryMerge(before, after, addresses, reordered); err != nil {
		t.Fatal("natural statistics/status/order change blocked recovery", err)
	}
	changed := []winRecoveryAddressRow{{LUID: 1, Addresses: []netip.Prefix{netip.MustParsePrefix("fdfe::3/126")}}}
	if _, err := winRecoveryMerge(before, after, addresses, changed); err == nil {
		t.Fatal("address-set drift accepted")
	}
}
