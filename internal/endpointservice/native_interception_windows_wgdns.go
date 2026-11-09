//go:build windows

package endpointservice

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"net"
	"net/netip"
	"unsafe"
)

func (system *WindowsSystem) nativeExpected() *TunnelPlan {
	system.nativeExpectedMu.Lock()
	defer system.nativeExpectedMu.Unlock()
	if system.expected == nil {
		return nil
	}
	copy := cloneTunnelPlan(*system.expected)
	return &copy
}
func winNativeWGSession(s nativeSession, restore bool, ctx context.Context) error {
	if _, ok := s.(*winNativeSession); !ok {
		return errors.New("untrusted WG native session")
	}
	return s.Validate(ctx, restore)
}
func (system *WindowsSystem) nativeWGOps(ctx context.Context, session nativeSession, restore bool) winNativeWGOps {
	return winNativeWGOps{
		read: func(ctx context.Context, pin string) (TunnelReadback, nativeInterface, error) {
			raw, err := system.readbackWindows(ctx, false, pin)
			if err != nil {
				return raw, nativeInterface{}, err
			}
			iface, err := winNativeWGInterface()
			return raw, iface, err
		},
		exists: winNativeWGExists, dns: winNativeDNSValue, write: func(scope nativeScope, v nativeValue) error {
			if err := winNativeCheckInterface(scope.Interface); err != nil {
				return err
			}
			if err := session.Validate(ctx, restore); err != nil {
				return err
			}
			if err := winNativeWriteDNS(scope, v); err != nil {
				return err
			}
			return session.Validate(ctx, restore)
		},
	}
}
func (system *WindowsSystem) PrepareNativeDNS(ctx context.Context, s nativeSession, servers []netip.Addr) ([]nativeChange, error) {
	if err := winNativeWGSession(s, false, ctx); err != nil {
		return nil, err
	}
	expected := system.nativeExpected()
	if expected == nil {
		return nil, errors.New("no trusted WG grant")
	}
	return system.nativeDNS.prepare(ctx, s, expected.Readback(), servers, system.nativeWGOps(ctx, s, false))
}
func (system *WindowsSystem) ReadNativeDNS(ctx context.Context, s nativeSession, c nativeChange) (nativeValue, error) {
	if err := winNativeWGSession(s, true, ctx); err != nil {
		return nativeValue{}, err
	}
	return system.nativeDNS.read(ctx, s, c, system.nativeWGOps(ctx, s, true))
}
func (system *WindowsSystem) CompareNativeDNS(ctx context.Context, s nativeSession, c nativeChange, restore bool) (nativeReceipt, error) {
	if err := winNativeWGSession(s, restore, ctx); err != nil {
		return nativeReceipt{ChangeID: c.ID, Outcome: "not_applied"}, err
	}
	expected := system.nativeExpected()
	var readback TunnelReadback
	if expected != nil {
		readback = expected.Readback()
	}
	return system.nativeDNS.compare(ctx, s, c, restore, readback, system.nativeWGOps(ctx, s, restore))
}
func winNativeWGInterface() (nativeInterface, error) {
	adapter, err := net.InterfaceByName(endpointInterfaceName)
	if err != nil {
		return nativeInterface{}, err
	}
	interfaces, _, err := winNativeAdapters()
	if err != nil {
		return nativeInterface{}, err
	}
	for _, i := range interfaces {
		if i.Index == uint32(adapter.Index) && i.Name == endpointInterfaceName {
			return i, nil
		}
	}
	return nativeInterface{}, errors.New("WG stable interface identity unavailable")
}
func winNativeWGExists(expected nativeInterface) (bool, error) {
	if _, err := windows.GUIDFromString(expected.ID); err != nil {
		return false, err
	}
	var table *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(0, &table); err != nil {
		return false, err
	}
	if table == nil {
		return false, errors.New("complete interface table unavailable")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	if table.NumEntries > 65536 {
		return false, errors.New("interface table exceeds bound")
	}
	for _, row := range unsafe.Slice(&table.Table[0], table.NumEntries) {
		if row.InterfaceGuid.String() == expected.ID {
			return true, nil
		}
	}
	return false, nil
}

var _ nativeWGDNSOwner = (*WindowsSystem)(nil)

func (system *WindowsSystem) ReleaseNativeDNS(ctx context.Context, s nativeSession, changes []nativeChange) error {
	if err := winNativeWGSession(s, true, ctx); err != nil {
		return err
	}
	expected := system.nativeExpected()
	return system.nativeDNS.release(ctx, s, changes, system.nativeWGOps(ctx, s, true), func(ctx context.Context, p winNativeWGProof) error {
		if expected != nil {
			canonical := expected.Readback()
			canonical.Peer.Endpoint = p.Endpoint
			if expected.Peer.Endpoint != p.DeclaredEndpoint || readbackHash(canonical) != p.Grant {
				return errors.New("original WG hostname grant changed")
			}
		}
		endpoint, err := netip.ParseAddrPort(p.Endpoint)
		if err != nil {
			return err
		}
		if !endpointMatches(ctx, p.DeclaredEndpoint, net.UDPAddrFromAddrPort(endpoint)) {
			return errors.New("original WG endpoint no longer passes strict hostname validation")
		}
		return nil
	})
}
