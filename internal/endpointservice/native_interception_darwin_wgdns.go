//go:build darwin && cgo

package endpointservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strings"
)

var errDarwinWGDNS = errors.New("macOS WG DNS grant, handle, or original scope could not be verified")

func darwinWGLoopbacks(servers []netip.Addr) bool {
	if len(servers) == 0 || len(servers) > 2 {
		return false
	}
	for i, a := range servers {
		if a != netip.MustParseAddr("127.0.0.1") && a != netip.IPv6Loopback() {
			return false
		}
		for j := 0; j < i; j++ {
			if servers[j] == a {
				return false
			}
		}
	}
	return true
}
func darwinWGServers(servers []string) ([]netip.Addr, error) {
	if len(servers) == 0 || len(servers) > 64 {
		return nil, errDarwinWGDNS
	}
	result := make([]netip.Addr, 0, len(servers))
	for _, raw := range servers {
		a, err := netip.ParseAddr(raw)
		if err != nil {
			return nil, errDarwinWGDNS
		}
		result = append(result, a)
	}
	return result, nil
}
func darwinWGStrings(servers []netip.Addr) []string {
	result := make([]string, 0, len(servers))
	for _, a := range servers {
		result = append(result, a.String())
	}
	return result
}
func darwinWGChange(service string, iface nativeInterface, grant TunnelReadback, servers []netip.Addr) (nativeChange, error) {
	before, err := darwinWGServers(grant.DNSServers)
	if err != nil || !darwinWGLoopbacks(servers) {
		return nativeChange{}, errDarwinWGDNS
	}
	c := nativeChange{Kind: "dns", Scope: nativeScope{ServiceID: service, Interface: iface}, Before: nativeValue{Present: true, DNS: &nativeDNSConfig{Servers: before}}, After: nativeValue{Present: true, DNS: &nativeDNSConfig{Servers: slices.Clone(servers)}}}
	raw, _ := json.Marshal(struct {
		Change nativeChange
		Grant  TunnelReadback
	}{c, grant})
	hash := sha256.Sum256(raw)
	c.ID = "darwin:wg-dns:" + hex.EncodeToString(hash[:])
	return c, nil
}
func darwinWGValidChange(c nativeChange) bool {
	return c.Kind == "dns" && c.Field == "" && strings.HasPrefix(c.ID, "darwin:wg-dns:") && strings.HasPrefix(c.Scope.ServiceID, "com.opensoha.vpn.") && len(c.Scope.ServiceID) <= 128 && identifierPattern.MatchString(c.Scope.ServiceID) && c.Scope.Interface.ID != "" && c.Scope.Interface.Name != "" && c.Scope.Interface.Index > 0 && c.Before.Present && c.Before.DNS != nil && !c.Before.DNS.Automatic && len(c.Before.DNS.Servers) > 0 && c.After.Present && c.After.DNS != nil && !c.After.DNS.Automatic && darwinWGLoopbacks(c.After.DNS.Servers)
}
func (s *DarwinSystem) wgNativeInterfaces() ([]nativeInterface, error) {
	if s.nativeDNSInterfaces != nil {
		return s.nativeDNSInterfaces()
	}
	return darwinNativeInterfaces()
}
func (s *DarwinSystem) wgNativeReadback(ctx context.Context) (TunnelReadback, error) {
	if s.nativeDNSReadback != nil {
		return s.nativeDNSReadback(ctx)
	}
	return s.readback(ctx)
}
func (s *DarwinSystem) wgNativeScope(c nativeChange) error {
	if s.dns == nil || s.dns.serviceID != c.Scope.ServiceID || s.name != c.Scope.Interface.Name || s.expected == nil {
		return errDarwinWGDNS
	}
	interfaces, err := s.wgNativeInterfaces()
	if err != nil {
		return err
	}
	matches := 0
	for _, iface := range interfaces {
		if darwinNativeSameInterface(iface, c.Scope.Interface) {
			matches++
		}
	}
	if matches != 1 {
		return errDarwinWGDNS
	}
	return nil
}
func (s *DarwinSystem) PrepareNativeDNS(ctx context.Context, session nativeSession, servers []netip.Addr) ([]nativeChange, error) {
	if session == nil {
		return nil, errDarwinWGDNS
	}
	if err := session.Validate(ctx, false); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !darwinWGLoopbacks(servers) || s.expected == nil || s.dns == nil || s.nativeDNSDelegate != nil {
		return nil, errDarwinWGDNS
	}
	state, err := s.wgNativeReadback(ctx)
	if err != nil || !reflect.DeepEqual(state, s.expected.Readback()) || !s.dns.matches() {
		return nil, errors.Join(err, errDarwinWGDNS)
	}
	actual, err := s.dns.currentServers()
	if err != nil || !slices.Equal(actual, state.DNSServers) {
		return nil, errors.Join(err, errDarwinWGDNS)
	}
	interfaces, err := s.wgNativeInterfaces()
	if err != nil {
		return nil, err
	}
	var iface nativeInterface
	for _, candidate := range interfaces {
		if candidate.Name == s.name {
			if iface.ID != "" {
				return nil, errDarwinWGDNS
			}
			iface = candidate
		}
	}
	if iface.ID == "" || iface.Kind != "tunnel" {
		return nil, errDarwinWGDNS
	}
	c, err := darwinWGChange(s.dns.serviceID, iface, s.expected.Readback(), servers)
	if err != nil || !darwinWGValidChange(c) {
		return nil, errDarwinWGDNS
	}
	if err = session.Validate(ctx, false); err != nil {
		return nil, err
	}
	return []nativeChange{c}, nil
}
func (s *DarwinSystem) readNativeDNSLocked(ctx context.Context, c nativeChange) (nativeValue, error) {
	if !darwinWGValidChange(c) {
		return nativeValue{}, errDarwinWGDNS
	}
	if err := s.wgNativeScope(c); err != nil {
		return nativeValue{}, err
	}
	expected, err := darwinWGChange(c.Scope.ServiceID, c.Scope.Interface, s.expected.Readback(), c.After.DNS.Servers)
	if err != nil || !reflect.DeepEqual(expected, c) {
		return nativeValue{}, errDarwinWGDNS
	}
	servers, err := s.dns.currentServers()
	if err != nil {
		return nativeValue{}, err
	}
	addresses, err := darwinWGServers(servers)
	if err != nil {
		return nativeValue{}, err
	}
	return nativeValue{Present: true, DNS: &nativeDNSConfig{Servers: addresses}}, nil
}
func (s *DarwinSystem) ReadNativeDNS(ctx context.Context, session nativeSession, c nativeChange) (nativeValue, error) {
	if session == nil {
		return nativeValue{}, errDarwinWGDNS
	}
	if err := session.Validate(ctx, true); err != nil {
		return nativeValue{}, err
	}
	if !darwinWGValidChange(c) {
		return nativeValue{}, errDarwinWGDNS
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	absent, err := s.wgNativeAbsent(c)
	if err != nil {
		return nativeValue{}, err
	}
	if absent {
		if err = session.Validate(ctx, true); err != nil {
			return nativeValue{}, err
		}
		return nativeValue{Present: false}, nil
	}
	value, err := s.readNativeDNSLocked(ctx, c)
	if err != nil {
		return value, err
	}
	state, readErr := s.wgNativeReadback(ctx)
	if readErr != nil || !darwinWGReadbackMatches(state, s.expected.Readback(), s.nativeDNSDelegate) {
		return value, errors.Join(readErr, errDarwinWGDNS)
	}
	if err = session.Validate(ctx, true); err != nil {
		return nativeValue{}, err
	}
	return value, nil
}
func (s *DarwinSystem) wgNativeAbsent(c nativeChange) (bool, error) {
	interfaces, err := s.wgNativeInterfaces()
	if err != nil {
		return false, err
	}
	for _, iface := range interfaces {
		if darwinNativeSameInterface(iface, c.Scope.Interface) {
			return false, nil
		}
	}
	if s.nativeDNSAbsent != nil {
		return s.nativeDNSAbsent(c)
	}
	return darwinWGHandleAbsent(c.Scope.ServiceID)
}
func (s *DarwinSystem) CompareNativeDNS(ctx context.Context, session nativeSession, c nativeChange, restore bool) (nativeReceipt, error) {
	receipt := nativeReceipt{ChangeID: c.ID, Outcome: "not_applied"}
	if session == nil {
		return receipt, errDarwinWGDNS
	}
	if err := session.Validate(ctx, restore); err != nil {
		return receipt, err
	}
	if !darwinWGValidChange(c) {
		return receipt, errDarwinWGDNS
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if restore {
		absent, err := s.wgNativeAbsent(c)
		if err != nil {
			return receipt, err
		}
		if absent {
			receipt.Outcome = "absent"
			return receipt, nil
		}
	}
	current, err := s.readNativeDNSLocked(ctx, c)
	receipt.Current = current
	if err != nil {
		return receipt, err
	}
	before, after := c.Before, c.After
	if restore {
		before, after = after, before
	}
	if !reflect.DeepEqual(current, before) {
		receipt.Outcome = "conflict"
		return receipt, errDarwinWGDNS
	}
	if !restore && s.nativeDNSDelegate != nil {
		return receipt, errDarwinWGDNS
	}
	if s.nativeDNSDelegate != nil {
		if !reflect.DeepEqual(s.nativeDNSDelegate.change, c) || !reflect.DeepEqual(s.nativeDNSDelegate.grant, s.expected.Readback()) || s.nativeDNSDelegate.owner != session.Owner() {
			return receipt, errDarwinWGDNS
		}
	} else if restore {
		return receipt, errDarwinWGDNS
	}
	stateBefore, e := s.wgNativeReadback(ctx)
	if e != nil || !darwinWGReadbackMatches(stateBefore, s.expected.Readback(), s.nativeDNSDelegate) {
		return receipt, errors.Join(e, errDarwinWGDNS)
	}
	if err = session.Validate(ctx, restore); err != nil {
		return receipt, err
	}
	// Retain the original grant even when a write's acknowledgement is lost.
	if s.nativeDNSDelegate == nil {
		s.nativeDNSDelegate = &darwinWGDNSEpoch{change: c, grant: s.expected.Readback(), owner: session.Owner()}
	}
	receipt.Outcome, err = s.dns.compareServers(darwinWGStrings(before.DNS.Servers), darwinWGStrings(after.DNS.Servers))
	if err != nil {
		observed, readErr := s.readNativeDNSLocked(ctx, c)
		receipt.Current = observed
		if restore && readErr == nil && reflect.DeepEqual(observed, after) {
			s.nativeDNSDelegate.restored = true
		}
		return receipt, errors.Join(err, readErr)
	}
	if restore {
		s.nativeDNSDelegate.restored = true
	}
	current, err = s.readNativeDNSLocked(ctx, c)
	receipt.Current = current
	if err != nil || !reflect.DeepEqual(current, after) {
		receipt.Outcome = "unknown"
		return receipt, errors.Join(err, errDarwinWGDNS)
	}
	state, err := s.wgNativeReadback(ctx)
	if err != nil || !darwinWGReadbackMatches(state, s.expected.Readback(), s.nativeDNSDelegate) {
		receipt.Outcome = "unknown"
		return receipt, errors.Join(err, errDarwinWGDNS)
	}
	receipt.Outcome = "applied"
	if err = session.Validate(ctx, restore); err != nil {
		return receipt, err
	}
	return receipt, nil
}

// Called only after all DNS scopes are restored and the coordinator's cache step succeeds.
// This does not write DNS or reinterpret the saved grant as fresh authorization.
func (s *DarwinSystem) ReleaseNativeDNS(ctx context.Context, session nativeSession, changes []nativeChange) error {
	if session == nil {
		return errDarwinWGDNS
	}
	if err := session.Validate(ctx, true); err != nil {
		return err
	}
	if len(changes) != 1 || !darwinWGValidChange(changes[0]) {
		return errDarwinWGDNS
	}
	c := changes[0]
	s.mu.Lock()
	defer s.mu.Unlock()
	absent, err := s.wgNativeAbsent(c)
	if err != nil {
		return err
	}
	if absent {
		if s.nativeDNSDelegate != nil && reflect.DeepEqual(s.nativeDNSDelegate.change, c) {
			if s.nativeDNSDelegate.owner != session.Owner() {
				return errDarwinWGDNS
			}
			s.nativeDNSDelegate = nil
			s.peerEndpoint = netip.AddrPort{}
		}
		return session.Validate(ctx, true)
	}
	current, err := s.readNativeDNSLocked(ctx, c)
	if err != nil || !reflect.DeepEqual(current, c.Before) {
		return errors.Join(err, errDarwinWGDNS)
	}
	if s.nativeDNSDelegate != nil && (!s.nativeDNSDelegate.restored || !reflect.DeepEqual(s.nativeDNSDelegate.change, c) || s.nativeDNSDelegate.owner != session.Owner()) {
		return errDarwinWGDNS
	}
	state, err := s.wgNativeReadback(ctx)
	if err != nil || !darwinWGReadbackMatches(state, s.expected.Readback(), s.nativeDNSDelegate) {
		return errors.Join(err, errDarwinWGDNS)
	}
	if !s.peerEndpoint.IsValid() {
		return errDarwinWGDNS
	}
	verified := false
	if s.nativeDNSVerifyEndpoint != nil {
		verified = s.nativeDNSVerifyEndpoint(ctx, s.expected.Peer.Endpoint, s.peerEndpoint)
	} else {
		verified = endpointMatches(ctx, s.expected.Peer.Endpoint, net.UDPAddrFromAddrPort(s.peerEndpoint))
	}
	if !verified {
		return errDarwinWGDNS
	}
	if err = session.Validate(ctx, true); err != nil {
		return err
	}
	s.nativeDNSDelegate = nil
	s.peerEndpoint = netip.AddrPort{}
	return nil
}
