package endpointservice

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
)

type winNativeWGProof struct {
	Version          int      `json:"version"`
	Grant            string   `json:"grant"`
	DNS              []string `json:"dns"`
	Endpoint         string   `json:"endpoint"`
	DeclaredEndpoint string   `json:"declaredEndpoint"`
	Nonce            string   `json:"nonce"`
}
type winNativeWGBinding struct {
	proof            winNativeWGProof
	id, expected     string
	owner            nativeOwner
	iface            nativeInterface
	steps            []nativeChange
	active           map[uint8]bool
	invalid, closing bool
}
type winNativeWGState struct {
	mu      sync.Mutex
	binding *winNativeWGBinding
	retired map[string]bool
}
type winNativeWGOps struct {
	read   func(context.Context, string) (TunnelReadback, nativeInterface, error)
	exists func(nativeInterface) (bool, error)
	dns    func(nativeScope) (nativeValue, error)
	write  func(nativeScope, nativeValue) error
}

func winNativeWGDecode(id string) (winNativeWGProof, error) {
	var p winNativeWGProof
	if len(id) > 4096 || !strings.HasPrefix(id, "soha-wg-dns-v1:") {
		return p, errors.New("invalid WG DNS proof")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(id, "soha-wg-dns-v1:"))
	if err != nil {
		return p, errors.New("invalid WG DNS proof")
	}
	if err := decodeStrict(raw, &p); err != nil {
		return p, errors.New("invalid WG DNS proof")
	}
	endpoint, err := netip.ParseAddrPort(p.Endpoint)
	if err != nil || endpoint.String() != p.Endpoint || !endpoint.Addr().IsGlobalUnicast() || endpoint.Port() == 0 || p.Version != 1 || !validReadbackHash(p.Grant) || len(p.Nonce) != 32 || len(p.DNS) > 8 {
		return p, errors.New("invalid WG public proof")
	}
	if _, err := hex.DecodeString(p.Nonce); err != nil {
		return p, errors.New("invalid WG proof nonce")
	}
	host, port, err := net.SplitHostPort(p.DeclaredEndpoint)
	n, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || portErr != nil || n == 0 || !validEndpointHost(host) || len(p.DeclaredEndpoint) > 512 {
		return p, errors.New("invalid original WG endpoint")
	}
	seen := map[string]bool{}
	for _, raw := range p.DNS {
		a, err := netip.ParseAddr(raw)
		if err != nil || a.String() != raw || a.Is4In6() || !a.IsGlobalUnicast() || seen[raw] {
			return p, errors.New("invalid original WG DNS")
		}
		seen[raw] = true
	}
	canonical, _ := json.Marshal(p)
	if base64.RawURLEncoding.EncodeToString(canonical) != strings.TrimPrefix(id, "soha-wg-dns-v1:") {
		return p, errors.New("noncanonical WG proof")
	}
	return p, nil
}
func winNativeWGFamily(servers []string, family uint8) []netip.Addr {
	var out []netip.Addr
	for _, raw := range servers {
		a, err := netip.ParseAddr(raw)
		if err == nil && a.Is4() == (family == 4) {
			out = append(out, a)
		}
	}
	return out
}
func winNativeWGValidate(c nativeChange) (winNativeWGProof, error) {
	p, err := winNativeWGDecode(c.Scope.ServiceID)
	if err != nil {
		return p, err
	}
	if c.ID != "wg-dns/"+p.Nonce+"/"+string(rune('0'+c.Scope.Family)) || c.Kind != "dns" || c.Field != "" || c.Scope.Interface.ID == "" || c.Scope.Interface.Index == 0 || c.Scope.Interface.Name != endpointInterfaceName || (c.Scope.Family != 4 && c.Scope.Family != 6) {
		return p, errors.New("invalid WG DNS step")
	}
	if err := winNativeValidate(c); err != nil {
		return p, err
	}
	original := winNativeWGFamily(p.DNS, c.Scope.Family)
	if c.Before.Present && c.Before.DNS != nil && !c.Before.DNS.Automatic {
		if !slices.Equal(c.Before.DNS.Servers, original) {
			return p, errors.New("WG baseline differs from original grant")
		}
	} else if len(original) != 0 {
		return p, errors.New("automatic WG DNS differs from original grant")
	}
	wanted := netip.MustParseAddr("::1")
	if c.Scope.Family == 4 {
		wanted = netip.MustParseAddr("127.0.0.1")
	}
	if !c.After.Present || c.After.DNS == nil || c.After.DNS.Automatic || len(c.After.DNS.Servers) != 1 || c.After.DNS.Servers[0] != wanted {
		return p, errors.New("WG DNS target is not fixed owned loopback")
	}
	return p, nil
}
func (d *winNativeWGState) invalidate() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.binding != nil {
		d.binding.invalid = true
		if d.retired == nil {
			d.retired = map[string]bool{}
		}
		d.retired[d.binding.id] = true
	}
}
func (d *winNativeWGState) prepare(ctx context.Context, s nativeSession, expected TunnelReadback, servers []netip.Addr, ops winNativeWGOps) ([]nativeChange, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if s == nil {
		return nil, errors.New("missing WG native session")
	}
	if err := s.Validate(ctx, false); err != nil {
		return nil, err
	}
	if d.binding != nil && !d.binding.invalid {
		return nil, errors.New("WG DNS already delegated")
	}
	if len(servers) != 2 || !slices.Contains(servers, netip.MustParseAddr("127.0.0.1")) || !slices.Contains(servers, netip.MustParseAddr("::1")) {
		return nil, errors.New("WG requires both fixed owned loopbacks")
	}
	raw, iface, err := ops.read(ctx, "")
	if err != nil {
		return nil, err
	}
	if expected.PublicKey == "" || raw.PublicKey == "" || iface.Name != endpointInterfaceName || iface.ID == "" || iface.Index == 0 {
		return nil, errors.New("WG grant is not verified")
	}
	normalized := raw
	normalized.Peer.Endpoint = expected.Peer.Endpoint
	if !reflect.DeepEqual(normalized, expected) {
		return nil, errors.New("actual WG state differs from original grant")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	proof := winNativeWGProof{Version: 1, Grant: readbackHash(raw), DNS: slices.Clone(raw.DNSServers), Endpoint: raw.Peer.Endpoint, DeclaredEndpoint: expected.Peer.Endpoint, Nonce: hex.EncodeToString(nonce)}
	encoded, _ := json.Marshal(proof)
	id := "soha-wg-dns-v1:" + base64.RawURLEncoding.EncodeToString(encoded)
	if _, err := winNativeWGDecode(id); err != nil {
		return nil, err
	}
	var steps []nativeChange
	for _, family := range []uint8{4, 6} {
		scope := nativeScope{ServiceID: id, Interface: iface, Family: family}
		before, err := ops.dns(scope)
		if err != nil {
			return nil, err
		}
		target := netip.MustParseAddr("::1")
		if family == 4 {
			target = netip.MustParseAddr("127.0.0.1")
		}
		c := nativeChange{ID: "wg-dns/" + proof.Nonce + "/" + string(rune('0'+family)), Kind: "dns", Scope: scope, Before: before, After: nativeValue{Present: true, DNS: &nativeDNSConfig{Servers: []netip.Addr{target}}}}
		if _, err := winNativeWGValidate(c); err != nil {
			return nil, err
		}
		steps = append(steps, c)
	}
	if err := s.Validate(ctx, false); err != nil {
		return nil, err
	}
	d.binding = &winNativeWGBinding{proof: proof, id: id, expected: readbackHash(expected), owner: s.Owner(), iface: iface, steps: steps, active: map[uint8]bool{}}
	return steps, nil
}
func winNativeWGGrant(ctx context.Context, c nativeChange, p winNativeWGProof, ops winNativeWGOps) error {
	raw, iface, err := ops.read(ctx, p.Endpoint)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(iface, c.Scope.Interface) || raw.Peer.Endpoint != p.Endpoint {
		return errors.New("WG interface or numeric peer changed")
	}
	for _, family := range []uint8{4, 6} {
		actual := winNativeWGFamily(raw.DNSServers, family)
		original := winNativeWGFamily(p.DNS, family)
		target := netip.MustParseAddr("::1")
		if family == 4 {
			target = netip.MustParseAddr("127.0.0.1")
		}
		if !slices.Equal(actual, original) && !(len(actual) == 1 && actual[0] == target) {
			return errors.New("another WG DNS family changed externally")
		}
	}
	raw.DNSServers = slices.Clone(p.DNS)
	if readbackHash(raw) != p.Grant {
		return errors.New("WG public grant changed")
	}
	return nil
}
func (d *winNativeWGState) read(ctx context.Context, s nativeSession, c nativeChange, ops winNativeWGOps) (nativeValue, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if s == nil {
		return nativeValue{}, errors.New("missing WG native session")
	}
	if err := s.Validate(ctx, true); err != nil {
		return nativeValue{}, err
	}
	p, err := winNativeWGValidate(c)
	if err != nil {
		return nativeValue{}, err
	}
	// A missing DNS value is not proof that its original interface disappeared.
	exists, err := ops.exists(c.Scope.Interface)
	if err != nil {
		return nativeValue{}, err
	}
	if !exists {
		return nativeValue{}, s.Validate(ctx, true)
	}
	if err := winNativeWGGrant(ctx, c, p, ops); err != nil {
		return nativeValue{}, err
	}
	v, err := ops.dns(c.Scope)
	if err != nil {
		return v, err
	}
	if !v.Present && c.Before.Present {
		return nativeValue{}, errors.New("WG DNS value missing on present original interface")
	}
	return v, s.Validate(ctx, true)
}
func (d *winNativeWGState) compare(ctx context.Context, s nativeSession, c nativeChange, restore bool, expected TunnelReadback, ops winNativeWGOps) (nativeReceipt, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	r := nativeReceipt{ChangeID: c.ID, Outcome: "not_applied"}
	if s == nil {
		return r, errors.New("missing WG native session")
	}
	if err := s.Validate(ctx, restore); err != nil {
		return r, err
	}
	p, err := winNativeWGValidate(c)
	if err != nil {
		return r, err
	}
	exists, err := ops.exists(c.Scope.Interface)
	if err != nil {
		return r, err
	}
	if !exists {
		if restore {
			r.Outcome = "absent"
			return r, nil
		}
		return r, errors.New("original WG interface disappeared")
	}
	if expected.PublicKey != "" {
		canonical := expected
		canonical.Peer.Endpoint = p.Endpoint
		if expected.Peer.Endpoint != p.DeclaredEndpoint || readbackHash(canonical) != p.Grant {
			return r, errors.New("current WG grant differs from journaled original grant")
		}
	}
	if d.retired[c.Scope.ServiceID] {
		return r, errors.New("WG delegation was invalidated")
	}
	if !restore && (d.binding == nil || d.binding.invalid || d.binding.closing || d.binding.id != c.Scope.ServiceID || d.binding.expected != readbackHash(expected) || d.binding.owner != s.Owner() || !slices.ContainsFunc(d.binding.steps, func(step nativeChange) bool { return reflect.DeepEqual(step, c) })) {
		return r, errors.New("WG delegation no longer belongs to current grant")
	}
	if err := winNativeWGGrant(ctx, c, p, ops); err != nil {
		return r, err
	}
	if restore {
		current, err := ops.dns(c.Scope)
		if err != nil {
			return r, err
		}
		if winNativeEqual(current, c.Before) {
			r.Current = current
			r.Outcome = "applied"
			if d.binding != nil && d.binding.id == c.Scope.ServiceID {
				delete(d.binding.active, c.Scope.Family)
			}
			return r, s.Validate(ctx, true)
		}
	}
	r, err = winNativeCompare(ctx, s, c, restore, func() (nativeValue, error) {
		if err := winNativeWGGrant(ctx, c, p, ops); err != nil {
			return nativeValue{}, err
		}
		return ops.dns(c.Scope)
	}, func(_, after nativeValue) error {
		if err := winNativeWGGrant(ctx, c, p, ops); err != nil {
			return err
		}
		if !restore && d.binding != nil {
			d.binding.active[c.Scope.Family] = true
		}
		if err := s.Validate(ctx, restore); err != nil {
			return err
		}
		return ops.write(c.Scope, after)
	})
	if err == nil && restore && d.binding != nil && d.binding.id == c.Scope.ServiceID {
		delete(d.binding.active, c.Scope.Family)
	}
	return r, err
}
func (d *winNativeWGState) readbackPlan(expected TunnelReadback) (string, TunnelReadback, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	b := d.binding
	if b == nil {
		return "", expected, nil
	}
	if b.invalid {
		return "", TunnelReadback{}, errors.New("WG DNS delegation invalidated; cleanup required")
	}
	if b.expected != readbackHash(expected) {
		return "", TunnelReadback{}, errors.New("WG grant changed during native delegation")
	}
	wanted := expected
	wanted.DNSServers = slices.Clone(expected.DNSServers)
	for family := range b.active {
		var next []string
		for _, raw := range wanted.DNSServers {
			a, err := netip.ParseAddr(raw)
			if err != nil {
				return "", TunnelReadback{}, err
			}
			if a.Is4() != (family == 4) {
				next = append(next, raw)
			}
		}
		target := "::1"
		if family == 4 {
			target = "127.0.0.1"
		}
		wanted.DNSServers = append(next, target)
	}
	slices.Sort(wanted.DNSServers)
	return b.proof.Endpoint, wanted, nil
}

func (d *winNativeWGState) release(ctx context.Context, s nativeSession, changes []nativeChange, ops winNativeWGOps, verifyEndpoint func(context.Context, winNativeWGProof) error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if s == nil {
		return errors.New("missing WG restore session")
	}
	if err := s.Validate(ctx, true); err != nil {
		return err
	}
	if len(changes) != 2 {
		return errors.New("incomplete WG DNS release")
	}
	var proof winNativeWGProof
	seen := map[uint8]bool{}
	id := ""
	for _, c := range changes {
		p, err := winNativeWGValidate(c)
		if err != nil {
			return err
		}
		if id != "" && (id != c.Scope.ServiceID || !reflect.DeepEqual(c.Scope.Interface, changes[0].Scope.Interface)) {
			return errors.New("mixed WG release proof")
		}
		if seen[c.Scope.Family] {
			return errors.New("duplicate WG DNS release family")
		}
		seen[c.Scope.Family] = true
		id = c.Scope.ServiceID
		proof = p
	}
	if d.binding != nil && d.binding.id == id {
		d.binding.closing = true
	}
	exists, err := ops.exists(changes[0].Scope.Interface)
	if err != nil {
		return err
	}
	if exists {
		for _, c := range changes {
			if err := winNativeWGGrant(ctx, c, proof, ops); err != nil {
				return err
			}
			value, err := ops.dns(c.Scope)
			if err != nil {
				return err
			}
			if !winNativeEqual(value, c.Before) {
				return errors.New("WG DNS is not fully restored before release")
			}
		}
		if err := verifyEndpoint(ctx, proof); err != nil {
			return err
		}
	}
	if err := s.Validate(ctx, true); err != nil {
		return err
	}
	if d.binding != nil && d.binding.id == id {
		d.binding = nil
	}
	if d.retired == nil {
		d.retired = map[string]bool{}
	}
	d.retired[id] = true
	return nil
}

func winNativePeerValue(actual, wanted TunnelReadback, pin string) (netip.AddrPort, error) {
	endpoint, err := netip.ParseAddrPort(actual.Peer.Endpoint)
	if err != nil || !endpoint.IsValid() || endpoint.Port() == 0 || !endpoint.Addr().IsGlobalUnicast() || endpoint.Addr().Is4In6() || endpoint.String() != actual.Peer.Endpoint {
		return netip.AddrPort{}, errors.New("WG readback has no canonical numeric peer")
	}
	if wanted.PublicKey == "" || actual.PublicKey == "" || pin != "" && actual.Peer.Endpoint != pin {
		return netip.AddrPort{}, errors.New("WG peer differs from trusted grant pin")
	}
	normalized := actual
	normalized.Peer.Endpoint = wanted.Peer.Endpoint
	if !reflect.DeepEqual(normalized, wanted) {
		return netip.AddrPort{}, errors.New("WG peer readback differs from complete trusted grant")
	}
	return endpoint, nil
}
func winNativePeerGuard(ctx context.Context, s nativeSession, read func() (netip.AddrPort, error)) (netip.AddrPort, error) {
	if s == nil {
		return netip.AddrPort{}, errors.New("missing native peer session")
	}
	if err := s.Validate(ctx, false); err != nil {
		return netip.AddrPort{}, err
	}
	peer, err := read()
	if err != nil {
		return netip.AddrPort{}, err
	}
	if !peer.IsValid() {
		return netip.AddrPort{}, errors.New("WG peer readback unavailable")
	}
	if err := s.Validate(ctx, false); err != nil {
		return netip.AddrPort{}, err
	}
	return peer, nil
}
