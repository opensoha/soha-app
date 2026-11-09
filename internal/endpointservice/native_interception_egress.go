package endpointservice

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Every native socket belongs to one verified network generation. No executor
// mutex is acquired from a dial callback (controllers dial while holding theirs).
type nativeGuard struct {
	internal   map[netip.AddrPort]bool
	mu         sync.Mutex
	platform   nativePlatform
	binding    *nativeEgressBinding
	blocked    bool
	sockets    map[net.Conn]struct{}
	clients    []*http.Transport
	closeGate  func()
	leaseTimer *time.Timer
	dialSocket func(context.Context, *net.Dialer, string, string) (net.Conn, error)
	dials      uint64
}
type nativeEgressBinding struct {
	lease    *atomic.Int64
	uiLease  *atomic.Int64
	snapshot nativeSnapshot
	session  nativeSession
	wg       TunnelReadback
	until    time.Time
	dns      *nativeDNSProxy
}

func (g *nativeGuard) set(b *nativeEgressBinding, blocked bool) {
	g.mu.Lock()
	if g.leaseTimer != nil {
		g.leaseTimer.Stop()
		g.leaseTimer = nil
	}
	if b != nil {
		if b.lease == nil {
			b.lease = &atomic.Int64{}
		}
		b.lease.Store(b.until.UnixNano())
	}
	g.binding = b
	g.blocked = blocked
	if b != nil && !blocked {
		g.leaseTimer = time.AfterFunc(time.Until(nativeBindingUntil(b)), func() { g.expireLease(b) })
	}
	sockets := g.sockets
	g.sockets = map[net.Conn]struct{}{}
	clients := append([]*http.Transport(nil), g.clients...)
	closeGate := g.closeGate
	g.mu.Unlock()
	if blocked && closeGate != nil {
		closeGate()
	}
	for c := range sockets {
		_ = c.Close()
	}
	for _, c := range clients {
		c.CloseIdleConnections()
	}
}
func (g *nativeGuard) attach(client *http.Client) error {
	if client == nil {
		return nil
	}
	t, ok := client.Transport.(*http.Transport)
	if !ok {
		return errors.New("native transport must be an owned HTTP transport")
	}
	t = t.Clone()
	originalProxy := t.Proxy
	t.Proxy = func(request *http.Request) (*url.URL, error) {
		g.mu.Lock()
		native := g.binding != nil || g.blocked
		g.mu.Unlock()
		if native || originalProxy == nil {
			return nil, nil
		}
		return originalProxy(request)
	}
	t.DialContext = g.DialContext
	client.Transport = t
	g.mu.Lock()
	g.clients = append(g.clients, t)
	g.mu.Unlock()
	return nil
}
func nativeNetworkHash(s nativeSnapshot) [32]byte {
	raw, _ := json.Marshal(struct {
		Interfaces []nativeInterface
		Routes     []nativeRoute
		Resolvers  []nativeResolverScope
		Service    string
	}{s.Interfaces, s.Routes, s.Resolvers, s.PrimaryServiceID})
	return sha256.Sum256(raw)
}
func (g *nativeGuard) state(ctx context.Context) (*nativeEgressBinding, error) {
	g.mu.Lock()
	b, blocked := g.binding, g.blocked
	g.mu.Unlock()
	if blocked {
		return nil, errors.New("native egress suspended")
	}
	if b == nil {
		return nil, nil
	}
	if b.uiLease != nil && b.uiLease.Load() <= time.Now().UnixNano() {
		g.set(nil, true)
		return nil, errors.New("native UI lease expired")
	}
	if !nativeBindingUntil(b).After(time.Now()) || b.session == nil || b.session.Validate(ctx, false) != nil {
		g.set(nil, true)
		return nil, errors.New("native session or lease expired")
	}
	current, err := g.platform.Snapshot(ctx, b.session)
	if err != nil || nativeNetworkHash(current) != nativeNetworkHash(b.snapshot) {
		g.set(nil, true)
		return nil, errors.New("native network generation changed")
	}
	return b, nil
}
func (g *nativeGuard) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	b, err := g.state(ctx)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return net.DefaultResolver.LookupNetIP(ctx, network, host)
	}
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		values := []netip.Addr{}
		for endpoint := range g.internal {
			ip := endpoint.Addr()
			if network == "ip" || network == "ip4" && ip.Is4() || network == "ip6" && ip.Is6() {
				values = append(values, ip)
			}
		}
		if len(values) > 0 {
			return values, nil
		}
	}
	if b.dns == nil {
		return nil, errors.New("native resolver unavailable")
	}
	return b.dns.lookup(ctx, network, host)
}
func (g *nativeGuard) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	if ip, e := netip.ParseAddr(host); e == nil {
		ep, e := netip.ParseAddrPort(net.JoinHostPort(ip.String(), port))
		if e != nil {
			return nil, e
		}
		return g.DialPinned(ctx, network, ep)
	}
	if strings.ContainsAny(host, "/\\%") {
		return nil, errors.New("invalid native dial host")
	}
	addresses, err := g.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	var failures []error
	for _, ip := range addresses {
		if strings.HasSuffix(network, "4") && !ip.Is4() || strings.HasSuffix(network, "6") && !ip.Is6() {
			continue
		}
		endpoint, e := netip.ParseAddrPort(net.JoinHostPort(ip.String(), port))
		if e != nil {
			return nil, e
		}
		c, e := g.DialPinned(ctx, network, endpoint)
		if e == nil {
			return c, nil
		}
		failures = append(failures, e)
	}
	if len(failures) == 0 {
		return nil, errors.New("native address family unavailable")
	}
	return nil, errors.Join(failures...)
}
func (g *nativeGuard) DialPinned(ctx context.Context, network string, remote netip.AddrPort) (net.Conn, error) {
	if !remote.IsValid() || remote.Port() == 0 || remote.Addr().IsUnspecified() || remote.Addr().IsMulticast() {
		return nil, errors.New("invalid native endpoint")
	}
	b, err := g.state(ctx)
	if err != nil {
		return nil, err
	}
	if b == nil {
		c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, remote.String())
		if err != nil {
			return nil, err
		}
		g.mu.Lock()
		valid := g.binding == nil && !g.blocked
		if valid {
			if g.sockets == nil {
				g.sockets = map[net.Conn]struct{}{}
			}
			g.rememberLocked(c)
		}
		g.mu.Unlock()
		if !valid {
			c.Close()
			return nil, errors.New("native egress changed while connecting")
		}
		return c, nil
	}
	if remote.Addr().IsLoopback() {
		if !g.internal[remote] {
			return nil, errors.New("external dial cannot enter loopback")
		}
		return g.dialInternal(ctx, network, remote)
	}
	exit, err := g.platform.SelectExit(ctx, remote.Addr(), b.snapshot, b.wg)
	if err != nil {
		return nil, err
	}
	if exit.Interface.ID == "" || exit.Interface.Index == 0 || exit.Interface.Kind != "physical" && !exit.ViaWG || exit.Generation != b.snapshot.Generation {
		return nil, errors.New("ambiguous native exit")
	}
	if exit.Source.IsValid() && exit.Source.BitLen() != remote.Addr().BitLen() {
		return nil, errors.New("native exit family mismatch")
	}
	control := g.platform.Control(exit)
	if control == nil {
		return nil, errors.New("native socket binding unavailable")
	}
	if network == "tcp" || network == "udp" {
		if remote.Addr().Is4() {
			network += "4"
		} else {
			network += "6"
		}
	}
	if network != "tcp4" && network != "tcp6" && network != "udp4" && network != "udp6" {
		return nil, errors.New("unsupported native socket network")
	}
	d := net.Dialer{Timeout: 5 * time.Second, Control: control}
	dial := d.DialContext
	if g.dialSocket != nil {
		dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			return g.dialSocket(ctx, &d, network, address)
		}
	}
	c, err := dial(ctx, network, remote.String())
	if err != nil {
		return nil, err
	}
	local, localErr := netip.ParseAddrPort(c.LocalAddr().String())
	if localErr != nil || !exit.Source.IsValid() || local.Addr().WithZone("") != exit.Source.WithZone("") {
		c.Close()
		return nil, errors.New("native source changed")
	}
	actual, e := netip.ParseAddrPort(c.RemoteAddr().String())
	if e != nil || actual != remote {
		c.Close()
		return nil, errors.New("native remote changed")
	}
	g.mu.Lock()
	valid := !g.blocked && g.binding == b
	if valid {
		if g.sockets == nil {
			g.sockets = map[net.Conn]struct{}{}
		}
		g.rememberLocked(c)
	}
	g.mu.Unlock()
	if !valid {
		c.Close()
		return nil, errors.New("native generation invalidated")
	}
	return c, nil
}
func nativeLookup(c MihomoConfiguration) func(context.Context, string, string) ([]netip.Addr, error) {
	if c.Egress != nil {
		return c.Egress.LookupNetIP
	}
	return net.DefaultResolver.LookupNetIP
}
func nativeDial(c MihomoConfiguration, ctx context.Context, network, address string) (net.Conn, error) {
	if c.Egress != nil {
		return c.Egress.DialContext(ctx, network, address)
	}
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
}
func nativeSnapshotEqual(a, b nativeSnapshot) bool {
	return reflect.DeepEqual(a.Interfaces, b.Interfaces) && reflect.DeepEqual(a.Routes, b.Routes)
}

func nativeEgressReady(ctx context.Context, c MihomoConfiguration) error {
	if guard, ok := c.Egress.(*nativeGuard); ok {
		_, err := guard.state(ctx)
		return err
	}
	return nil
}

func (g *nativeGuard) rememberLocked(c net.Conn) {
	if g.sockets == nil {
		g.sockets = map[net.Conn]struct{}{}
	}
	g.sockets[c] = struct{}{}
	g.dials++
	// Preserve concrete UDP sockets for the contracts callback. Periodically drop
	// closed descriptors, without wrapping them or shortening inactive-mode leases.
	if g.dials%64 == 0 {
		for conn := range g.sockets {
			if raw, ok := conn.(syscall.Conn); ok {
				control, err := raw.SyscallConn()
				if err != nil {
					delete(g.sockets, conn)
					continue
				}
				if err = control.Control(func(uintptr) {}); err != nil {
					delete(g.sockets, conn)
				}
			}
		}
	}
}

// Only validated control/ingest origins and signed projection transports call
// this path. Business destinations still pass Scope and cannot enter loopback.
func (g *nativeGuard) dialInternal(ctx context.Context, network string, endpoint netip.AddrPort) (net.Conn, error) {
	b, err := g.state(ctx)
	if err != nil {
		return nil, err
	}
	if !endpoint.Addr().IsLoopback() {
		return nil, errors.New("internal endpoint must be literal loopback")
	}
	c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, endpoint.String())
	if err != nil {
		return nil, err
	}
	actual, e := netip.ParseAddrPort(c.RemoteAddr().String())
	if e != nil || actual != endpoint {
		c.Close()
		return nil, errors.New("internal endpoint changed")
	}
	g.mu.Lock()
	valid := !g.blocked && g.binding == b
	if valid {
		g.rememberLocked(c)
	}
	g.mu.Unlock()
	if !valid {
		c.Close()
		return nil, errors.New("native internal generation changed")
	}
	return c, nil
}

func (g *nativeGuard) expireUIScope(lease *atomic.Int64) {
	g.mu.Lock()
	if g.binding == nil || g.binding.uiLease != lease || lease.Load() > time.Now().UnixNano() {
		g.mu.Unlock()
		return
	}
	g.binding = nil
	g.blocked = true
	if g.leaseTimer != nil {
		g.leaseTimer.Stop()
		g.leaseTimer = nil
	}
	sockets := g.sockets
	g.sockets = map[net.Conn]struct{}{}
	closeGate := g.closeGate
	clients := append([]*http.Transport(nil), g.clients...)
	g.mu.Unlock()
	if closeGate != nil {
		closeGate()
	}
	for c := range sockets {
		c.Close()
	}
	for _, t := range clients {
		t.CloseIdleConnections()
	}
}

func nativeBindingUntil(b *nativeEgressBinding) time.Time {
	if b.lease != nil {
		return time.Unix(0, b.lease.Load())
	}
	return b.until
}
func (g *nativeGuard) renewLease(ctx context.Context, expected *nativeEgressBinding, until time.Time) error {
	current, err := g.state(ctx)
	if err != nil {
		return err
	}
	if current != expected {
		return errors.New("native binding changed during renewal")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if g.blocked || expected == nil || g.binding != expected || !nativeBindingUntil(expected).After(now) || !until.After(now) || expected.uiLease != nil && expected.uiLease.Load() <= now.UnixNano() {
		return errors.New("native lease cannot be revived")
	}
	expected.lease.Store(until.UnixNano())
	if g.leaseTimer != nil {
		g.leaseTimer.Stop()
	}
	g.leaseTimer = time.AfterFunc(time.Until(until), func() { g.expireLease(expected) })
	return nil
}

// One timer follows the current verified binding lease, including shorter
// renewals. Per-connection grant/certificate deadlines remain independently set.
func (g *nativeGuard) expireLease(expected *nativeEgressBinding) {
	g.mu.Lock()
	if g.binding != expected || g.blocked || nativeBindingUntil(expected).After(time.Now()) {
		g.mu.Unlock()
		return
	}
	g.binding = nil
	g.blocked = true
	g.leaseTimer = nil
	sockets := g.sockets
	g.sockets = map[net.Conn]struct{}{}
	clients := append([]*http.Transport(nil), g.clients...)
	closeGate := g.closeGate
	g.mu.Unlock()
	if closeGate != nil {
		closeGate()
	}
	for c := range sockets {
		c.Close()
	}
	for _, t := range clients {
		t.CloseIdleConnections()
	}
}
