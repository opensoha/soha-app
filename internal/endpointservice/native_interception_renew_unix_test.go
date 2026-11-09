//go:build !windows

package endpointservice

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type nativeRenewPlatform struct{ *nativeTestPlatform }

func (p nativeRenewPlatform) SelectExit(_ context.Context, ip netip.Addr, s nativeSnapshot, _ TunnelReadback) (nativeExit, error) {
	return nativeExit{Interface: s.Interfaces[0], Source: netip.MustParseAddr("192.0.2.2"), Generation: s.Generation}, nil
}
func (p nativeRenewPlatform) Control(nativeExit) func(string, string, syscall.RawConn) error {
	return func(string, string, syscall.RawConn) error { return nil }
}

type nativeRenewAddress string

func (a nativeRenewAddress) Network() string { return "fixture" }
func (a nativeRenewAddress) String() string  { return string(a) }

type nativeRenewConn struct {
	net.Conn
	target string
}

func (c *nativeRenewConn) LocalAddr() net.Addr  { return nativeRenewAddress("192.0.2.2:24000") }
func (c *nativeRenewConn) RemoteAddr() net.Addr { return nativeRenewAddress(c.target) }

func nativeRenewEcho(t *testing.T, network string) string {
	t.Helper()
	if network == "tcp4" {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() { defer c.Close(); io.Copy(c, c) }()
			}
		}()
		return l.Addr().String()
	}
	l, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		buf := make([]byte, 64)
		for {
			n, a, err := l.ReadFrom(buf)
			if err != nil {
				return
			}
			l.WriteTo(buf[:n], a)
		}
	}()
	return l.LocalAddr().String()
}
func nativeRenewPing(c net.Conn) error {
	if err := c.SetDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		return err
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		return err
	}
	buf := make([]byte, 4)
	_, err := io.ReadFull(c, buf)
	if err == nil && string(buf) != "ping" {
		return fmt.Errorf("unexpected echo")
	}
	return err
}
func nativeRenewFixture(t *testing.T) (*CoordinatedExecutor, *nativeGuard, MihomoConfiguration, time.Time, []net.Conn) {
	t.Helper()
	now := time.Now()
	configuration, p := bundleFixture(now)
	configuration.Projection = &p
	secret := strings.Repeat("n", 32)
	server, _ := newMihomoControllerFixture(t, secret)
	controller, err := NewMihomoController(server.URL, secret)
	if err != nil {
		t.Fatal(err)
	}
	configuration.ControllerPort = controller.port
	e, platform, peer := nativeTestExecutor(t)
	e.mihomo = controller
	e.wireGuard = &fakeConfigurationExecutor{outcome: ApplyOutcome{Status: "applied"}}
	e.appStatePath = filepath.Join(t.TempDir(), "app")
	if out := e.Apply(context.Background(), ConfigurationDesired{PolicyVersion: 1, ValidUntil: configuration.EnforcementUntil, Mihomo: &configuration}, now); out.Status != "applied" {
		t.Fatal(out)
	}
	t.Cleanup(func() { e.Disable(context.Background()) })
	n := e.native
	n.session = peer.session
	base := cloneMihomoConfiguration(e.previousMihomo.Configuration)
	n.base = &base
	n.journal.Binding = nativeBindingHash(n.identity, base)
	n.uiExpectedUser = p.Credential.UserID
	n.uiScope.UserID = p.Credential.UserID
	n.journal.UIBindingHash = nativeUIScopeBinding(n.uiScope)
	guard := n.guard
	guard.platform = nativeRenewPlatform{platform}
	oldUntil := time.Now().Add(800 * time.Millisecond)
	guard.set(&nativeEgressBinding{snapshot: platform.snap, session: n.session, until: oldUntil, uiLease: &n.uiLease}, false)
	tcp, udp := nativeRenewEcho(t, "tcp4"), nativeRenewEcho(t, "udp4")
	guard.dialSocket = func(ctx context.Context, _ *net.Dialer, network, target string) (net.Conn, error) {
		endpoint := tcp
		if strings.HasPrefix(network, "udp") {
			endpoint = udp
		}
		c, err := (&net.Dialer{}).DialContext(ctx, network, endpoint)
		if err != nil {
			return nil, err
		}
		return &nativeRenewConn{Conn: c, target: target}, nil
	}
	sockets := []net.Conn{}
	for _, network := range []string{"tcp", "udp"} {
		c, err := nativeDial(MihomoConfiguration{Egress: guard}, context.Background(), network, "192.0.2.40:443")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		if err = nativeRenewPing(c); err != nil {
			t.Fatal(err)
		}
		sockets = append(sockets, c)
	}
	return e, guard, configuration, oldUntil, sockets
}
func TestNativeInterceptionRenewProjectionPreservesSocketAndTimer(t *testing.T) {
	e, _, next, oldUntil, sockets := nativeRenewFixture(t)
	until := time.Now().Add(1600 * time.Millisecond)
	next.Projection.Credential.ExpiresAt = until
	renewed, err := e.RenewProjection(context.Background(), ConfigurationDesired{ValidUntil: until, Mihomo: &next}, time.Now())
	if err != nil || !renewed {
		t.Fatal(renewed, err)
	}
	for i, c := range sockets {
		if err := nativeRenewPing(c); err != nil {
			t.Fatalf("socket%d immediately after RenewProjection: %v", i, err)
		}
	}
	time.Sleep(time.Until(oldUntil.Add(60 * time.Millisecond)))
	for i, c := range sockets {
		if err := nativeRenewPing(c); err != nil {
			t.Fatalf("socket%d after old timer: %v", i, err)
		}
	}
	time.Sleep(time.Until(until.Add(60 * time.Millisecond)))
	for i, c := range sockets {
		if err := nativeRenewPing(c); err == nil {
			t.Fatalf("socket%d survived renewed hard cap", i)
		}
	}
}

func TestNativeInterceptionRenewProjectionShorterLeaseAndNoRevival(t *testing.T) {
	e, g, next, oldUntil, sockets := nativeRenewFixture(t)
	until := time.Now().Add(200 * time.Millisecond)
	next.Projection.Credential.ExpiresAt = until
	if renewed, err := e.RenewProjection(context.Background(), ConfigurationDesired{ValidUntil: until, Mihomo: &next}, time.Now()); err != nil || !renewed {
		t.Fatal(renewed, err)
	}
	time.Sleep(time.Until(until.Add(50 * time.Millisecond)))
	if !time.Now().Before(oldUntil) {
		t.Fatal("fixture missed shorter-bound window")
	}
	for i, c := range sockets {
		if err := nativeRenewPing(c); err == nil {
			t.Fatalf("socket%d ignored shorter lease", i)
		}
	}
	next.Projection.Credential.ExpiresAt = time.Now().Add(time.Minute)
	if renewed, _ := e.RenewProjection(context.Background(), ConfigurationDesired{ValidUntil: next.Projection.Credential.ExpiresAt, Mihomo: &next}, time.Now()); renewed {
		t.Fatal("expired native renewed")
	}
	if _, err := g.DialPinned(context.Background(), "tcp", netip.MustParseAddrPort("192.0.2.40:443")); err == nil {
		t.Fatal("expired native revived")
	}
}
func TestNativeInterceptionRenewProjectionPreservesOriginalFlowDeadline(t *testing.T) {
	e, _, next, _, sockets := nativeRenewFixture(t)
	hardCap := time.Now().Add(150 * time.Millisecond)
	flow := &projectionConnection{Conn: sockets[0], reader: bufio.NewReader(sockets[0]), validUntil: hardCap}
	next.Projection.Credential.ExpiresAt = time.Now().Add(time.Minute)
	if renewed, err := e.RenewProjection(context.Background(), ConfigurationDesired{ValidUntil: next.Projection.Credential.ExpiresAt, Mihomo: &next}, time.Now()); err != nil || !renewed {
		t.Fatal(renewed, err)
	}
	if err := flow.SetDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := flow.Read(make([]byte, 1)); err == nil || time.Now().Before(hardCap) {
		t.Fatal("original grant deadline extended", err)
	}
}
func TestNativeInterceptionRenewProjectionRejectsBlockedExpiredOrChangedBinding(t *testing.T) {
	for _, kind := range []string{"blocked", "expired", "ui-expired", "network", "session", "credential", "secret", "principal", "drift"} {
		t.Run(kind, func(t *testing.T) {
			e, g, next, _, sockets := nativeRenewFixture(t)
			next.Projection.Credential.ExpiresAt = time.Now().Add(time.Minute)
			switch kind {
			case "blocked":
				g.set(nil, true)
			case "expired":
				g.mu.Lock()
				g.binding.lease.Store(time.Now().Add(-time.Second).UnixNano())
				g.mu.Unlock()
			case "ui-expired":
				e.native.uiLease.Store(time.Now().Add(-time.Second).UnixNano())
			case "network":
				p := g.platform.(nativeRenewPlatform).nativeTestPlatform
				p.snap.PrimaryServiceID = "new-service"
			case "session":
				e.native.session.(*nativeTestSession).stale = true
			case "credential":
				next.Projection.CredentialEpoch++
				next.Projection.Credential.CredentialEpoch++
			case "secret":
				next.Projection.Credential.Secret += "changed"
			case "principal":
				next.Projection.Credential.UserID = "other-core-user"
			case "drift":
				controller := e.mihomo.(*MihomoController)
				if err := controller.request(context.Background(), "PATCH", "/configs", []byte(`{"mixed-port":1}`), 204, nil); err != nil {
					t.Fatal(err)
				}
			}
			if renewed, _ := e.RenewProjection(context.Background(), ConfigurationDesired{ValidUntil: next.Projection.Credential.ExpiresAt, Mihomo: &next}, time.Now()); renewed {
				t.Fatal("invalid binding renewed")
			}
			for i, c := range sockets {
				if err := nativeRenewPing(c); err == nil {
					t.Fatalf("socket%d survived %s", i, kind)
				}
			}
		})
	}
}
