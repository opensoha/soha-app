//go:build darwin && cgo

package endpointservice

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func nativeDarwinFixture() (*darwinNativePlatform, *darwinNativeSession) {
	p := &darwinNativePlatform{uid: 501, presence: &UIProcessPresence{verify: func(net.Conn) error { return nil }}}
	p.calls.console = func(u, a uint32) error {
		if u != 501 || a != 77 {
			return errDarwinNative
		}
		return nil
	}
	token := [8]uint32{501, 501, 20, 501, 20, 123, 77, 9}
	p.calls.peer = func(net.Conn) ([8]uint32, error) { return token, nil }
	p.calls.code = func(v [8]uint32) error {
		if v != token {
			return errDarwinNative
		}
		return nil
	}
	return p, &darwinNativeSession{platform: p, token: token, owner: nativeOwner{UserID: "501", SessionID: "77"}}
}
func TestDarwinNativeAuthentication(t *testing.T) {
	ctx := context.Background()
	for _, which := range []string{"valid", "uid", "asid", "pidversion", "tokenchanged", "presence"} {
		t.Run(which, func(t *testing.T) {
			p, _ := nativeDarwinFixture()
			base, _ := p.calls.peer(nil)
			switch which {
			case "uid":
				base[1] = 502
			case "asid":
				base[6] = 78
			case "pidversion":
				base[7]++
			case "presence":
				p.presence.verify = func(net.Conn) error { return errDarwinNative }
			}
			n := 0
			p.calls.peer = func(net.Conn) ([8]uint32, error) {
				n++
				v := base
				if which == "tokenchanged" && n > 1 {
					v[7]++
				}
				return v, nil
			}
			peer, err := p.Authenticate(ctx, nil)
			if which == "valid" {
				if err != nil || peer.pid != 123 || peer.owner.SessionID != "77" {
					t.Fatalf("valid peer: %v", err)
				}
			} else if err == nil {
				t.Fatal("accepted invalid peer")
			}
		})
	}
	// The production transport helper refuses objects which cannot provide an OS Unix FD.
	if _, err := darwinNativePeer(nil); err == nil {
		t.Fatal("accepted non-Unix peer")
	}
}
func TestDarwinNativeRestoreOnly(t *testing.T) {
	p, s := nativeDarwinFixture()
	ctx := context.Background()
	p.calls.console = func(uint32, uint32) error { return errors.New("console switched") }
	p.calls.code = func([8]uint32) error { return errors.New("UI exited") }
	if s.Validate(ctx, false) == nil || s.Validate(ctx, true) != nil {
		t.Fatal("wrong active/restore session semantics")
	}
	restore, err := p.AcquireRestoreSession(ctx, s.Owner())
	if err != nil {
		t.Fatal(err)
	}
	if restore.Validate(ctx, false) == nil || restore.Validate(ctx, true) != nil {
		t.Fatal("restore handle gained apply authority")
	}
	if _, err = p.AcquireRestoreSession(ctx, nativeOwner{UserID: "502", SessionID: "77"}); err == nil {
		t.Fatal("foreign owner accepted")
	}
	restore.Close()
	if restore.Validate(ctx, true) == nil {
		t.Fatal("closed handle accepted")
	}
}
func TestDarwinNativeSettingsCAS(t *testing.T) {
	for _, kind := range []string{"proxy", "dns"} {
		t.Run(kind, func(t *testing.T) {
			p, s := nativeDarwinFixture()
			ctx := context.Background()
			raw := json.RawMessage("null")
			writes := 0
			p.calls.read = func(string, string, string) (json.RawMessage, error) { return raw, nil }
			p.calls.cas = func(_, _, _ string, b, a json.RawMessage) (string, error) {
				writes++
				if string(raw) != string(b) {
					return "conflict", errDarwinNative
				}
				raw = a
				return "applied", nil
			}
			c := nativeChange{ID: "test", Kind: kind, Scope: nativeScope{ServiceID: "stable-old-service"}, Field: "HTTPEnable", After: nativeValue{Present: true, Proxy: &nativeProxyValue{Bool: true}}}
			if kind == "dns" {
				c.Field = ""
				c.Before = nativeValue{DNS: &nativeDNSConfig{Automatic: true}}
				c.After = nativeValue{Present: true, DNS: &nativeDNSConfig{Servers: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}}
			}
			receipt, err := p.CompareApply(ctx, s, c)
			if err != nil || receipt.Outcome != "applied" {
				t.Fatalf("apply %s: %v", receipt.Outcome, err)
			}
			restore, _ := p.AcquireRestoreSession(ctx, s.Owner())
			receipt, err = p.CompareRestore(ctx, restore, c)
			if err != nil || receipt.Outcome != "applied" || string(raw) != "null" {
				t.Fatalf("restore automatic/absent: %s %v", receipt.Outcome, err)
			}
			raw = json.RawMessage("0")
			if kind == "dns" {
				raw = json.RawMessage(`["192.0.2.53"]`)
			}
			previous := string(raw)
			writes = 0
			receipt, err = p.CompareRestore(ctx, restore, c)
			if err == nil || receipt.Outcome != "conflict" || writes != 0 || string(raw) != previous {
				t.Fatal("external value overwritten")
			}
		})
	}
}
func TestDarwinNativeUnknownReceipt(t *testing.T) {
	p, s := nativeDarwinFixture()
	p.calls.read = func(string, string, string) (json.RawMessage, error) { return json.RawMessage("null"), nil }
	calls := 0
	p.calls.cas = func(string, string, string, json.RawMessage, json.RawMessage) (string, error) {
		calls++
		return "unknown", errors.New("commit acknowledgement lost")
	}
	c := nativeChange{Kind: "proxy", Field: "HTTPEnable", Scope: nativeScope{ServiceID: "stable"}, After: nativeValue{Present: true, Proxy: &nativeProxyValue{Bool: true}}}
	r, err := p.CompareApply(context.Background(), s, c)
	if err == nil || r.Outcome != "unknown" || calls != 1 {
		t.Fatal("unknown write was replayed or hidden")
	}
}
func TestDarwinNativeControlFailure(t *testing.T) {
	p, _ := nativeDarwinFixture()
	iface := nativeInterface{ID: "incarnation", Name: "en0", Index: 7, Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")}}
	e := nativeExit{Interface: iface, Source: iface.Addresses[0].Addr(), Gateway: netip.MustParseAddr("192.0.2.1")}
	p.calls.interfaces = func() ([]nativeInterface, error) { return []nativeInterface{iface}, nil }
	p.calls.lookup = func(netip.Addr, nativeInterface) (nativeRoute, error) {
		return nativeRoute{Interface: iface, Gateway: e.Gateway, Flags: 1}, nil
	}
	e.Route, _ = p.calls.lookup(netip.MustParseAddr("198.51.100.1"), iface)
	p.calls.bind = func(syscall.RawConn, uint32, netip.Addr) error { return errors.New("IP_BOUND_IF denied") }
	if p.Control(e)("tcp4", "198.51.100.1:443", nil) == nil {
		t.Fatal("binding failure fell back")
	}
	iface.ID = "reused-index"
	if p.verifyExit(netip.MustParseAddr("198.51.100.1"), e) == nil {
		t.Fatal("reused interface accepted")
	}
}
func TestDarwinNativeRouteConflict(t *testing.T) {
	p, s := nativeDarwinFixture()
	iface := nativeInterface{ID: "old", Name: "utun10", Index: 10}
	wanted := nativeRoute{Destination: netip.MustParsePrefix("0.0.0.0/1"), Interface: iface, Flags: 1}
	actual := wanted
	actual.Gateway = netip.MustParseAddr("192.0.2.1")
	p.calls.interfaces = func() ([]nativeInterface, error) { return []nativeInterface{iface}, nil }
	p.calls.routes = func([]nativeInterface) ([]nativeRoute, error) { return []nativeRoute{actual}, nil }
	calls := 0
	p.calls.routeWrite = func(nativeRoute, bool) error { calls++; return nil }
	c := nativeChange{Kind: "route", Scope: nativeScope{Interface: iface}, After: nativeValue{Present: true, Route: &wanted}}
	r, err := p.CompareRestore(context.Background(), s, c)
	if err == nil || r.Outcome != "conflict" || calls != 0 || !reflect.DeepEqual(r.Current.Route, &actual) {
		t.Fatal("replaced route was removed")
	}
}

func TestDarwinNativeSnapshotBoundary(t *testing.T) {
	p, s := nativeDarwinFixture()
	ctx := context.Background()
	iface := nativeInterface{ID: "physical-incarnation", Name: "en0", Index: 3, Kind: "physical", Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")}}
	p.calls.interfaces = func() ([]nativeInterface, error) { return []nativeInterface{iface}, nil }
	p.calls.routes = func([]nativeInterface) ([]nativeRoute, error) { return nil, nil }
	p.calls.read = func(string, string, string) (json.RawMessage, error) { return json.RawMessage("null"), nil }
	p.calls.network = func() (darwinNativeNetwork, error) {
		var n darwinNativeNetwork
		err := json.Unmarshal([]byte(`{"IPv4":"service-a","IPv6":"service-a","Services":[{"ID":"service-a","Name":"Synthetic","Interface":"en0","Type":"Ethernet"}],"Resolvers":[{"ID":"State:/Network/Service/service-a/DNS","Value":{"ServerAddresses":["192.0.2.53"],"SearchOrder":200000}}]}`), &n)
		return n, err
	}
	snapshot, err := p.Snapshot(ctx, s)
	if err != nil || snapshot.PrimaryServiceID != "service-a" || snapshot.Generation == 0 || len(snapshot.Resolvers) != 1 || snapshot.Resolvers[0].Interface.ID != iface.ID {
		t.Fatalf("snapshot scope: %v", err)
	}
	if snapshot.Settings[8].Before.DNS == nil || !snapshot.Settings[8].Before.DNS.Automatic {
		t.Fatal("automatic DNS baseline missing")
	}
	p.calls.console = func(uint32, uint32) error { return errDarwinNative }
	if _, err = p.Snapshot(ctx, s); err == nil {
		t.Fatal("stale console snapshot accepted")
	}
}
func TestDarwinNativeRouteWriteReceipts(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(strconv.FormatBool(failure), func(t *testing.T) {
			p, s := nativeDarwinFixture()
			iface := nativeInterface{ID: "incarnation", Name: "utun7", Index: 7}
			wanted := nativeRoute{Destination: netip.MustParsePrefix("8000::/1"), Interface: iface, Flags: 1}
			var routes []nativeRoute
			p.calls.interfaces = func() ([]nativeInterface, error) { return []nativeInterface{iface}, nil }
			p.calls.routes = func([]nativeInterface) ([]nativeRoute, error) { return routes, nil }
			calls := 0
			p.calls.routeWrite = func(r nativeRoute, add bool) error {
				calls++
				if failure {
					return syscall.EPERM
				}
				if add {
					routes = []nativeRoute{r}
				} else {
					routes = nil
				}
				return nil
			}
			c := nativeChange{Kind: "route", Scope: nativeScope{Interface: iface}, After: nativeValue{Present: true, Route: &wanted}}
			r, err := p.CompareApply(context.Background(), s, c)
			if failure {
				if err == nil || r.Outcome != "not_applied" || calls != 1 {
					t.Fatal("known refusal receipt lost")
				}
				return
			}
			if err != nil || r.Outcome != "applied" {
				t.Fatalf("route add: %v", err)
			}
			r, err = p.CompareRestore(context.Background(), s, c)
			if err != nil || r.Outcome != "applied" || len(routes) != 0 {
				t.Fatalf("route delete: %v", err)
			}
		})
	}
}

func TestDarwinNativeListenerOwner(t *testing.T) {
	p, s := nativeDarwinFixture()
	ctx := context.Background()
	endpoint := netip.MustParseAddrPort("127.0.0.1:53")
	calls := 0
	p.calls.listener = func(network string, e netip.AddrPort, pid uint32) error {
		calls++
		if network != "tcp" || e != endpoint || pid != 123 {
			return errDarwinNative
		}
		return nil
	}
	if err := p.VerifyListenerOwner(ctx, s, "tcp", endpoint, 123); err != nil || calls != 1 {
		t.Fatalf("owned listener: %v", err)
	}
	for _, e := range []string{"0.0.0.0:53", "192.0.2.1:53", "[::]:53"} {
		if err := p.VerifyListenerOwner(ctx, s, "tcp", netip.MustParseAddrPort(e), 123); err == nil {
			t.Fatal("non-loopback listener accepted")
		}
	}
	if err := p.VerifyListenerOwner(ctx, s, "tcp", endpoint, 999); err == nil {
		t.Fatal("foreign PID accepted")
	}
	p.calls.listener = func(string, netip.AddrPort, uint32) error { return errors.New("metadata unavailable") }
	if err := p.VerifyListenerOwner(ctx, s, "udp", endpoint, 123); err == nil {
		t.Fatal("metadata failure accepted")
	}
	restore, _ := p.AcquireRestoreSession(ctx, s.Owner())
	if err := p.VerifyListenerOwner(ctx, restore, "tcp", endpoint, 123); err == nil {
		t.Fatal("restore-only session authorized listener")
	}
}

func TestDarwinNativeFlushFixedCommands(t *testing.T) {
	p, s := nativeDarwinFixture()
	ctx := context.Background()
	var commands [][]string
	p.calls.flushCommand = func(ctx context.Context, path string, args ...string) error {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 5*time.Second {
			t.Fatal("cache request has no fixed deadline")
		}
		commands = append(commands, append([]string{path}, args...))
		return nil
	}
	restore, _ := p.AcquireRestoreSession(ctx, s.Owner())
	if err := p.FlushResolverCache(ctx, restore); err != nil {
		t.Fatal(err)
	}
	expected := [][]string{{"/usr/bin/dscacheutil", "-flushcache"}, {"/bin/launchctl", "kill", "SIGHUP", "system/com.apple.mDNSResponder"}}
	if !reflect.DeepEqual(commands, expected) {
		t.Fatalf("commands: %v", commands)
	}
	for _, failure := range []error{errors.New("sensitive child output"), context.DeadlineExceeded} {
		commands = nil
		p.calls.flushCommand = func(context.Context, string, ...string) error { commands = append(commands, nil); return failure }
		err := p.FlushResolverCache(ctx, restore)
		if err == nil || strings.Contains(err.Error(), "sensitive") || len(commands) != 1 {
			t.Fatal("cache request failure retried or exposed output")
		}
	}
	calls := 0
	p.calls.flushCommand = func(context.Context, string, ...string) error { calls++; return nil }
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if p.FlushResolverCache(cancelled, restore) == nil || calls != 0 {
		t.Fatal("cancelled cache request executed")
	}
	restore.Close()
	if p.FlushResolverCache(ctx, restore) == nil || calls != 0 {
		t.Fatal("closed restore session ran cache commands")
	}
}
