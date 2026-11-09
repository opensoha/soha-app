package endpointservice

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"
)

type nativeTestSession struct {
	owner  nativeOwner
	stale  bool
	closed bool
}

func (s *nativeTestSession) Owner() nativeOwner { return s.owner }
func (s *nativeTestSession) Validate(_ context.Context, restore bool) error {
	if s.stale && !restore {
		return errors.New("stale session")
	}
	return nil
}
func (s *nativeTestSession) Close() error { s.closed = true; return nil }

type nativeTestPlatform struct {
	mu               sync.Mutex
	value            nativeValue
	writes, restores int
	unknown          bool
	cancel           context.CancelFunc
	authErr          error
	snap             nativeSnapshot
}

func (p *nativeTestPlatform) Authenticate(context.Context, net.Conn) (NativePeer, error) {
	return NativePeer{}, p.authErr
}
func (p *nativeTestPlatform) AcquireRestoreSession(_ context.Context, o nativeOwner) (nativeSession, error) {
	return &nativeTestSession{owner: o}, nil
}
func (p *nativeTestPlatform) Snapshot(context.Context, nativeSession) (nativeSnapshot, error) {
	return p.snap, nil
}
func (p *nativeTestPlatform) PlanChanges(nativeSnapshot, nativeInterceptionPlan) ([]nativeChange, error) {
	return []nativeChange{{ID: "proxy-flags", Kind: "proxy", Field: "flags", Before: nativeValue{}, After: nativeValue{Present: true, Proxy: &nativeProxyValue{Number: 1}}}}, nil
}
func (p *nativeTestPlatform) ReadChange(context.Context, nativeSession, nativeChange) (nativeValue, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.value, nil
}
func (p *nativeTestPlatform) CompareApply(_ context.Context, _ nativeSession, c nativeChange) (nativeReceipt, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !nativeValuesEqual(p.value, c.Before) {
		return nativeReceipt{ChangeID: c.ID, Outcome: "conflict", Current: p.value}, errors.New("conflict")
	}
	p.value = c.After
	p.writes++
	if p.cancel != nil {
		p.cancel()
	}
	if p.unknown {
		return nativeReceipt{ChangeID: c.ID, Outcome: "unknown"}, errors.New("lost receipt")
	}
	return nativeReceipt{ChangeID: c.ID, Outcome: "applied", Current: p.value}, nil
}
func (p *nativeTestPlatform) CompareRestore(ctx context.Context, _ nativeSession, c nativeChange) (nativeReceipt, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ctx.Err() != nil {
		return nativeReceipt{}, ctx.Err()
	}
	if !nativeValuesEqual(p.value, c.After) {
		return nativeReceipt{ChangeID: c.ID, Outcome: "conflict", Current: p.value}, errors.New("conflict")
	}
	p.value = c.Before
	p.restores++
	return nativeReceipt{ChangeID: c.ID, Outcome: "applied", Current: p.value}, nil
}
func (p *nativeTestPlatform) SelectExit(context.Context, netip.Addr, nativeSnapshot, TunnelReadback) (nativeExit, error) {
	return nativeExit{}, errors.New("test forbids non-loopback network")
}
func (p *nativeTestPlatform) Control(nativeExit) func(string, string, syscall.RawConn) error {
	return nil
}
func (p *nativeTestPlatform) VerifyListenerOwner(context.Context, nativeSession, string, netip.AddrPort, uint32) error {
	return nil
}

type nativeTestEngine struct {
	configuration     MihomoConfiguration
	applies, disabled int
}

func (r *nativeTestEngine) Apply(_ context.Context, c MihomoConfiguration) (MihomoReadback, error) {
	r.configuration = c
	r.applies++
	return expectedMihomoReadback(c), nil
}
func (r *nativeTestEngine) Disable(context.Context) error { r.disabled++; return nil }
func (r *nativeTestEngine) Verify(_ context.Context, c *MihomoConfiguration) error {
	if c == nil || !reflect.DeepEqual(c.NativePlan, r.configuration.NativePlan) {
		return errors.New("native drift")
	}
	return nil
}
func nativeTestExecutor(t *testing.T) (*CoordinatedExecutor, *nativeTestPlatform, NativePeer) {
	t.Helper()
	iface := nativeInterface{ID: "physical-a", Name: "en0", Index: 1, Kind: "physical", Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")}}
	p := &nativeTestPlatform{snap: nativeSnapshot{Generation: 1, Interfaces: []nativeInterface{iface}, Routes: []nativeRoute{{Destination: netip.MustParsePrefix("0.0.0.0/0"), Interface: iface, Gateway: netip.MustParseAddr("192.0.2.1")}}, Resolvers: []nativeResolverScope{{ID: "physical-dns", Default: true, Servers: []netip.Addr{netip.MustParseAddr("192.0.2.53")}, Interface: iface}}}}
	c := MihomoConfiguration{Mode: "managed_follow", ProfileID: "profile-a", MixedPort: 12345, DNSMode: "disabled", EnforcementUntil: time.Now().Add(time.Minute), Protection: &MihomoProtection{PolicyVersion: 1}}
	r := &nativeTestEngine{configuration: c}
	e := &CoordinatedExecutor{mihomo: r, mihomoActive: true, previousMihomo: &mihomoAppliedState{Configuration: c}}
	n := &nativeInterception{platform: p, path: filepath.Join(t.TempDir(), "private", "journal"), journal: nativeJournal{Version: 1}, guard: &nativeGuard{platform: p}, identity: "server-device-a", status: InterceptionStatus{State: interceptionInactive, ObservedAt: time.Now(), Capabilities: InterceptionCapabilities{SystemProxy: true, TUN: true}}}
	e.native = n
	owner := nativeOwner{UserID: "501", SessionID: "session-a"}
	n.uiExpectedServer = "https://control.example.test"
	n.uiExpectedUser = "core-user-a"
	n.uiScope = NativeUIScope{ServerURL: n.uiExpectedServer, UserID: n.uiExpectedUser, Epoch: "fixture-native-host-epoch", Generation: 1, Authenticated: true}
	n.uiPeerPID = 42
	n.uiOwner = owner
	n.uiLease.Store(time.Now().Add(nativeUIScopeTTL).UnixNano())

	peer := NativePeer{owner: owner, pid: 42, session: &nativeTestSession{owner: owner}}
	t.Cleanup(func() { e.mu.Lock(); _ = e.restoreNativeLocked(context.Background(), false); e.mu.Unlock() })
	return e, p, peer
}
func TestNativeInterceptionExplicitIntentAndIdempotency(t *testing.T) {
	e, p, peer := nativeTestExecutor(t)
	intent := InterceptionIntent{RequestID: "enable-a", SystemProxy: true}
	status, err := e.SetInterception(context.Background(), peer, intent)
	if err != nil || status.State != interceptionActive || !status.SystemProxy || status.TUN || status.Generation != 1 {
		t.Fatalf("enable: %+v %v", status, err)
	}
	_, err = e.SetInterception(context.Background(), NativePeer{owner: peer.owner, pid: peer.pid, session: &nativeTestSession{owner: peer.owner}}, intent)
	if err != nil || p.writes != 1 {
		t.Fatal("same request was replayed", err)
	}
	intent.TUN = true
	if _, err = e.SetInterception(context.Background(), peer, intent); err == nil {
		t.Fatal("changed request ID accepted")
	}
	stop := InterceptionIntent{RequestID: "stop-a", ExpectedGeneration: 1}
	status, err = e.SetInterception(context.Background(), peer, stop)
	if err != nil || status.State != interceptionInactive || p.restores != 1 {
		t.Fatal(status, err)
	}
	j, err := loadNativeJournal(e.native.path)
	if err != nil || j.Pending || j.Request.SystemProxy || j.Request.TUN || j.Generation != 2 {
		t.Fatal("stop was not durable", j, err)
	}
}
func TestNativeInterceptionRejectsMissingOrStaleNativePeer(t *testing.T) {
	for _, kind := range []string{"missing", "wrong-owner", "stale"} {
		t.Run(kind, func(t *testing.T) {
			e, p, peer := nativeTestExecutor(t)
			switch kind {
			case "missing":
				peer.session = nil
			case "wrong-owner":
				peer.owner.UserID = "other"
			case "stale":
				peer.session.(*nativeTestSession).stale = true
			}
			if _, err := e.SetInterception(context.Background(), peer, InterceptionIntent{RequestID: "enable", SystemProxy: true}); err == nil || p.writes != 0 {
				t.Fatal("untrusted session wrote OS state")
			}
		})
	}
}
func TestNativeInterceptionUnknownWriteAndCancellationRestore(t *testing.T) {
	for _, kind := range []string{"lost-receipt", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			e, p, peer := nativeTestExecutor(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancel" {
				p.cancel = cancel
			} else {
				p.unknown = true
			}
			status, err := e.SetInterception(ctx, peer, InterceptionIntent{RequestID: "enable", SystemProxy: true})
			if err == nil || status.CleanupPending || p.writes != 1 || p.restores != 1 || p.value.Present {
				t.Fatal("partial write was not restored", status, err, p.writes, p.restores)
			}
		})
	}
}
func TestNativeInterceptionExternalChangeIsPreserved(t *testing.T) {
	e, p, peer := nativeTestExecutor(t)
	_, err := e.SetInterception(context.Background(), peer, InterceptionIntent{RequestID: "enable", SystemProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	p.value = nativeValue{Present: true, Proxy: &nativeProxyValue{Number: 9}}
	status, err := e.SetInterception(context.Background(), peer, InterceptionIntent{RequestID: "stop", ExpectedGeneration: 1})
	if err == nil || !status.CleanupPending || p.restores != 0 || p.value.Proxy.Number != 9 {
		t.Fatal("external edit overwritten", status, err)
	}
	if !validInterceptionStatus(status) {
		t.Fatal("pending stop hid desired/observed divergence", status)
	}
	j, err := loadNativeJournal(e.native.path)
	if err != nil || !j.Pending || j.Steps[0].Stage != "conflict" {
		t.Fatal("conflict journal lost", err)
	}
}
func TestNativeInterceptionPoolConflictAndGeneration(t *testing.T) {
	e, p, peer := nativeTestExecutor(t)
	p.snap.Interfaces[0].Addresses = append(p.snap.Interfaces[0].Addresses, netip.MustParsePrefix("198.18.0.1/15"))
	if _, err := chooseNativePool(p.snap, TunnelReadback{}); err == nil {
		t.Fatal("overlapping fake-IP pool accepted")
	}
	if _, err := e.SetInterception(context.Background(), peer, InterceptionIntent{RequestID: "wrong-generation", ExpectedGeneration: 7, SystemProxy: true}); err == nil {
		t.Fatal("stale generation accepted")
	}
}
func TestNativeInterceptionEgressSuspendedNeverFallsBack(t *testing.T) {
	g := &nativeGuard{blocked: true}
	if _, err := g.LookupNetIP(context.Background(), "ip", "example.invalid"); err == nil {
		t.Fatal("blocked DNS escaped")
	}
	if _, err := g.DialPinned(context.Background(), "tcp", netip.MustParseAddrPort("192.0.2.10:443")); err == nil {
		t.Fatal("blocked dial escaped")
	}
	if _, err := g.DialContext(context.Background(), "tcp", "192.0.2.10:bad"); err == nil {
		t.Fatal("invalid port accepted")
	}
}

type nativeTestWG struct{}

func (nativeTestWG) Apply(context.Context, ConfigurationDesired, time.Time) ApplyOutcome {
	return ApplyOutcome{Status: "applied", ReadbackHash: "wg-test"}
}
func (nativeTestWG) Disable(context.Context) error { return nil }
func (nativeTestWG) Verify(context.Context, ConfigurationDesired, time.Time) ApplyOutcome {
	return ApplyOutcome{Status: "applied", ReadbackHash: "wg-test"}
}
func TestNativeInterceptionACKNormalizesOnlyAfterActualPlanVerify(t *testing.T) {
	e, _, _ := nativeTestExecutor(t)
	base := e.previousMihomo.Configuration
	actual := cloneMihomoConfiguration(base)
	actual.DNSMode = "fake_ip"
	actual.FakeIPRange = "198.18.0.0/16"
	actual.NativePlan = &nativeEnginePlan{TUN: true, Device: "owned-tun"}
	e.previousMihomo.Configuration = actual
	r := e.mihomo.(*nativeTestEngine)
	r.configuration = cloneMihomoConfiguration(actual)
	e.wireGuard = nativeTestWG{}
	desired := ConfigurationDesired{Mihomo: &base}
	got := e.Verify(context.Background(), desired, time.Now())
	want := combinedReadbackHash("wg-test", mihomoConfigurationReadbackHash(&base, expectedMihomoReadback(base)))
	if got.Status != "applied" || got.ReadbackHash != want {
		t.Fatal("native local transport changed Core ACK", got, want)
	}
	r.configuration.NativePlan.Device = "foreign-tun"
	if got = e.Verify(context.Background(), desired, time.Now()); got.Status == "applied" {
		t.Fatal("actual native drift was normalized away")
	}
}
func TestNativeInterceptionRestartRestoresWithoutReenabling(t *testing.T) {
	e, p, peer := nativeTestExecutor(t)
	_, err := e.SetInterception(context.Background(), peer, InterceptionIntent{RequestID: "enable", SystemProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	old := e.native
	old.dns.close()
	old.dns = nil
	old.session.Close()
	old.session = nil
	journal, err := loadNativeJournal(old.path)
	if err != nil {
		t.Fatal(err)
	}
	restarted := &CoordinatedExecutor{mihomo: &nativeTestEngine{}, native: &nativeInterception{platform: p, path: old.path, journal: journal, guard: &nativeGuard{platform: p, blocked: true}, status: InterceptionStatus{State: interceptionCleanupPending, CleanupPending: true}, identity: old.identity}}
	if err = restarted.restoreNativeLocked(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if p.restores != 1 || restarted.native.status.State != interceptionInactive || restarted.mihomo.(*nativeTestEngine).applies != 0 {
		t.Fatal("restart replayed native enable")
	}
	e.native = restarted.native
}

type nativeMultiPlatform struct {
	*nativeTestPlatform
	values   map[string]nativeValue
	cancelAt int
	cancelFn context.CancelFunc
	order    []string
}

func (p *nativeMultiPlatform) PlanChanges(nativeSnapshot, nativeInterceptionPlan) ([]nativeChange, error) {
	return []nativeChange{{ID: "flags", Kind: "proxy", Field: "flags", After: nativeValue{Present: true, Proxy: &nativeProxyValue{Number: 1}}}, {ID: "server", Kind: "proxy", Field: "server", After: nativeValue{Present: true, Proxy: &nativeProxyValue{Text: "127.0.0.1:12345"}}}, {ID: "bypass", Kind: "proxy", Field: "bypass", After: nativeValue{Present: true, Proxy: &nativeProxyValue{Text: "<local>"}}}}, nil
}
func (p *nativeMultiPlatform) ReadChange(_ context.Context, _ nativeSession, c nativeChange) (nativeValue, error) {
	return p.values[c.ID], nil
}
func (p *nativeMultiPlatform) CompareApply(_ context.Context, _ nativeSession, c nativeChange) (nativeReceipt, error) {
	p.values[c.ID] = c.After
	p.writes++
	if p.writes == p.cancelAt {
		p.cancelFn()
	}
	return nativeReceipt{ChangeID: c.ID, Outcome: "applied", Current: c.After}, nil
}
func (p *nativeMultiPlatform) CompareRestore(ctx context.Context, _ nativeSession, c nativeChange) (nativeReceipt, error) {
	if ctx.Err() != nil {
		return nativeReceipt{}, ctx.Err()
	}
	p.order = append(p.order, c.ID)
	delete(p.values, c.ID)
	return nativeReceipt{ChangeID: c.ID, Outcome: "applied", Current: c.Before}, nil
}
func TestNativeInterceptionCancellationAtEachStepRestoresReverseOrder(t *testing.T) {
	for at := 1; at <= 3; at++ {
		t.Run(fmt.Sprint(at), func(t *testing.T) {
			e, base, peer := nativeTestExecutor(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := &nativeMultiPlatform{nativeTestPlatform: base, values: map[string]nativeValue{}, cancelAt: at, cancelFn: cancel}
			e.native.platform = p
			e.native.guard.platform = p
			status, err := e.SetInterception(ctx, peer, InterceptionIntent{RequestID: "enable", SystemProxy: true})
			want := []string{"flags", "server", "bypass"}[:at]
			for i, j := 0, len(want)-1; i < j; i, j = i+1, j-1 {
				want[i], want[j] = want[j], want[i]
			}
			if err == nil || status.CleanupPending || !reflect.DeepEqual(p.order, want) || len(p.values) != 0 {
				t.Fatal("cancellation lost restoration", status, err, p.order, want)
			}
		})
	}
}
func TestNativeInterceptionIPCRejectsRendererIdentityAndConflictingParameters(t *testing.T) {
	e, p, _ := nativeTestExecutor(t)
	p.authErr = errors.New("same user, wrong executable")
	manager, err := NewManager(ManagerOptions{RuntimeID: "endpoint-1", DeviceID: "device-1", PollInterval: time.Second, HeartbeatInterval: time.Minute, RenewBefore: 10 * time.Second, MaxClockSkew: time.Minute}, &fakeControl{}, e, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		`{"version":1,"requestId":"a","action":"interception_set","interception":{"requestId":"enable","expectedGeneration":0,"systemProxy":true,"tun":false},"pid":42}`,
		`{"version":1,"requestId":"b","action":"status","interception":{"requestId":"enable","expectedGeneration":0,"systemProxy":true,"tun":false}}`,
		`{"version":1,"requestId":"c","action":"interception_set","interception":{"requestId":"enable","expectedGeneration":0,"systemProxy":true,"tun":false}}`,
		`{"version":1,"requestId":"e","action":"interception_ui_scope","uiScope":{"serverUrl":"https://control.example.test","userId":"core-user-a","epoch":"fixture-native-host-epoch","generation":1,"authenticated":true}}`,
		`{"version":1,"requestId":"f","action":"status","uiScope":{"serverUrl":"https://control.example.test"}}`,
		`{"version":1,"requestId":"g","action":"interception_set","interception":{"requestId":"enable","systemProxy":true},"uiScope":{"userId":"core-user-a"}}`,
	} {
		response := ipcRoundTrip(t, manager, raw)
		if response.OK || p.writes != 0 {
			t.Fatal("renderer bypassed native peer authentication", response)
		}
	}
	response := ipcRoundTrip(t, manager, `{"version":1,"requestId":"d","action":"interception_status"}`)
	if !response.OK || response.Interception == nil || response.Interception.State != interceptionInactive {
		t.Fatal("native status unavailable", response)
	}
}

func (p *nativeTestPlatform) FlushResolverCache(context.Context, nativeSession) error { return nil }

func TestNativeInterceptionEmptySupplementalNamespaceCannotFallThroughPublicDNS(t *testing.T) {
	p := &nativeDNSProxy{scopes: []nativeResolverScope{{ID: "wg", Domains: []string{""}, Priority: 1, Servers: []netip.Addr{netip.MustParseAddr("10.0.0.53")}}, {ID: "physical", Default: true, Priority: 10, Servers: []netip.Addr{netip.MustParseAddr("192.0.2.53")}}}}
	scope, err := p.scopeFor("corp.internal.test")
	if err != nil || scope.ID != "wg" {
		t.Fatal("WG catch-all namespace fell through", scope, err)
	}
}

func TestNativeInterceptionKnownLoopbackOriginIsNarrow(t *testing.T) {
	e, p, peer := nativeTestExecutor(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	target := listener.Addr().(*net.TCPAddr).AddrPort()
	g := e.native.guard
	g.internal = map[netip.AddrPort]bool{target: true}
	g.set(&nativeEgressBinding{snapshot: p.snap, session: peer.session, until: time.Now().Add(time.Minute)}, false)
	conn, err := g.DialPinned(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal("registered local control origin rejected", err)
	}
	conn.Close()
	unknown := netip.AddrPortFrom(target.Addr(), target.Port()+1)
	if _, err = g.DialPinned(context.Background(), "tcp", unknown); err == nil {
		t.Fatal("arbitrary loopback target was admitted")
	}
	g.set(nil, false)
}

func TestNativeInterceptionUnavailableCapabilityPreservesOrdinaryUIPresence(t *testing.T) {
	e, _, _ := nativeTestExecutor(t)
	calls := 0
	presence := &UIProcessPresence{verify: func(net.Conn) error { calls++; return nil }}
	config := Config{StateDirectory: t.TempDir(), ControlURL: "https://control.example.test", RuntimeID: "endpoint-a", DeviceID: "device-a", MihomoProcess: MihomoProcessConfig{Ownership: "external"}}
	if err := e.ConfigureNativeInterception(config, presence); err != nil {
		t.Fatal(err)
	}
	if e.native.status.Capabilities.SystemProxy || e.native.status.Capabilities.TUN || presence.authenticate != nil {
		t.Fatal("unavailable native feature replaced ordinary presence verification")
	}
	if err := presence.Observe(nil, time.Now()); err != nil || calls != 1 {
		t.Fatal("ordinary presence regressed", err, calls)
	}
}
