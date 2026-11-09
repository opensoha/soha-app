//go:build darwin && cgo

package endpointservice

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type darwinCleanupSnapshotReader interface {
	RecoverySnapshot(context.Context, nativeSession) (nativeSnapshot, error)
}

func darwinRecoverySnapshotFixture(t *testing.T, p *darwinNativePlatform, interfaces []nativeInterface) {
	t.Helper()
	p.calls.interfaces = func() ([]nativeInterface, error) { return append([]nativeInterface(nil), interfaces...), nil }
	p.calls.network = func() (darwinNativeNetwork, error) {
		var network darwinNativeNetwork
		err := json.Unmarshal([]byte(`{"IPv4":"physical-service","IPv6":"physical-service","Services":[{"ID":"physical-service","Name":"Synthetic physical","Interface":"en0","Type":"Ethernet"}]}`), &network)
		return network, err
	}
	p.calls.routes = func([]nativeInterface) ([]nativeRoute, error) { return nil, nil }
	p.calls.read = func(string, string, string) (json.RawMessage, error) { return json.RawMessage("null"), nil }
	p.calls.cas = func(string, string, string, json.RawMessage, json.RawMessage) (string, error) {
		t.Error("recovery snapshot attempted a native settings write")
		return "unknown", errDarwinNative
	}
	p.calls.routeWrite = func(nativeRoute, bool) error {
		t.Error("recovery snapshot attempted a route write")
		return errDarwinNative
	}
}
func darwinRecoveryPhysical() nativeInterface {
	return nativeInterface{ID: "physical-new", Name: "en0", Index: 1, Kind: "physical", Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")}}
}
func TestDarwinNativeRecoverySessionSnapshotBoundary(t *testing.T) {
	p, s := nativeDarwinFixture()
	ctx := context.Background()
	restore, err := p.AcquireRestoreSession(ctx, s.Owner())
	if err != nil {
		t.Fatal(err)
	}
	darwinRecoverySnapshotFixture(t, p, []nativeInterface{darwinRecoveryPhysical()})
	if _, err = p.Snapshot(ctx, restore); err == nil {
		t.Fatal("ordinary Snapshot granted activity to restore-only session")
	}
	reader, ok := any(p).(darwinCleanupSnapshotReader)
	if !ok {
		t.Fatal("restore-only cleanup snapshot reader missing")
	}
	if snap, err := reader.RecoverySnapshot(ctx, restore); err != nil || !reflect.DeepEqual(snap.Interfaces, []nativeInterface{darwinRecoveryPhysical()}) {
		t.Fatalf("cleanup-only snapshot: %v", err)
	}
	change := nativeChange{ID: "no-enable", Kind: "proxy", Field: "HTTPEnable", Scope: nativeScope{ServiceID: "physical-service"}, After: nativeValue{Present: true, Proxy: &nativeProxyValue{Bool: true}}}
	if _, err = p.CompareApply(ctx, restore, change); err == nil {
		t.Fatal("restore-only session enabled native settings")
	}
	guard := &nativeGuard{platform: p, binding: &nativeEgressBinding{session: restore, until: time.Now().Add(time.Minute)}}
	if _, err = guard.state(ctx); err == nil {
		t.Fatal("restore-only session gained egress authorization")
	}
	foreign, _ := nativeDarwinFixture()
	foreignRestore, err := foreign.AcquireRestoreSession(ctx, s.Owner())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reader.RecoverySnapshot(ctx, foreignRestore); err == nil {
		t.Fatal("foreign platform session read recovery snapshot")
	}
	restore.Close()
	if _, err = reader.RecoverySnapshot(ctx, restore); err == nil {
		t.Fatal("closed session read recovery snapshot")
	}
}
func TestDarwinNativeRecoveryWGAbsentRead(t *testing.T) {
	old := newDarwinWGFixture(t)
	change := old.prepare(t)
	ctx := context.Background()
	restore, err := old.session.platform.AcquireRestoreSession(ctx, old.session.Owner())
	if err != nil {
		t.Fatal(err)
	}
	replacement := change.Scope.Interface
	replacement.ID = "new-incarnation-same-index"
	fresh := &DarwinSystem{nativeDNSInterfaces: func() ([]nativeInterface, error) { return []nativeInterface{replacement}, nil }, nativeDNSAbsent: func(nativeChange) (bool, error) { return true, nil }}
	receipt, err := fresh.CompareNativeDNS(ctx, restore, change, true)
	if err != nil || receipt.Outcome != "absent" {
		t.Fatalf("positive original scope absence: %v", err)
	}
	if err = fresh.ReleaseNativeDNS(ctx, restore, []nativeChange{change}); err != nil {
		t.Fatal(err)
	}
	value, err := fresh.ReadNativeDNS(ctx, restore, change)
	if err != nil || value.Present {
		t.Fatalf("post-release old scope audit blocked: %+v %v", value, err)
	}
	if nativeValuesEqual(value, change.After) {
		t.Fatal("absent DNS masqueraded as successful After ACK")
	}
	if receipt, err = fresh.CompareNativeDNS(ctx, restore, change, false); err == nil || receipt.Outcome == "absent" {
		t.Fatal("absence authorized apply")
	}
	for _, which := range []string{"old-interface-present", "old-handle-present", "metadata-error", "interface-error", "malformed-change", "closed-session"} {
		t.Run(which, func(t *testing.T) {
			restore, err := old.session.platform.AcquireRestoreSession(ctx, old.session.Owner())
			if err != nil {
				t.Fatal(err)
			}
			candidate := change
			system := &DarwinSystem{nativeDNSInterfaces: func() ([]nativeInterface, error) { return []nativeInterface{replacement}, nil }, nativeDNSAbsent: func(nativeChange) (bool, error) { return true, nil }}
			switch which {
			case "old-interface-present":
				system.nativeDNSInterfaces = func() ([]nativeInterface, error) { return []nativeInterface{change.Scope.Interface}, nil }
			case "old-handle-present":
				system.nativeDNSAbsent = func(nativeChange) (bool, error) { return false, nil }
			case "metadata-error":
				system.nativeDNSAbsent = func(nativeChange) (bool, error) { return false, errors.New("unreadable handle") }
			case "interface-error":
				system.nativeDNSInterfaces = func() ([]nativeInterface, error) { return nil, errors.New("unreadable interfaces") }
			case "malformed-change":
				candidate.ID = ""
				system.nativeDNSAbsent = func(nativeChange) (bool, error) { t.Error("invalid change reached handle probe"); return true, nil }
			case "closed-session":
				restore.Close()
			}
			if _, err = system.ReadNativeDNS(ctx, restore, candidate); err == nil {
				t.Fatal("unknown/changed scope was classified absent")
			}
		})
	}
}
func TestDarwinNativeRecoveryCoordinatorAcrossOwners(t *testing.T) {
	for _, scene := range []string{"connected", "no-primary", "owned-controller-denied"} {
		t.Run(scene, func(t *testing.T) {
			f := newDarwinRecoveryFixture(t)
			ctx := context.Background()
			directory := t.TempDir()
			launch := filepath.Join(directory, "launch-recovered")
			f.proof.LaunchDirectory = launch
			f.proof.ExecutablePath = filepath.Join(launch, "mihomo")
			f.proof.Arguments = []string{f.proof.ExecutablePath, "-d", launch, "-f", filepath.Join(launch, "config.yaml")}
			f.platform.calls.recovery.path = func(uint32) (string, error) { f.pathCalls++; return f.proof.ExecutablePath, nil }
			f.platform.calls.recovery.args = func(uint32) ([]string, error) { return append([]string(nil), f.proof.Arguments...), nil }
			identity := f.capture(t)
			old := newDarwinWGFixture(t)
			change := old.prepare(t)
			replacement := change.Scope.Interface
			replacement.ID = "new-WG-incarnation-same-index"
			oldTUN := nativeInterface{ID: "old-native-TUN", Name: "utun233", Index: 19, Kind: "tunnel"}
			newTUN := oldTUN
			newTUN.ID = "new-native-TUN-same-index"
			newTUN.Addresses = []netip.Prefix{netip.MustParsePrefix("fd04:122::2/64")}
			interfaces := []nativeInterface{darwinRecoveryPhysical(), replacement, newTUN}
			darwinRecoverySnapshotFixture(t, f.platform, interfaces)
			if scene == "no-primary" {
				f.platform.calls.network = func() (darwinNativeNetwork, error) { return darwinNativeNetwork{}, nil }
			}

			api := &nativeQuiesceAPI{secret: strings.Repeat("f", 32), mixed: 12345}
			proof := newDarwinRecoveryHTTPProof(t, f, api, identity)
			defer proof.close()
			if scene == "owned-controller-denied" {
				proof.deny.Store(true)
			}
			controller, err := NewMihomoController(proof.server.URL, api.secret)
			if err != nil {
				t.Fatal(err)
			}
			controller.process = &mihomoProcess{directory: directory, config: MihomoProcessConfig{Ownership: "soha_owned", SHA256: f.proof.BinarySHA256, Version: "Mihomo Meta v1.19.30"}, status: MihomoProcessStatus{Ownership: "soha_owned", State: "stopped"}}
			original := MihomoConfiguration{DNSMode: "disabled"}
			after := original
			after.NativePlan = &nativeEnginePlan{TUN: true, Device: "utun233", FakeIPPool: netip.MustParsePrefix("198.19.0.0/16"), FakeIPv6Pool: netip.MustParsePrefix("fdfe:dcba:9875::/48"), TUNAddress6: netip.MustParsePrefix("fdfe:dcba:9875::1/126"), DNSUpstream: netip.MustParseAddrPort("127.0.0.1:32001")}
			binding := "sha256:" + strings.Repeat("d", 64)
			plan := &nativeDNSQuiescePlan{DNS: true, Version: 1, Kernel: "v1.19.30", Binding: binding, Controller: proof.server.URL, ControllerBinding: nativeControllerBinding(proof.server.URL, api.secret), Process: identity, Upstream: after.NativePlan.DNSUpstream, Before: nativeQuiesceState(original), After: nativeQuiesceState(after)}
			api.mu.Lock()
			api.tun = plan.After.Tun
			api.mu.Unlock()
			freshWG := &DarwinSystem{nativeDNSInterfaces: func() ([]nativeInterface, error) { return append([]nativeInterface(nil), interfaces...), nil }, nativeDNSAbsent: func(nativeChange) (bool, error) {
				if !api.ready() {
					t.Error("WG DNS restore crossed controller quiesce ACK")
					return false, errDarwinNative
				}
				return true, nil
			}}
			route := nativeChange{ID: "old-native-route", Kind: "route", Scope: nativeScope{Interface: oldTUN, Family: 4}, After: nativeValue{Present: true, Route: &nativeRoute{Destination: netip.MustParsePrefix("0.0.0.0/1"), Interface: oldTUN}}}
			journal := nativeJournal{Version: 1, Generation: 9, Owner: f.session.Owner(), Binding: binding, ProcessEpoch: identity.Proof.ProcessEpoch, Quiesce: plan, Pending: true, Process: &identity, CacheFlushPending: true, DNSReleasePending: true, Steps: []nativeJournalStep{{Owner: "wireguard", Change: change, Stage: "written"}, {Owner: "platform", Change: route, Stage: "restored"}}}
			path := filepath.Join(directory, "recovery", "journal")
			if err := saveNativeJournal(path, journal); err != nil {
				t.Fatal(err)
			}
			loaded, err := loadNativeJournal(path)
			if err != nil {
				t.Fatal(err)
			}
			e := &CoordinatedExecutor{mihomo: controller, wireGuard: &Executor{system: freshWG}, native: &nativeInterception{platform: f.platform, path: path, journal: loaded, guard: &nativeGuard{platform: f.platform}}}
			flushes := 0
			f.platform.calls.flushCommand = func(context.Context, string, ...string) error {
				flushes++
				if !api.ready() {
					t.Error("cache flush crossed controller quiesce ACK")
				}
				if e.native.session == nil || e.native.session.Validate(ctx, false) == nil {
					t.Error("recovery did not acquire a real restore-only session")
				}
				return nil
			}
			f.session.Close()
			f.platform.calls.code = func([8]uint32) error { return errDarwinNative }
			f.platform.calls.console = func(uint32, uint32) error { return errDarwinNative }
			err = e.restoreNativeLocked(ctx, false)
			proof.waitReleased(t)
			api.mu.Lock()
			requests, puts, observed := api.requests, api.puts, api.observed
			api.mu.Unlock()
			if proof.secretBeforeProof.Load() {
				t.Fatal("controller received Authorization before accepted-tuple proof")
			}
			if scene == "owned-controller-denied" {
				if err == nil || !e.native.status.CleanupPending || e.native.journal.Process == nil || e.native.journal.Quiesce == nil || flushes != 0 || f.terminationCalls != 0 || requests != 0 {
					t.Fatalf("unproved owner crossed recovery barrier: requests=%d flush=%d term=%d err=%v", requests, flushes, f.terminationCalls, err)
				}
				return
			}
			if requests == 0 || puts != 1 || !observed || proof.dials.Load() == 0 {
				t.Fatalf("recovery bypassed live owned controller: requests=%d puts=%d observed=%v", requests, puts, observed)
			}
			if err != nil {
				t.Fatalf("restart coordinator retained Process/old WG despite proved cleanup: %v (state=%s reason=%s)", err, e.native.status.State, e.native.status.ReasonCode)
			}
			if f.terminationCalls != 1 || flushes != 2 || e.native.journal.Process != nil || e.native.journal.Pending || e.native.journal.DNSReleasePending || e.native.status.State != interceptionInactive || e.native.session != nil {
				t.Fatalf("recovery did not complete: term=%d flush=%d journal=%+v", f.terminationCalls, flushes, e.native.journal)
			}
			persisted, err := loadNativeJournal(path)
			if err != nil || persisted.Process != nil || persisted.Quiesce != nil || persisted.Pending || len(persisted.Steps) != 0 {
				t.Fatalf("durable process recovery incomplete: %+v %v", persisted, err)
			}
			current, _ := freshWG.wgNativeInterfaces()
			if !reflect.DeepEqual(current, interfaces) {
				t.Fatal("recovery touched replacement incarnations")
			}

		})
	}
}

func TestDarwinNativeRecoverySnapshotWithoutPrimary(t *testing.T) {
	p, active := nativeDarwinFixture()
	ctx := context.Background()
	restore, err := p.AcquireRestoreSession(ctx, active.Owner())
	if err != nil {
		t.Fatal(err)
	}
	owned := nativeInterface{ID: "owned-TUN-still-live", Name: "utun233", Index: 233, Kind: "tunnel", Addresses: []netip.Prefix{netip.MustParsePrefix("fd00:122::2/126")}}
	interfaces := []nativeInterface{owned}
	darwinRecoverySnapshotFixture(t, p, interfaces)
	networkCalls := 0
	p.calls.network = func() (darwinNativeNetwork, error) { networkCalls++; return darwinNativeNetwork{}, nil }
	if _, err = p.Snapshot(ctx, active); err == nil {
		t.Fatal("ordinary Snapshot accepted unavailable primary service")
	}
	networkCalls = 0
	p.calls.routes = func([]nativeInterface) ([]nativeRoute, error) {
		t.Error("interface-only recovery queried routes/defaults")
		return nil, errDarwinNative
	}
	p.calls.read = func(string, string, string) (json.RawMessage, error) {
		t.Error("interface-only recovery queried DNS/proxy settings")
		return nil, errDarwinNative
	}
	snapshot, err := p.RecoverySnapshot(ctx, restore)
	if err != nil || !reflect.DeepEqual(snapshot.Interfaces, interfaces) {
		t.Fatalf("no-primary recovery lost real interfaces: %+v %v", snapshot.Interfaces, err)
	}
	if networkCalls != 0 || snapshot.PrimaryServiceID != "" || len(snapshot.Routes) != 0 || len(snapshot.Resolvers) != 0 || len(snapshot.Settings) != 0 {
		t.Fatal("recovery depended on non-interface network state")
	}
	if !snapshot.Interfaces[0].Addresses[0].Addr().IsGlobalUnicast() {
		t.Fatal("owned TUN ULA unavailable to IPv6 recovery audit")
	}
	p.calls.interfaces = func() ([]nativeInterface, error) { return nil, nil }
	snapshot, err = p.RecoverySnapshot(ctx, restore)
	if err != nil || len(snapshot.Interfaces) != 0 || networkCalls != 0 {
		t.Fatal("successful complete enumeration could not prove old TUN gone")
	}
	for _, which := range []string{"interfaces-unknown", "closed-during-read", "cancelled-during-read"} {
		t.Run(which, func(t *testing.T) {
			p, active := nativeDarwinFixture()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			restore, err := p.AcquireRestoreSession(ctx, active.Owner())
			if err != nil {
				t.Fatal(err)
			}
			darwinRecoverySnapshotFixture(t, p, interfaces)
			p.calls.network = func() (darwinNativeNetwork, error) {
				t.Error("recovery read non-interface metadata")
				return darwinNativeNetwork{}, errDarwinNative
			}
			p.calls.interfaces = func() ([]nativeInterface, error) {
				switch which {
				case "interfaces-unknown":
					return nil, errors.New("interface enumeration unknown")
				case "closed-during-read":
					restore.Close()
				case "cancelled-during-read":
					cancel()
				}
				return interfaces, nil
			}
			if snapshot, err = p.RecoverySnapshot(ctx, restore); err == nil || len(snapshot.Interfaces) != 0 {
				t.Fatal("unknown/unauthorized enumeration used as disappearance proof")
			}
		})
	}
}

// Only the controller is real loopback TCP. Mach, process and FD metadata remain
// injected, with accepted tuples taken from this exact httptest server.
type darwinRecoveryHTTPEntry struct {
	server, client netip.AddrPort
	cookie         [4]uint64
	proofs         int
}
type darwinRecoveryHTTPProof struct {
	server                    *httptest.Server
	api                       *nativeQuiesceAPI
	mu                        sync.Mutex
	accepted                  map[netip.AddrPort]*darwinRecoveryHTTPEntry
	raw                       []net.Conn
	next                      uint64
	alive                     atomic.Bool
	deny                      atomic.Bool
	secretBeforeProof         atomic.Bool
	dials, acquired, released atomic.Int64
	releaseEvent              chan struct{}
}

func newDarwinRecoveryHTTPProof(t *testing.T, f *darwinRecoveryFixture, api *nativeQuiesceAPI, record nativeOwnedProcessIdentity) *darwinRecoveryHTTPProof {
	t.Helper()
	proof := &darwinRecoveryHTTPProof{api: api, accepted: map[netip.AddrPort]*darwinRecoveryHTTPEntry{}, releaseEvent: make(chan struct{}, 64)}
	proof.alive.Store(true)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		client, err := netip.ParseAddrPort(r.RemoteAddr)
		proof.mu.Lock()
		entry := proof.accepted[client]
		verified := err == nil && entry != nil && entry.proofs >= 3
		proof.mu.Unlock()
		if !verified {
			proof.secretBeforeProof.Store(true)
			http.Error(w, "tuple proof missing", 500)
			return
		}
		api.serve(w, r)
	})
	proof.server = httptest.NewUnstartedServer(handler)
	proof.server.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		server, sErr := darwinControllerEndpoint(conn.LocalAddr())
		client, cErr := darwinControllerEndpoint(conn.RemoteAddr())
		if sErr != nil || cErr != nil {
			return
		}
		proof.mu.Lock()
		defer proof.mu.Unlock()
		switch state {
		case http.StateNew:
			proof.next++
			n := proof.next
			proof.accepted[client] = &darwinRecoveryHTTPEntry{server: server, client: client, cookie: [4]uint64{100 + n, 200 + n, 300 + n, 400 + n}}
		case http.StateClosed, http.StateHijacked:
			delete(proof.accepted, client)
		}
	}
	proof.server.Start()
	endpoint, err := netip.ParseAddrPort(strings.TrimPrefix(proof.server.URL, "http://"))
	if err != nil {
		proof.close()
		t.Fatal(err)
	}
	calls := f.platform.calls.recovery
	originalTask := calls.task
	calls.task = func(pid uint32) (uint32, [8]uint32, error) {
		port, token, err := originalTask(pid)
		if port != 0 {
			proof.acquired.Add(1)
		}
		return port, token, err
	}
	calls.release = func(port uint32) {
		if port != 88 {
			t.Error("foreign task port released")
		}
		proof.released.Add(1)
		select {
		case proof.releaseEvent <- struct{}{}:
		default:
		}
	}
	calls.meta = func(pid uint32) (darwinRecoveryMeta, error) {
		if pid != record.Proof.PID {
			return darwinRecoveryMeta{}, errDarwinRecovery
		}
		if !proof.alive.Load() {
			return darwinRecoveryMeta{}, errDarwinProcessGone
		}
		return f.meta, nil
	}
	calls.dialController = func(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
		if target != endpoint {
			return nil, errDarwinRecovery
		}
		proof.dials.Add(1)
		conn, err := darwinRecoveryControllerDial(ctx, target)
		if conn != nil {
			proof.mu.Lock()
			proof.raw = append(proof.raw, conn)
			proof.mu.Unlock()
		}
		return conn, err
	}
	calls.controllerSocket = func(pid uint32, server, client netip.AddrPort) ([4]uint64, error) {
		if proof.deny.Load() || !proof.alive.Load() || pid != record.Proof.PID || server != endpoint {
			return [4]uint64{}, errDarwinRecovery
		}
		proof.mu.Lock()
		defer proof.mu.Unlock()
		entry := proof.accepted[client]
		if entry == nil {
			return [4]uint64{}, errDarwinControllerNotReady
		}
		if entry.server != server || entry.client != client {
			return [4]uint64{}, errDarwinRecovery
		}
		entry.proofs++
		return entry.cookie, nil
	}
	calls.wait = func(ctx context.Context) error {
		timer := time.NewTimer(10 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}
	calls.terminate = func(port uint32) error {
		if port != 88 || !api.ready() {
			t.Error("termination crossed the owned controller quiesce barrier")
			return errDarwinRecovery
		}
		f.terminationCalls++
		proof.alive.Store(false)
		return nil
	}
	return proof
}
func (p *darwinRecoveryHTTPProof) waitReleased(t *testing.T) {
	t.Helper()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for p.acquired.Load() != p.released.Load() {
		select {
		case <-p.releaseEvent:
		case <-timer.C:
			t.Fatalf("owned task rights leaked: acquired=%d released=%d", p.acquired.Load(), p.released.Load())
		}
	}
}
func (p *darwinRecoveryHTTPProof) close() {
	p.api.release.Do(func() {
		if p.api.hold != nil {
			close(p.api.hold)
		}
	})
	p.mu.Lock()
	raw := append([]net.Conn(nil), p.raw...)
	p.mu.Unlock()
	for _, conn := range raw {
		conn.Close()
	}
	p.server.CloseClientConnections()
	p.server.Close()
}
