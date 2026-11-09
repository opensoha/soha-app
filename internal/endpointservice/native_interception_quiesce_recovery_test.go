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
	"testing"
	"time"
)

type nativeQuiesceAPI struct {
	mu                                          sync.Mutex
	secret                                      string
	tun                                         nativeTunReadback
	mixed                                       int
	quiet, observed                             bool
	failPut, unknownPut, badAfter, unknownAfter bool
	hold, seen                                  chan struct{}
	release                                     sync.Once
	requests, puts                              int
	history                                     []string
}

func (a *nativeQuiesceAPI) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") != "Bearer "+a.secret {
		w.WriteHeader(401)
		return
	}
	a.mu.Lock()
	a.requests++
	a.history = append(a.history, r.Method+" "+r.URL.Path)
	switch r.Method + " " + r.URL.Path {
	case "PATCH /configs":
		a.mixed = 0
		a.mu.Unlock()
		w.WriteHeader(204)
		return
	case "GET /configs":
		raw, _ := json.Marshal(a.tun)
		if a.quiet && a.badAfter {
			var m map[string]any
			json.Unmarshal(raw, &m)
			m["mtu"] = 9000
			raw, _ = json.Marshal(m)
		}
		if a.quiet && a.unknownAfter {
			var m map[string]any
			json.Unmarshal(raw, &m)
			m["unknown-native-field"] = true
			raw, _ = json.Marshal(m)
		}
		mixed := a.mixed
		if a.quiet {
			a.observed = true
		}
		a.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"mixed-port": mixed, "port": 0, "socks-port": 0, "redir-port": 0, "tproxy-port": 0, "mode": "rule", "bind-address": "127.0.0.1", "allow-lan": false, "ipv6": true, "tun": json.RawMessage(raw)})
		return
	case "PUT /configs":
		a.puts++
		fail, hold, unknown := a.failPut, a.hold, a.unknownPut
		expected := a.tun
		a.mu.Unlock()
		var envelope struct{ Payload string }
		if json.NewDecoder(r.Body).Decode(&envelope) != nil {
			w.WriteHeader(400)
			return
		}
		var document struct {
			Tun nativeTunReadback `json:"tun"`
			DNS struct {
				Enable bool   `json:"enable"`
				Fake4  string `json:"fake-ip-range"`
				Fake6  string `json:"fake-ip-range6"`
			} `json:"dns"`
			IPv6 bool `json:"ipv6"`
		}
		if json.Unmarshal([]byte(envelope.Payload), &document) != nil || document.DNS.Enable || !document.IPv6 {
			w.WriteHeader(400)
			return
		}
		prefix, err := netip.ParsePrefix(document.DNS.Fake4)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		document.Tun.Inet4Address = []netip.Prefix{netip.PrefixFrom(prefix.Addr(), 30)}
		if !nativeTunEqual(document.Tun, expected) {
			w.WriteHeader(409)
			return
		}
		if fail {
			w.WriteHeader(500)
			return
		}
		a.mu.Lock()
		if a.seen != nil {
			select {
			case <-a.seen:
			default:
				close(a.seen)
			}
		}
		a.mu.Unlock()
		if hold != nil {
			<-hold
		}
		a.mu.Lock()
		a.quiet = true
		a.mixed = 0
		a.history = append(a.history, "backend-quiet")
		a.mu.Unlock()
		if unknown {
			h, ok := w.(http.Hijacker)
			if ok {
				conn, _, err := h.Hijack()
				if err == nil {
					conn.Close()
				}
			}
			return
		}
		w.WriteHeader(204)
		return
	}
	a.mu.Unlock()
	w.WriteHeader(404)
}
func (a *nativeQuiesceAPI) ready() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.quiet && a.observed
}

type nativeQuiesceRestoreSession struct{ owner nativeOwner }

func (s *nativeQuiesceRestoreSession) Owner() nativeOwner { return s.owner }
func (s *nativeQuiesceRestoreSession) Validate(ctx context.Context, restore bool) error {
	if !restore {
		return errors.New("restore-only")
	}
	return ctx.Err()
}
func (s *nativeQuiesceRestoreSession) Close() error { return nil }

type nativeQuiesceRecoveryPlatform struct {
	*nativeRecoveryPlatform
	api              *nativeQuiesceAPI
	record           nativeOwnedProcessIdentity
	endpoint         netip.AddrPort
	gone, deny, held bool
	dials            int
}

func (p *nativeQuiesceRecoveryPlatform) AcquireRestoreSession(_ context.Context, owner nativeOwner) (nativeSession, error) {
	return &nativeQuiesceRestoreSession{owner}, nil
}
func (p *nativeQuiesceRecoveryPlatform) Snapshot(ctx context.Context, s nativeSession) (nativeSnapshot, error) {
	if err := s.Validate(ctx, false); err != nil {
		return nativeSnapshot{}, err
	}
	return p.snap, nil
}
func (p *nativeQuiesceRecoveryPlatform) RecoverySnapshot(ctx context.Context, s nativeSession) (nativeSnapshot, error) {
	if err := s.Validate(ctx, true); err != nil {
		return nativeSnapshot{}, err
	}
	return p.snap, nil
}
func (p *nativeQuiesceRecoveryPlatform) CaptureOwnedProcess(ctx context.Context, s nativeSession, proof nativeOwnedProcessProof) (nativeOwnedProcessIdentity, error) {
	if err := s.Validate(ctx, false); err != nil {
		return nativeOwnedProcessIdentity{}, err
	}
	if !reflect.DeepEqual(proof, p.record.Proof) {
		return nativeOwnedProcessIdentity{}, errors.New("wrong process")
	}
	return p.record, nil
}
func (p *nativeQuiesceRecoveryPlatform) DialOwnedController(ctx context.Context, s nativeSession, record nativeOwnedProcessIdentity, endpoint netip.AddrPort) (net.Conn, bool, error) {
	if s == nil {
		return nil, false, errors.New("missing restore session")
	}
	if err := s.Validate(ctx, true); err != nil {
		return nil, false, err
	}
	p.dials++
	if p.deny || !reflect.DeepEqual(record, p.record) || endpoint != p.endpoint {
		return nil, false, errors.New("owned socket proof rejected")
	}
	if p.gone {
		return nil, true, nil
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", endpoint.String())
	return conn, false, err
}
func (p *nativeQuiesceRecoveryPlatform) CompareRestore(ctx context.Context, s nativeSession, c nativeChange) (nativeReceipt, error) {
	if !p.gone && !p.api.ready() {
		return nativeReceipt{}, errors.New("OS restore crossed DNS quiesce/readback")
	}
	return p.nativeRecoveryPlatform.CompareRestore(ctx, s, c)
}
func (p *nativeQuiesceRecoveryPlatform) RecoverOwnedProcess(_ context.Context, _ nativeSession, record nativeOwnedProcessIdentity) (string, error) {
	unlock, err := lockMihomoProcess(filepath.Join(filepath.Dir(record.Proof.LaunchDirectory), "owner.lock"))
	if err == nil {
		unlock()
		return "", errors.New("outer recovery owner lock was not held")
	}
	p.held = true
	p.gone = true
	return "gone", nil
}
func nativeQuiesceRecoveryFixture(t *testing.T, before bool) (*CoordinatedExecutor, *nativeQuiesceRecoveryPlatform, *nativeQuiesceAPI, *nativeRecoveryWG, *[]string) {
	t.Helper()
	e, base, w, events := nativeRecoveryFixture(t)
	secret := strings.Repeat("q", 32)
	api := &nativeQuiesceAPI{secret: secret, mixed: 12345}
	server := httptest.NewServer(http.HandlerFunc(api.serve))
	t.Cleanup(server.Close)
	controller, err := NewMihomoController(server.URL, secret)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	launch := filepath.Join(directory, "launch-fixture")
	proof := nativeOwnedProcessProof{PID: 90001, ProcessEpoch: strings.Repeat("b", 32), BinarySHA256: strings.Repeat("a", 64), ExecutablePath: filepath.Join(launch, "mihomo"), LaunchDirectory: launch}
	proof.Arguments = []string{proof.ExecutablePath, "-d", launch, "-f", filepath.Join(launch, "config.yaml")}
	record := nativeOwnedProcessIdentity{Proof: proof, Incarnation: "fixture-owned-process-incarnation"}
	controller.process = &mihomoProcess{directory: directory, config: MihomoProcessConfig{Ownership: "soha_owned", SHA256: proof.BinarySHA256, Version: "Mihomo Meta v1.19.30"}, status: MihomoProcessStatus{Ownership: "soha_owned", State: "stopped"}}
	p := &nativeQuiesceRecoveryPlatform{nativeRecoveryPlatform: base, api: api, record: record, endpoint: netip.MustParseAddrPort(strings.TrimPrefix(server.URL, "http://"))}
	p.snap.Interfaces[0].Addresses = append(p.snap.Interfaces[0].Addresses, netip.MustParsePrefix("fd04:122::2/64"))
	e.mihomo = controller
	e.native.platform = p
	e.native.guard.platform = p
	e.native.session = nil
	original := e.previousMihomo.Configuration
	e.native.base = &original
	next := cloneMihomoConfiguration(original)
	next.NativePlan = &nativeEnginePlan{TUN: true, Device: "utun233", FakeIPPool: netip.MustParsePrefix("198.19.0.0/16"), FakeIPv6Pool: netip.MustParsePrefix("fdfe:dcba:9875::/48"), TUNAddress6: netip.MustParsePrefix("fdfe:dcba:9875::1/126"), DNSUpstream: netip.MustParseAddrPort("127.0.0.1:32001")}
	binding := nativeBindingHash(e.native.identity, original)
	plan := &nativeDNSQuiescePlan{DNS: true, Version: 1, Kernel: "v1.19.30", Binding: binding, Controller: server.URL, ControllerBinding: nativeControllerBinding(server.URL, secret), Process: record, Upstream: next.NativePlan.DNSUpstream, Before: nativeQuiesceState(original), After: nativeQuiesceState(next)}
	api.tun = plan.After.Tun
	if before {
		api.tun = plan.Before.Tun
	}
	e.native.journal.Binding = binding
	e.native.journal.Process = &record
	e.native.journal.ProcessEpoch = proof.ProcessEpoch
	e.native.journal.Quiesce = plan
	if err = saveNativeJournal(e.native.path, e.native.journal); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		api.release.Do(func() {
			if api.hold != nil {
				close(api.hold)
			}
		})
	})
	return e, p, api, w, events
}
func TestNativeInterceptionDNSQuiesceRecoveryTwoStates(t *testing.T) {
	for _, before := range []bool{true, false} {
		t.Run(map[bool]string{true: "before", false: "after"}[before], func(t *testing.T) {
			e, p, api, _, events := nativeQuiesceRecoveryFixture(t, before)
			if err := e.restoreNativeLocked(context.Background(), false); err != nil {
				t.Fatal(err)
			}
			if e.native.status.CleanupPending || e.native.journal.Quiesce != nil || !p.held || !api.ready() {
				t.Fatal("restart recovery did not pass quiesce barrier")
			}
			if !reflect.DeepEqual(*events, []string{"proxy", "dns", "wg6", "wg4", "flush", "release", "route"}) {
				t.Fatal("DNS/route recovery order", *events)
			}
			api.mu.Lock()
			defer api.mu.Unlock()
			if api.puts != 1 {
				t.Fatal("DNS stop PUT count", api.puts)
			}
		})
	}
}
func TestNativeInterceptionDNSQuiesceWaitsHandlersBeforeOSRestore(t *testing.T) {
	e, p, api, w, events := nativeQuiesceRecoveryFixture(t, false)
	api.hold = make(chan struct{})
	api.seen = make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- e.restoreNativeLocked(context.Background(), false) }()
	select {
	case <-api.seen:
	case <-time.After(time.Second):
		t.Fatal("DNS stop did not reach backend")
	}
	if len(*events) != 0 || p.flushes != 0 || w.releases != 0 {
		t.Fatal("restore crossed in-flight DNS handler", *events)
	}
	api.release.Do(func() { close(api.hold) })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !api.ready() || e.native.status.CleanupPending {
		t.Fatal("quiesce completion missing")
	}
}
func TestNativeInterceptionDNSQuiesceFailuresDoNotCrossBarrier(t *testing.T) {
	for _, kind := range []string{"api", "unknown-receipt", "readback", "unknown-field", "owner", "binding", "environment"} {
		t.Run(kind, func(t *testing.T) {
			e, p, api, w, events := nativeQuiesceRecoveryFixture(t, false)
			switch kind {
			case "api":
				api.failPut = true
			case "unknown-receipt":
				api.unknownPut = true
			case "readback":
				api.badAfter = true
			case "unknown-field":
				api.unknownAfter = true
			case "owner":
				p.deny = true
			case "binding":
				e.native.journal.Quiesce.ControllerBinding = "sha256:" + strings.Repeat("c", 64)
			case "environment":
				p.snap.Interfaces[0].Addresses = p.snap.Interfaces[0].Addresses[:1]
			}
			if err := e.restoreNativeLocked(context.Background(), false); err == nil || !e.native.status.CleanupPending || len(*events) != 0 || p.flushes != 0 || w.releases != 0 {
				t.Fatal("DNS quiesce failure crossed OS barrier", *events, err)
			}
			if kind == "unknown-receipt" {
				api.mu.Lock()
				api.unknownPut = false
				api.mu.Unlock()
				if err := e.restoreNativeLocked(context.Background(), false); err != nil {
					t.Fatal("read-before-idempotent-stop retry", err)
				}
			}
		})
	}
}
func TestNativeInterceptionDNSQuiesceGoneDoesNotWriteForeignController(t *testing.T) {
	e, p, api, _, _ := nativeQuiesceRecoveryFixture(t, false)
	p.gone = true
	if err := e.restoreNativeLocked(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if api.requests != 0 {
		t.Fatal("gone old process sent HTTP credentials to new endpoint")
	}
}
func TestNativeInterceptionDNSQuiesceJournalRejectsUntrustedMaterial(t *testing.T) {
	e, _, _, _, _ := nativeQuiesceRecoveryFixture(t, false)
	raw, err := json.Marshal(e.native.journal)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), strings.Repeat("q", 32)) || strings.Contains(string(raw), "subscriptions.example") {
		t.Fatal("secret/source URL persisted")
	}
	for _, change := range []func(*nativeDNSQuiescePlan){func(p *nativeDNSQuiescePlan) { p.Kernel = "v1.19.31" }, func(p *nativeDNSQuiescePlan) { p.After.Tun.AutoRoute = true }, func(p *nativeDNSQuiescePlan) { p.After.Fake4 = "198.18.0.0/16" }, func(p *nativeDNSQuiescePlan) { p.Upstream = netip.MustParseAddrPort("8.8.8.8:53") }, func(p *nativeDNSQuiescePlan) { p.Binding = "sha256:" + strings.Repeat("e", 64) }} {
		var j nativeJournal
		if json.Unmarshal(raw, &j) != nil {
			t.Fatal("fixture")
		}
		change(j.Quiesce)
		if err := saveNativeJournal(e.native.path, j); err == nil {
			t.Fatal("untrusted quiesce material persisted")
		}
	}
}
