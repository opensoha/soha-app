//go:build !windows

package endpointservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go.yaml.in/yaml/v3"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type nativeStageAPI struct {
	standard                  *mihomoControllerFixture
	mu                        sync.Mutex
	tun                       nativeTunReadback
	native                    atomic.Bool
	puts, patches, violations int
	journal                   string
	cancelAfterPatch          context.CancelFunc
	unknownPUT                bool
	beforeRequest             func(http.ResponseWriter, *http.Request) bool
	listener                  net.Listener
}

func (a *nativeStageAPI) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	a.mu.Lock()
	before := a.beforeRequest
	a.mu.Unlock()
	if before != nil && before(w, r) {
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+a.standard.secret {
		w.WriteHeader(401)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/version" {
		json.NewEncoder(w).Encode(map[string]string{"version": "Mihomo Meta v1.19.30"})
		return
	}
	if r.Method == "GET" && r.URL.Path == "/configs" {
		a.standard.mu.Lock()
		d := a.standard.document
		a.standard.mu.Unlock()
		a.mu.Lock()
		tun := a.tun
		a.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"mixed-port": d.MixedPort, "port": d.HTTPPort, "socks-port": d.SOCKSPort, "redir-port": d.RedirectPort, "tproxy-port": d.TProxyPort, "mode": d.Mode, "allow-lan": d.AllowLAN, "bind-address": d.BindAddress, "ipv6": d.IPv6, "tun": tun})
		return
	}
	if r.Method == "PATCH" && r.URL.Path == "/configs" {
		a.standard.serveHTTP(w, r)
		if a.native.Load() {
			a.mu.Lock()
			a.patches++
			cancel := a.cancelAfterPatch
			a.mu.Unlock()
			if cancel != nil {
				cancel()
			}
		}
		return
	}
	if r.Method == "PUT" && r.URL.Path == "/configs" {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		if err != nil {
			w.WriteHeader(400)
			return
		}
		var envelope struct{ Payload string }
		if json.Unmarshal(raw, &envelope) != nil {
			w.WriteHeader(400)
			return
		}
		defaults := nativeQuiesceState(MihomoConfiguration{DNSMode: "disabled"})
		document := struct {
			Tun nativeTunReadback `yaml:"tun"`
			DNS struct {
				Fake4 string `yaml:"fake-ip-range"`
			} `yaml:"dns"`
			IPv6 bool `yaml:"ipv6"`
		}{Tun: defaults.Tun, IPv6: true}
		document.DNS.Fake4 = defaults.Fake4
		if yaml.Unmarshal([]byte(envelope.Payload), &document) != nil {
			w.WriteHeader(400)
			return
		}
		prefix, err := netip.ParsePrefix(document.DNS.Fake4)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		document.Tun.Inet4Address = []netip.Prefix{netip.PrefixFrom(prefix.Addr(), 30)}
		if !document.IPv6 {
			document.Tun.Inet6Address = nil
		}
		native := a.native.Load()
		a.mu.Lock()
		unknown := a.unknownPUT
		if native {
			a.puts++
			journal, readErr := loadNativeJournal(a.journal)
			if readErr != nil || journal.Quiesce == nil || !document.IPv6 || !nativeTunEqual(document.Tun, journal.Quiesce.After.Tun) {
				a.violations++
				a.mu.Unlock()
				w.WriteHeader(409)
				return
			}
		}
		a.tun = document.Tun
		a.mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(raw))
		if native && unknown {
			recorder := httptest.NewRecorder()
			a.standard.serveHTTP(recorder, r)
			if recorder.Code != 204 {
				w.WriteHeader(recorder.Code)
				return
			}
			if hijack, ok := w.(http.Hijacker); ok {
				conn, _, err := hijack.Hijack()
				if err == nil {
					conn.Close()
				}
			}
			return
		}
		a.standard.serveHTTP(w, r)
		return
	}
	a.standard.serveHTTP(w, r)
}

type nativeStagePlatform struct {
	*nativeTestPlatform
	endpoint netip.AddrPort
	process  *mihomoProcess
	mu       sync.Mutex
	record   nativeOwnedProcessIdentity
	alive    atomic.Bool
	dialErr  error
}

func (p *nativeStagePlatform) CaptureOwnedProcess(ctx context.Context, s nativeSession, proof nativeOwnedProcessProof) (nativeOwnedProcessIdentity, error) {
	if err := s.Validate(ctx, false); err != nil {
		return nativeOwnedProcessIdentity{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.record = nativeOwnedProcessIdentity{Proof: proof, Incarnation: "fixture-" + proof.ProcessEpoch}
	p.alive.Store(true)
	p.process.mu.Lock()
	kill := p.process.kill
	p.process.kill = func() error { p.alive.Store(false); return kill() }
	p.process.mu.Unlock()
	return p.record, nil
}
func (p *nativeStagePlatform) DialOwnedController(ctx context.Context, s nativeSession, record nativeOwnedProcessIdentity, endpoint netip.AddrPort) (net.Conn, bool, error) {
	if err := s.Validate(ctx, true); err != nil {
		return nil, false, err
	}
	p.mu.Lock()
	same := reflect.DeepEqual(record, p.record)
	dialErr := p.dialErr
	p.mu.Unlock()
	if dialErr != nil {
		return nil, false, dialErr
	}
	if !same || endpoint != p.endpoint {
		return nil, false, errors.New("fixture process pin mismatch")
	}
	if !p.alive.Load() {
		return nil, true, nil
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", endpoint.String())
	return conn, false, err
}
func (p *nativeStagePlatform) RecoverOwnedProcess(context.Context, nativeSession, nativeOwnedProcessIdentity) (string, error) {
	if p.alive.Load() {
		return "", errors.New("old child still alive")
	}
	return "gone", nil
}
func (p *nativeStagePlatform) RecoverySnapshot(context.Context, nativeSession) (nativeSnapshot, error) {
	return p.snap, nil
}

func nativeStageFixture(t *testing.T) (*CoordinatedExecutor, *MihomoController, *nativeStagePlatform, *nativeStageAPI, NativePeer, ConfigurationDesired) {
	t.Helper()
	secret := strings.Repeat("a", 32)
	api := &nativeStageAPI{standard: &mihomoControllerFixture{secret: secret}}
	server := httptest.NewServer(http.HandlerFunc(api.serve))
	api.listener = server.Listener
	t.Cleanup(server.Close)
	controller, err := NewMihomoController(server.URL, secret)
	if err != nil {
		t.Fatal(err)
	}
	processController, _ := processFixture(t)
	process := processController.process
	raw := []byte("#!/bin/sh\ncase \"$1\" in\n-v) echo Mihomo Meta v1.19.30; exit 0;;\n-t) exit 0;;\nesac\nexec sleep 60\n")
	if err = os.WriteFile(process.config.Binary, raw, 0700); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	process.config.SHA256 = hex.EncodeToString(hash[:])
	process.config.Version = "Mihomo Meta v1.19.30"
	controller.process = process
	e, base, peer := nativeTestExecutor(t)
	p := &nativeStagePlatform{nativeTestPlatform: base, endpoint: netip.MustParseAddrPort(strings.TrimPrefix(server.URL, "http://")), process: process}
	p.snap.Interfaces[0].Addresses = append(p.snap.Interfaces[0].Addresses, netip.MustParsePrefix("fd04:122::2/64"))
	e.native.platform = p
	e.native.guard.platform = p
	e.mihomo = controller
	e.wireGuard = &nativeSubscriptionWGFixture{fakeConfigurationExecutor: fakeConfigurationExecutor{outcome: ApplyOutcome{Status: "applied", ReadbackHash: emptyReadbackHash()}}}
	c, projection := bundleFixture(time.Now())
	c.Projection = &projection
	c.ControllerPort = controller.port
	e.native.uiExpectedUser = projection.Credential.UserID
	e.native.uiScope.UserID = projection.Credential.UserID
	desired := ConfigurationDesired{PolicyVersion: 1, ValidUntil: c.EnforcementUntil, Mihomo: &c}
	if outcome := e.Apply(context.Background(), desired, time.Now()); outcome.Status != "applied" {
		t.Fatal(outcome)
	}
	api.journal = e.native.path
	t.Cleanup(func() { api.native.Store(false); e.Disable(context.Background()) })
	return e, controller, p, api, peer, desired
}
func TestNativeInterceptionQuiescePlanBeforeNativePUTAndOrdinaryRestore(t *testing.T) {
	e, c, _, api, peer, desired := nativeStageFixture(t)
	before := e.Verify(context.Background(), desired, time.Now())
	if before.Status != "applied" {
		t.Fatal(before)
	}
	api.native.Store(true)
	status, err := e.SetInterception(context.Background(), peer, InterceptionIntent{RequestID: "native-start", SystemProxy: true})
	api.native.Store(false)
	if err != nil || !status.SystemProxy {
		t.Fatal(status, err)
	}
	api.mu.Lock()
	puts, patches, violations := api.puts, api.patches, api.violations
	api.mu.Unlock()
	if puts != 1 || patches < 1 || violations != 0 || e.native.journal.Quiesce == nil || e.native.journal.Quiesce.DNS {
		t.Fatal("Native staging bypassed WAL/two-state boundary", puts, patches, violations)
	}
	active := e.Verify(context.Background(), desired, time.Now())
	if active.Status != "applied" || active.ReadbackHash != before.ReadbackHash {
		t.Fatal("canonical ACK changed", before, active)
	}
	api.native.Store(true)
	if err := c.quiesceOwnedNativeIngress(context.Background(), e.native.session, e.native.platform, e.native.journal.Quiesce); err != nil {
		t.Fatal(err)
	}
	api.native.Store(false)
	api.mu.Lock()
	noDNSPuts := api.puts
	api.mu.Unlock()
	if noDNSPuts != puts {
		t.Fatal("SystemProxy-only added a DNS stop PUT", noDNSPuts, puts)
	}
	stopped, err := e.SetInterception(context.Background(), NativePeer{owner: peer.owner, pid: peer.pid, session: &nativeTestSession{owner: peer.owner}}, InterceptionIntent{RequestID: "native-stop", ExpectedGeneration: status.Generation})
	if err != nil || stopped.CleanupPending || stopped.SystemProxy || c.nativeControl != nil || e.native.journal.Quiesce != nil {
		t.Fatal("ordinary restore", stopped, err)
	}
	after := e.Verify(context.Background(), desired, time.Now())
	if after.Status != "applied" || after.ReadbackHash != before.ReadbackHash {
		t.Fatal("ordinary mode regression", after)
	}
}
func TestNativeInterceptionQuiesceStagingCancellationAndUnknownPUT(t *testing.T) {
	for _, kind := range []string{"before-patch", "after-patch", "unknown-put"} {
		t.Run(kind, func(t *testing.T) {
			e, c, p, api, peer, _ := nativeStageFixture(t)
			n := e.native
			n.session = peer.session
			base := cloneMihomoConfiguration(e.previousMihomo.Configuration)
			n.base = &base
			proof, err := c.nativeOwnedProof()
			if err != nil {
				t.Fatal(err)
			}
			record, err := p.CaptureOwnedProcess(context.Background(), peer.session, proof)
			if err != nil {
				t.Fatal(err)
			}
			n.journal = nativeJournal{Version: 1, Pending: true, Generation: 1, Owner: peer.owner, Binding: nativeBindingHash(n.identity, base), Process: &record, ProcessEpoch: proof.ProcessEpoch}
			n.guard.set(&nativeEgressBinding{snapshot: p.snap, session: peer.session, until: base.EnforcementUntil, uiLease: &n.uiLease}, false)
			next := cloneMihomoConfiguration(base)
			next.NativePlan = &nativeEnginePlan{DNSUpstream: netip.MustParseAddrPort("127.0.0.1:32001"), NodeInterfaces: map[string]string{}}
			if err = e.prepareNativeQuiesce(context.Background(), next); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			api.mu.Lock()
			if kind == "after-patch" {
				api.cancelAfterPatch = cancel
			}
			if kind == "unknown-put" {
				api.unknownPUT = true
			}
			api.mu.Unlock()
			if kind == "before-patch" {
				cancel()
			}
			api.native.Store(true)
			err = e.applyNativeEngineLocked(ctx, next)
			api.native.Store(false)
			if err == nil {
				t.Fatal("cancel/unknown apply succeeded")
			}
			api.mu.Lock()
			puts, violations := api.puts, api.violations
			api.cancelAfterPatch = nil
			api.unknownPUT = false
			api.mu.Unlock()
			if violations != 0 || kind != "unknown-put" && puts != 0 || kind == "unknown-put" && puts != 1 {
				t.Fatal("unrecorded third state", puts, violations)
			}
			if err = e.restoreNativeLocked(context.Background(), true); err != nil {
				t.Fatal("cancel/unknown cleanup", err)
			}
			if n.status.CleanupPending || n.journal.Quiesce != nil || c.nativeControl != nil || c.nativeControlRequired {
				t.Fatal("cancel recovery retained active scope")
			}
		})
	}
}

func TestNativeInterceptionQuiesceStoppingCurrentProcessKeepsItsLock(t *testing.T) {
	e, c, p, _, peer, _ := nativeStageFixture(t)
	proof, err := c.nativeOwnedProof()
	if err != nil {
		t.Fatal(err)
	}
	record, err := p.CaptureOwnedProcess(context.Background(), peer.session, proof)
	if err != nil {
		t.Fatal(err)
	}
	e.native.journal.Process = &record
	p.process.mu.Lock()
	p.process.status.State = "stopping"
	p.process.mu.Unlock()
	defer func() {
		p.process.mu.Lock()
		p.process.status.State = "running"
		p.process.mu.Unlock()
		e.native.journal.Process = nil
	}()
	unlock, err := e.nativeRestoreOwnerLock()
	if err != nil {
		t.Fatal("live stopping cmd was misclassified orphan", err)
	}
	unlock()
	if e.native.recoveryLockHeld {
		t.Fatal("current child lock became an orphan recovery lock")
	}
	if other, err := lockMihomoProcess(filepath.Join(p.process.directory, "owner.lock")); err == nil {
		other()
		t.Fatal("current child's owner lock was released")
	}
	wrong := record
	wrong.Proof.ProcessEpoch = strings.Repeat("c", 32)
	e.native.journal.Process = &wrong
	if unlock, err := e.nativeRestoreOwnerLock(); err == nil {
		unlock()
		t.Fatal("different current identity accepted during stopping")
	}
}
