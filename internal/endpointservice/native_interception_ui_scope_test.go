package endpointservice

import (
	"context"
	"errors"
	api "github.com/opensoha/soha-contracts/gen/go/sohaapi"
	"net/netip"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func nativeScopePeer(n *nativeInterception) NativePeer {
	return NativePeer{owner: n.uiOwner, pid: n.uiPeerPID, session: &nativeTestSession{owner: n.uiOwner}}
}
func TestNativeUIScopeOperatorBindingAndPrincipalAreRequired(t *testing.T) {
	for _, kind := range []string{"missing-binding", "missing-host", "wrong-user", "mapped-other-user"} {
		t.Run(kind, func(t *testing.T) {
			e, p, peer := nativeTestExecutor(t)
			n := e.native
			switch kind {
			case "missing-binding":
				n.uiExpectedUser = ""
			case "missing-host":
				n.uiScope.Authenticated = false
			case "wrong-user":
				n.uiScope.UserID = "other"
			case "mapped-other-user":
				c := e.previousMihomo.Configuration
				c.Projection = &api.NetworkProxyEmployeeProjection{Credential: api.NetworkProxyEmployeeCredential{UserID: "other"}}
				e.previousMihomo.Configuration = c
			}
			if _, err := e.SetInterception(context.Background(), peer, InterceptionIntent{RequestID: "enable", SystemProxy: true}); err == nil || p.writes != 0 {
				t.Fatal("UI scope bypassed operator/current principal binding")
			}
		})
	}
}
func TestNativeUIScopeChangedServerOrUserRestoresBeforeNewEnable(t *testing.T) {
	for _, kind := range []string{"user", "server", "logout", "http"} {
		t.Run(kind, func(t *testing.T) {
			e, p, peer := nativeTestExecutor(t)
			if _, err := e.SetInterception(context.Background(), peer, InterceptionIntent{RequestID: "enable", SystemProxy: true}); err != nil {
				t.Fatal(err)
			}
			scope := e.native.uiScope
			scope.Generation++
			switch kind {
			case "user":
				scope.UserID = "other-user"
			case "server":
				scope.ServerURL = "https://other.example.test"
			case "logout":
				scope.Authenticated = false
				scope.UserID = ""
			case "http":
				scope.ServerURL = "http://remote.example.test"
			}
			status, err := e.SetNativeUIScope(context.Background(), nativeScopePeer(e.native), scope)
			if err != nil || status.SystemProxy || status.TUN || status.State != interceptionSuspended || p.restores != 1 {
				t.Fatal("identity change did not restore", status, err)
			}
			if _, err = e.SetInterception(context.Background(), peer, InterceptionIntent{RequestID: "new-enable", ExpectedGeneration: status.Generation, SystemProxy: true}); err == nil {
				t.Fatal("new unbound account reused old configuration")
			}
		})
	}
}
func TestNativeUIScopeLateGenerationAndRetiredEpochDoNotRenew(t *testing.T) {
	e, _, _ := nativeTestExecutor(t)
	n := e.native
	initial := n.uiLease.Load()
	scope := n.uiScope
	scope.Generation = 0
	if _, err := e.SetNativeUIScope(context.Background(), nativeScopePeer(n), scope); err == nil || n.uiLease.Load() != initial {
		t.Fatal("invalid generation renewed UI")
	}
	newer := n.uiScope
	newer.Generation++
	if _, err := e.SetNativeUIScope(context.Background(), nativeScopePeer(n), newer); err != nil {
		t.Fatal(err)
	}
	seen := n.uiLease.Load()
	old := newer
	old.Generation--
	if _, err := e.SetNativeUIScope(context.Background(), nativeScopePeer(n), old); err == nil || n.uiLease.Load() != seen {
		t.Fatal("late scope renewed UI")
	}
	rollover := newer
	rollover.Epoch = "new-process-native-epoch"
	rollover.Generation = 1
	if _, err := e.SetNativeUIScope(context.Background(), nativeScopePeer(n), rollover); err != nil {
		t.Fatal(err)
	}
	seen = n.uiLease.Load()
	newer.Generation += 10
	if _, err := e.SetNativeUIScope(context.Background(), nativeScopePeer(n), newer); err == nil || n.uiLease.Load() != seen {
		t.Fatal("retired host revived scope")
	}
}
func TestNativeUIScopeExpiredAtRPCEntryCannotReviveNative(t *testing.T) {
	e, p, peer := nativeTestExecutor(t)
	if _, err := e.SetInterception(context.Background(), peer, InterceptionIntent{RequestID: "enable", SystemProxy: true}); err != nil {
		t.Fatal(err)
	}
	n := e.native
	n.uiLease.Store(time.Now().Add(-time.Second).UnixNano())
	scope := n.uiScope
	status, err := e.SetNativeUIScope(context.Background(), nativeScopePeer(n), scope)
	if err != nil || status.State != interceptionSuspended || status.SystemProxy || status.DesiredSystemProxy || p.restores != 1 {
		t.Fatal("late heartbeat revived expired native", status, err)
	}
	status, err = e.SetNativeUIScope(context.Background(), nativeScopePeer(n), scope)
	if err != nil || status.SystemProxy || p.writes != 1 {
		t.Fatal("scope heartbeat enabled native automatically", status, err)
	}
}
func TestNativeUIScopeLeaseIsIndependentOfOldCoreDeadline(t *testing.T) {
	e, _, _ := nativeTestExecutor(t)
	n := e.native
	e.previousMihomo.Configuration.EnforcementUntil = time.Now().Add(time.Second)
	scope := n.uiScope
	if _, err := e.SetNativeUIScope(context.Background(), nativeScopePeer(n), scope); err != nil {
		t.Fatal(err)
	}
	if time.Until(time.Unix(0, n.uiLease.Load())) < 25*time.Second {
		t.Fatal("UI last-seen was clipped to an old Core deadline")
	}
	e.previousMihomo.Configuration.EnforcementUntil = time.Now().Add(time.Minute)
	if reason := n.uiScopeReason(&e.previousMihomo.Configuration); reason != "" {
		t.Fatal("renewed Core kept old UI cap", reason)
	}
}
func TestNativeUIScopeExpiredGuardClosesWithoutWatcher(t *testing.T) {
	e, p, peer := nativeTestExecutor(t)
	n := e.native
	n.guard.set(&nativeEgressBinding{snapshot: p.snap, session: peer.session, until: time.Now().Add(time.Minute), uiLease: &n.uiLease}, false)
	n.uiLease.Store(time.Now().Add(-time.Second).UnixNano())
	if _, err := n.guard.DialPinned(context.Background(), "tcp", netip.MustParseAddrPort("192.0.2.10:443")); err == nil {
		t.Fatal("expired UI scope reached physical dial")
	}
	n.guard.mu.Lock()
	blocked := n.guard.blocked
	n.guard.mu.Unlock()
	if !blocked {
		t.Fatal("expired scope did not close old business")
	}
}
func TestNativeUIScopeBindingOnlyTrustsHTTPSOrLoopbackHTTP(t *testing.T) {
	for _, url := range []string{"http://remote.example.test", "ftp://control.example.test"} {
		if _, _, err := (Config{NativeUIServerURL: url, NativeUIUserID: "core-user-a"}).nativeUIBinding(); err == nil {
			t.Fatal("untrusted origin authorized Native", url)
		}
	}
	if _, _, err := (Config{NativeUIServerURL: "http://127.0.0.1:8000", NativeUIUserID: "core-user-a"}).nativeUIBinding(); err != nil {
		t.Fatal(err)
	}
}

func TestNativeUIScopeTrustedOriginJoinsControlExclusions(t *testing.T) {
	for _, trusted := range []bool{true, false} {
		config := Config{StateDirectory: t.TempDir(), ControlURL: "https://control.example.test", IngestURL: "https://ingest.example.test", NativeUIServerURL: "https://ui.example.test", NativeUIUserID: "core-user-a"}
		if !trusted {
			config.NativeUIServerURL = "http://ui.example.test"
		}
		e := &CoordinatedExecutor{}
		if err := e.ConfigureNativeInterception(config, nil); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, host := range e.native.controls {
			if host == "ui.example.test" {
				found = true
			}
		}
		if found != trusted {
			t.Fatal("UI origin exclusion did not follow trusted operator binding", trusted, e.native.controls)
		}
		if trusted {
			deadline := time.Now().Add(time.Minute)
			dns := &nativeDNSProxy{until: deadline, records: []DNSRecord{{Hostname: "control.example.test", Addresses: []string{"192.0.2.20"}, ExpiresAt: deadline}, {Hostname: "ingest.example.test", Addresses: []string{"192.0.2.21"}, ExpiresAt: deadline}, {Hostname: "ui.example.test", Addresses: []string{"203.0.113.24"}, ExpiresAt: deadline}}}
			addresses, err := nativeControlAddresses(context.Background(), dns, e.native.controls)
			if err != nil {
				t.Fatal(err)
			}
			_, platform, _ := nativeTestExecutor(t)
			captures, exceptions, err := nativePlanCaptures(platform.snap, TunnelReadback{}, addresses)
			if err != nil {
				t.Fatal(err)
			}
			ui := netip.MustParseAddr("203.0.113.24")
			approved := false
			for _, prefix := range exceptions {
				if prefix == netip.PrefixFrom(ui, 32) {
					approved = true
				}
			}
			for _, prefix := range captures {
				if prefix.Contains(ui) {
					t.Fatal("UI origin captured by owned TUN")
				}
			}
			if !approved {
				t.Fatal("UI origin missing exact pre-TUN exclusion")
			}
		}
	}
}

func TestNativeUIScopeBoundDeliveryModesKeepOSAndCoreIdentitySeparate(t *testing.T) {
	for _, mode := range []string{"direct", "app_subscription", "mapped"} {
		t.Run(mode, func(t *testing.T) {
			e, p, peer := nativeTestExecutor(t)
			if peer.owner.UserID == e.native.uiScope.UserID {
				t.Fatal("fixture conflated OS and Core users")
			}
			c := e.previousMihomo.Configuration
			switch mode {
			case "direct":
				c.DeliveryMode = "direct_subscription"
			case "app_subscription":
				c.Mode = "app_subscription"
			case "mapped":
				c.Projection = &api.NetworkProxyEmployeeProjection{Credential: api.NetworkProxyEmployeeCredential{UserID: "core-user-a"}}
			}
			e.previousMihomo.Configuration = c
			if reason := e.native.uiScopeReason(&c); reason != "" {
				t.Fatal("explicit binding rejected delivery mode", reason)
			}
			// The bounded fixture has no subscription runtime. Assert its shared
			// authorization gate here; existing subscription tests cover apply.
			if mode == "app_subscription" {
				return
			}
			status, err := e.SetInterception(context.Background(), peer, InterceptionIntent{RequestID: "enable", SystemProxy: true})
			if err != nil || !status.SystemProxy || p.writes != 1 {
				t.Fatal("explicit bound delivery refused", status, err)
			}
		})
	}
}

func TestNativeUIScopeWrongActorAndStaleSessionCannotRenew(t *testing.T) {
	for _, kind := range []string{"wrong-pid", "wrong-session", "stale-session"} {
		t.Run(kind, func(t *testing.T) {
			e, _, _ := nativeTestExecutor(t)
			n := e.native
			scope := n.uiScope
			scope.Generation++
			peer := nativeScopePeer(n)
			switch kind {
			case "wrong-pid":
				peer.pid++
			case "wrong-session":
				peer.owner.SessionID = "other-session"
				peer.session = &nativeTestSession{owner: peer.owner}
			case "stale-session":
				peer.session = &nativeTestSession{owner: peer.owner, stale: true}
			}
			before := n.uiLease.Load()
			if _, err := e.SetNativeUIScope(context.Background(), peer, scope); err == nil || n.uiLease.Load() != before || n.uiScope.Generation == scope.Generation {
				t.Fatal("untrusted actor renewed scope")
			}
		})
	}
}

// Extend the existing App subscription fixture with strict actual-applied
// readback. It performs no subscription download or non-loopback connection.
type nativeSubscriptionFixture struct {
	fakeMihomoRuntime
	expectedURL, expectedSelection string
}

func (r *nativeSubscriptionFixture) Verify(_ context.Context, c *MihomoConfiguration) error {
	if c == nil || !reflect.DeepEqual(*c, r.lastConfiguration) || r.expectedURL != "" && (r.lastSubscriptionURL != r.expectedURL || r.lastSelectedProxy != r.expectedSelection) {
		return errors.New("actual subscription configuration drift")
	}
	return nil
}

func (r *nativeSubscriptionFixture) selectLocal(_ context.Context, c MihomoConfiguration, group, node string) error {
	if group != c.SelectorGroup || (node != "edge-a" && node != "edge-b") {
		return errors.New("node outside authorized group")
	}
	r.lastSelectedProxy = node
	r.expectedSelection = node
	return nil
}

type nativeSubscriptionWGFixture struct{ fakeConfigurationExecutor }

func (w *nativeSubscriptionWGFixture) Verify(context.Context, ConfigurationDesired, time.Time) ApplyOutcome {
	return w.outcome
}
func TestNativeUIScopeAppSubscriptionEnableACKAndRestore(t *testing.T) {
	e, p, peer := nativeTestExecutor(t)
	r := &nativeSubscriptionFixture{fakeMihomoRuntime: fakeMihomoRuntime{proxies: []string{"edge-a", "edge-b"}}}
	e.mihomo = r
	e.wireGuard = &nativeSubscriptionWGFixture{fakeConfigurationExecutor: fakeConfigurationExecutor{outcome: ApplyOutcome{Status: "applied", ReadbackHash: emptyReadbackHash()}}}
	e.appStatePath = filepath.Join(t.TempDir(), "app-subscription")
	c := appMihomoConfiguration(9090)
	c.EnforcementUntil = time.Now().Add(time.Minute)
	desired := ConfigurationDesired{ConfigurationVersion: 1, PolicyVersion: 1, ValidUntil: c.EnforcementUntil, Mihomo: &c}
	if out := e.Apply(context.Background(), desired, time.Now()); out.Status != "applied" {
		t.Fatal(out)
	}
	const subscription = "https://subscriptions.example.test/fixture"
	if status, err := e.ConfigureMihomoApp(context.Background(), MihomoAppInput{SubscriptionURL: subscription}); err != nil || !status.Configured {
		t.Fatal(status, err)
	}
	if status, err := e.SelectMihomoApp(context.Background(), "edge-b"); err != nil || status.SelectedProxy != "edge-b" {
		t.Fatal(status, err)
	}
	r.expectedURL, r.expectedSelection = subscription, "edge-b"
	before := e.Verify(context.Background(), desired, time.Now())
	if before.Status != "applied" {
		t.Fatal("baseline ACK", before)
	}
	original := cloneMihomoConfiguration(r.lastConfiguration)
	status, err := e.SetInterception(context.Background(), peer, InterceptionIntent{RequestID: "enable-app-subscription", SystemProxy: true})
	if err != nil || status.State != interceptionActive || !status.SystemProxy || p.writes != 1 {
		t.Fatal(status, err)
	}
	if r.lastSubscriptionURL != subscription || r.lastSelectedProxy != "edge-b" || r.lastConfiguration.NativePlan == nil {
		t.Fatal("subscription source/selection lost during Native apply")
	}
	active := e.Verify(context.Background(), desired, time.Now())
	if active.Status != "applied" || active.ReadbackHash != before.ReadbackHash {
		t.Fatal("Native changed immutable Core ACK", before, active)
	}
	// The real public selection entry keeps Native active and advances only
	// the authorized selection, preserving the immutable source/profile.
	if selected, err := e.SelectMihomoApp(context.Background(), "edge-a"); err != nil || selected.SelectedProxy != "edge-a" {
		t.Fatal("authorized active selection", selected, err)
	}
	if view := e.LocalProxyInterception(); !view.SystemProxy || view.Generation != status.Generation || p.restores != 0 {
		t.Fatal("authorized selection stopped Native", view)
	}
	selectedACK := e.Verify(context.Background(), desired, time.Now())
	expectedReadback := expectedMihomoReadback(c)
	expectedReadback.SelectedProxy = "edge-a"
	expectedACK := combinedReadbackHash(emptyReadbackHash(), mihomoConfigurationReadbackHash(&c, expectedReadback))
	if selectedACK.Status != "applied" || selectedACK.ReadbackHash != expectedACK {
		t.Fatal("authorized selection ACK", selectedACK)
	}
	// URL/state and actual selected-node drift cannot use ACK normalization.
	e.previousMihomo.AppState.SubscriptionURL = "https://other.example.test/changed"
	if err := e.verifyNativeLocked(context.Background()); err == nil {
		t.Fatal("private source drift normalized")
	}
	if e.native.subscriptionState.SubscriptionURL != subscription {
		t.Fatal("mutable state aliased trusted subscription snapshot")
	}
	e.previousMihomo.AppState.SubscriptionURL = subscription
	r.lastSelectedProxy = "edge-b"
	if err := e.verifyNativeLocked(context.Background()); err == nil {
		t.Fatal("actual selected node drift normalized")
	}
	r.lastSelectedProxy = "edge-a"
	// Strict verifier rejects an engine drift while keeping the trusted plan intact.
	r.lastConfiguration.MixedPort++
	if err := e.verifyNativeLocked(context.Background()); err == nil {
		t.Fatal("actual engine drift normalized")
	}
	r.lastConfiguration.MixedPort--
	stopped, err := e.SetInterception(context.Background(), NativePeer{owner: peer.owner, pid: peer.pid, session: &nativeTestSession{owner: peer.owner}}, InterceptionIntent{RequestID: "stop-app-subscription", ExpectedGeneration: status.Generation})
	if err != nil || stopped.SystemProxy || stopped.CleanupPending || p.restores != 1 {
		t.Fatal(stopped, err)
	}
	if !reflect.DeepEqual(r.lastConfiguration, original) || r.lastSubscriptionURL != subscription || r.lastSelectedProxy != "edge-a" {
		t.Fatal("original App subscription configuration was not restored")
	}
	after := e.Verify(context.Background(), desired, time.Now())
	if after.Status != "applied" || after.ReadbackHash != selectedACK.ReadbackHash {
		t.Fatal("restored subscription ACK", after)
	}
	if view, err := e.SetInterception(context.Background(), NativePeer{owner: peer.owner, pid: peer.pid, session: &nativeTestSession{owner: peer.owner}}, InterceptionIntent{RequestID: "reenable-before-clear", ExpectedGeneration: stopped.Generation, SystemProxy: true}); err != nil || !view.SystemProxy {
		t.Fatal(view, err)
	}
	beforeClear, err := loadMihomoAppState(e.appStatePath)
	if err != nil {
		t.Fatal(err)
	}
	ownedValue := p.value
	p.value = nativeValue{Present: true, Proxy: &nativeProxyValue{Number: 99}}
	disabledBefore := r.disableCalls
	if _, err = e.ClearMihomoApp(context.Background()); err == nil {
		t.Fatal("clear bypassed failed Native restore")
	}
	stillConfigured, err := loadMihomoAppState(e.appStatePath)
	if err != nil || !reflect.DeepEqual(stillConfigured, beforeClear) || r.disableCalls != disabledBefore || !e.LocalProxyInterception().CleanupPending {
		t.Fatal("failed restore committed clear", stillConfigured, err)
	}
	p.value = ownedValue
	if cleared, err := e.ClearMihomoApp(context.Background()); err != nil || cleared.Configured {
		t.Fatal("clear", cleared, err)
	}
	if view := e.LocalProxyInterception(); view.SystemProxy || view.CleanupPending || p.restores != 2 {
		t.Fatal("clear left Native OS interception", view)
	}
}
