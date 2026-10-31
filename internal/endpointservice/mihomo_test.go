package endpointservice

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func TestMihomoControllerAppliesSafeProxyOnlyConfiguration(t *testing.T) {
	const secret = "test-mihomo-controller-secret-123456"
	server, fixture := newMihomoControllerFixture(t, secret)
	controller, err := NewMihomoController(server.URL, secret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = controller.Disable(ctx)
	})
	_, port, _ := mihomoOrigin(server.URL)
	configuration := managedMihomoConfiguration(port)
	configuration.SourceType, configuration.SelectedProxy, configuration.SubscriptionURL = "manual_node", "", ""
	configuration.ManualNode = &MihomoManualNode{Protocol: "https", Server: "192.0.2.8", Port: 8443}
	configuration.Protection.CIDRs = []string{"10.30.0.0/16"}
	configuration.Protection.Hosts = []string{"protected.example"}
	readback, err := controller.Apply(context.Background(), configuration)
	if err != nil || readback.ProfileID != configuration.ProfileID || readback.SelectedProxy != mihomoManualProxyName {
		t.Fatalf("Apply() = %#v, %v", readback, err)
	}
	fixture.mu.Lock()
	fixture.connections = true
	payload, probes := fixture.payload, fixture.probes
	fixture.mu.Unlock()
	if probes != 2 {
		t.Fatalf("authenticated guard probes = %d", probes)
	}
	snapshot, err := controller.ProxyFlowSnapshot(context.Background())
	encoded, _ := json.Marshal(snapshot)
	if err != nil || snapshot.DownloadTotal != 4096 || snapshot.UploadTotal != 1024 || snapshot.ActiveConnections != 1 || snapshot.SelectedProxy != mihomoManualProxyName || strings.Contains(string(encoded), "must-not-leave-endpoint") {
		t.Fatalf("ProxyFlowSnapshot() = %#v, %v", snapshot, err)
	}
	for _, required := range []string{"mixed-port: 0", "allow-lan: false", `bind-address: "127.0.0.1"`, "enable: false", "10.20.0.0/16,soha-egress-direct", "DOMAIN-SUFFIX,protected.example,REJECT", "IP-CIDR,10.30.0.0/16,REJECT", "192.0.2.8"} {
		if !strings.Contains(payload, required) {
			t.Fatalf("mihomo payload omitted %q", required)
		}
	}
	if strings.Index(payload, "IP-CIDR,10.30.0.0/16,REJECT") > strings.Index(payload, "IP-CIDR,10.20.0.0/16,soha-egress-direct") || strings.Contains(payload, "0.0.0.0/0") || strings.Contains(payload, "proxy-providers:") {
		t.Fatal("protected order, route scope or pinned bootstrap changed")
	}
	if err := controller.Verify(context.Background(), &configuration); err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	fixture.failReset = true
	fixture.mu.Unlock()
	if err := controller.Disable(context.Background()); err == nil {
		t.Fatal("expected the controller reset to fail")
	}
	snapshot, err = controller.ProxyFlowSnapshot(context.Background())
	if err != nil || !snapshot.Active || snapshot.DownloadTotal != 4096 {
		t.Fatalf("failed reset lost proxy metrics: %#v, %v", snapshot, err)
	}
	fixture.mu.Lock()
	fixture.failReset = false
	fixture.mu.Unlock()
	if err := controller.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot, err = controller.ProxyFlowSnapshot(context.Background())
	if err != nil || snapshot.Active {
		t.Fatalf("successful reset retained active proxy metrics: %#v, %v", snapshot, err)
	}
}

func TestCoordinatedExecutorKeepsComponentsIndependent(t *testing.T) {
	wireGuard := &fakeConfigurationExecutor{outcome: ApplyOutcome{Status: "applied", ReadbackHash: emptyReadbackHash()}}
	mihomo := &fakeMihomoRuntime{applyErr: errors.New("controller unavailable")}
	executor, err := NewCoordinatedExecutor(wireGuard, mihomo)
	if err != nil {
		t.Fatal(err)
	}
	desired := ConfigurationDesired{ConfigurationVersion: 1, PolicyVersion: 1, ValidUntil: time.Now().Add(time.Minute), Mihomo: ptrMihomo(managedMihomoConfiguration(9090))}
	outcome := executor.Apply(context.Background(), desired, time.Now())
	if outcome.Status != "rejected" || wireGuard.applyCalls != 1 || wireGuard.disableCalls != 0 || mihomo.applyCalls != 1 {
		t.Fatalf("Apply() = %#v, wireguard=%#v mihomo=%#v", outcome, wireGuard, mihomo)
	}

	wireGuard.outcome = ApplyOutcome{Status: "rejected", ReadbackHash: emptyReadbackHash(), ReasonCode: "wireguard_failed"}
	mihomo.applyErr = nil
	_ = executor.Apply(context.Background(), desired, time.Now())
	if mihomo.applyCalls != 1 || executor.mihomoActive || wireGuard.disableCalls != 0 {
		t.Fatal("WireGuard failure must keep the proxy stopped without disabling the independent tunnel component")
	}
}

func TestCoordinatedExecutorStopsManagedMihomoAfterReplacementFailure(t *testing.T) {
	wireGuard := &fakeConfigurationExecutor{outcome: ApplyOutcome{Status: "applied", ReadbackHash: emptyReadbackHash()}}
	mihomo := &fakeMihomoRuntime{}
	executor, err := NewCoordinatedExecutor(wireGuard, mihomo)
	if err != nil {
		t.Fatal(err)
	}
	first := ConfigurationDesired{ConfigurationVersion: 1, PolicyVersion: 1, ValidUntil: time.Now().Add(time.Minute), Mihomo: ptrMihomo(managedMihomoConfiguration(9090))}
	if outcome := executor.Apply(context.Background(), first, time.Now()); outcome.Status != "applied" {
		t.Fatalf("first Apply() = %#v", outcome)
	}
	second := first
	second.ConfigurationVersion = 2
	second.Mihomo = ptrMihomo(managedMihomoConfiguration(9090))
	second.Mihomo.ProfileRevision = 2
	second.Mihomo.SelectedProxy = "edge-b"
	mihomo.applyErrOnce = errors.New("controller reload failed")
	if outcome := executor.Apply(context.Background(), second, time.Now()); outcome.Status != "rejected" || outcome.ReasonCode != "mihomo_apply_failed" {
		t.Fatalf("second Apply() = %#v", outcome)
	}
	if mihomo.applyCalls != 2 || mihomo.disableCalls < 2 || executor.mihomoActive || executor.appDesired != nil || wireGuard.disableCalls != 0 {
		t.Fatalf("old proxy restarted or failed to stop: runtime=%#v wireguard=%#v", mihomo, wireGuard)
	}
}

func TestCoordinatedExecutorPersistsAppSubscriptionWithoutExposingURL(t *testing.T) {
	wireGuard := &fakeConfigurationExecutor{outcome: ApplyOutcome{Status: "applied", ReadbackHash: emptyReadbackHash()}}
	mihomo := &fakeMihomoRuntime{proxies: []string{"edge-a", "edge-b"}}
	executor, err := NewCoordinatedExecutor(wireGuard, mihomo, filepath.Join(t.TempDir(), "mihomo-app.dpapi"))
	if err != nil {
		t.Fatal(err)
	}
	desired := ConfigurationDesired{ConfigurationVersion: 1, PolicyVersion: 1, ValidUntil: time.Now().Add(time.Minute), Mihomo: ptrMihomo(appMihomoConfiguration(9090))}
	if outcome := executor.Apply(context.Background(), desired, time.Now()); outcome.Status != "applied" {
		t.Fatalf("Apply() = %#v", outcome)
	}
	const subscriptionURL = "https://subscriptions.example.test/private?token=secret"
	status, err := executor.ConfigureMihomoApp(context.Background(), MihomoAppInput{SubscriptionURL: subscriptionURL})
	if err != nil || !status.Configured || status.SelectedProxy != "edge-a" || !slices.Equal(status.Proxies, []string{"edge-a", "edge-b"}) {
		t.Fatalf("ConfigureMihomoApp() = %#v, %v", status, err)
	}
	encoded, _ := json.Marshal(status)
	if strings.Contains(string(encoded), subscriptionURL) || strings.Contains(string(encoded), "token=secret") {
		t.Fatalf("app subscription URL leaked through status: %s", encoded)
	}
	status, err = executor.SelectMihomoApp(context.Background(), "edge-b")
	if err != nil || status.SelectedProxy != "edge-b" {
		t.Fatalf("SelectMihomoApp() = %#v, %v", status, err)
	}
	if err := executor.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewCoordinatedExecutor(wireGuard, mihomo, executor.appStatePath)
	if err != nil {
		t.Fatal(err)
	}
	if outcome := restarted.Apply(context.Background(), desired, time.Now()); outcome.Status != "applied" || mihomo.lastSubscriptionURL != subscriptionURL || mihomo.lastSelectedProxy != "edge-b" {
		t.Fatalf("restart Apply() = %#v, runtime=%#v", outcome, mihomo)
	}
}

func TestCoordinatedExecutorStopsFailedSelectionAndRetainsRepairState(t *testing.T) {
	mihomo := &fakeMihomoRuntime{proxies: []string{"edge-a", "edge-b"}}
	statePath := filepath.Join(t.TempDir(), "mihomo-app.dpapi")
	executor, err := NewCoordinatedExecutor(&fakeConfigurationExecutor{outcome: ApplyOutcome{Status: "applied", ReadbackHash: emptyReadbackHash()}}, mihomo, statePath)
	if err != nil {
		t.Fatal(err)
	}
	desired := ConfigurationDesired{ConfigurationVersion: 1, PolicyVersion: 1, ValidUntil: time.Now().Add(time.Minute), Mihomo: ptrMihomo(appMihomoConfiguration(9090))}
	if outcome := executor.Apply(context.Background(), desired, time.Now()); outcome.Status != "applied" {
		t.Fatalf("Apply() = %#v", outcome)
	}
	const subscriptionURL = "https://subscriptions.example.test/private?token=secret"
	if _, err := executor.ConfigureMihomoApp(context.Background(), MihomoAppInput{SubscriptionURL: subscriptionURL}); err != nil {
		t.Fatal(err)
	}
	mihomo.applyErrOnce = errors.New("selection failed")
	status, err := executor.SelectMihomoApp(context.Background(), "edge-b")
	if err == nil || status.Configured || status.SelectedProxy != "" || mihomo.applyCalls != 2 || executor.mihomoActive || executor.appDesired != nil {
		t.Fatalf("SelectMihomoApp() = %#v, %v runtime=%#v", status, err, mihomo)
	}
	state, err := loadMihomoAppState(statePath)
	if err != nil || state.SelectedProxy != "edge-a" || state.SubscriptionURL != subscriptionURL {
		t.Fatalf("persisted state = %#v, %v", state, err)
	}
	if outcome := executor.Apply(context.Background(), desired, time.Now()); outcome.Status != "applied" || !executor.appStatus.Configured || executor.appStatus.SelectedProxy != "edge-a" {
		t.Fatalf("fresh configuration could not recover the retained selection: %#v, %#v", outcome, executor.appStatus)
	}
}

func managedMihomoConfiguration(controllerPort int) MihomoConfiguration {
	return MihomoConfiguration{
		Mode: "managed_follow", SourceType: "managed_subscription", ProfileID: "mihomo-1", ProfileRevision: 1, MixedPort: 7890,
		ControllerPort: controllerPort, DNSMode: "disabled", SelectorGroup: "Soha", SelectedProxy: "edge-a",
		BypassCIDRs: []string{"10.20.0.0/16"}, BypassHosts: []string{"control.example.test"}, FailClosed: true,
		SubscriptionURL:  "https://subscriptions.example.test/profile?id=1",
		Protection:       &MihomoProtection{PolicyVersion: 1, CIDRs: []string{}, Hosts: []string{}},
		EnforcementUntil: time.Now().Add(time.Minute),
	}
}

func TestRenderMihomoConfigurationSupportsManualNode(t *testing.T) {
	configuration := managedMihomoConfiguration(9090)
	configuration.SourceType, configuration.SelectedProxy, configuration.SubscriptionURL = "manual_node", "", ""
	configuration.ManualNode = &MihomoManualNode{Protocol: "https", Server: "192.0.2.8", Port: 8443, Username: "alice", Password: "synthetic-secret"}
	configuration.GuardPort, configuration.GuardProxyPort, configuration.GuardDirectPort = 18080, 18081, 18082
	configuration.GuardProxySecret, configuration.GuardDirectSecret = strings.Repeat("p", 32), strings.Repeat("d", 32)
	configuration.BootstrapNodes = []map[string]any{{"name": mihomoManualProxyName, "type": "http", "tls": true, "server": "192.0.2.8", "port": 8443, "username": "alice", "password": "synthetic-secret"}}
	raw, err := renderMihomoConfiguration(configuration, "", "127.0.0.1", "127.0.0.1:9090", strings.Repeat("s", 32))
	if err != nil {
		t.Fatal(err)
	}
	var document struct{ Proxies []map[string]any }
	if err := yaml.Unmarshal([]byte(raw), &document); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, node := range document.Proxies {
		if node["name"] != mihomoManualProxyName {
			continue
		}
		found = node["type"] == "http" && node["tls"] == true && node["server"] == "192.0.2.8" && node["port"] == 8443 && node["username"] == "alice" && node["password"] == "synthetic-secret"
	}
	if !found || strings.Contains(raw, "proxy-providers:") {
		t.Fatal("pinned manual node or provider boundary changed")
	}
	configuration.GuardPort = 0
	if _, err := renderMihomoConfiguration(configuration, "", "127.0.0.1", "127.0.0.1:9090", strings.Repeat("s", 32)); err == nil {
		t.Fatal("manual node rendered without its guard")
	}
}

func appMihomoConfiguration(controllerPort int) MihomoConfiguration {
	configuration := managedMihomoConfiguration(controllerPort)
	configuration.Mode = "app_subscription"
	configuration.SourceType = ""
	configuration.SelectedProxy = ""
	configuration.SubscriptionURL = ""
	configuration.FailClosed = false
	return configuration
}

func ptrMihomo(value MihomoConfiguration) *MihomoConfiguration { return &value }

type fakeConfigurationExecutor struct {
	outcome      ApplyOutcome
	applyCalls   int
	disableCalls int
	lastDesired  ConfigurationDesired
}

func (executor *fakeConfigurationExecutor) Apply(_ context.Context, desired ConfigurationDesired, _ time.Time) ApplyOutcome {
	executor.applyCalls++
	executor.lastDesired = desired
	return executor.outcome
}

func (executor *fakeConfigurationExecutor) Disable(context.Context) error {
	executor.disableCalls++
	return nil
}

type fakeMihomoRuntime struct {
	applyCalls          int
	disableCalls        int
	applyErr            error
	applyErrOnce        error
	proxies             []string
	lastConfiguration   MihomoConfiguration
	lastSubscriptionURL string
	lastSelectedProxy   string
}

func (runtime *fakeMihomoRuntime) Apply(_ context.Context, configuration MihomoConfiguration) (MihomoReadback, error) {
	runtime.applyCalls++
	runtime.lastConfiguration = configuration
	if runtime.applyErrOnce != nil {
		err := runtime.applyErrOnce
		runtime.applyErrOnce = nil
		return MihomoReadback{}, err
	}
	if runtime.applyErr != nil {
		return MihomoReadback{}, runtime.applyErr
	}
	return expectedMihomoReadback(configuration), nil
}

func (runtime *fakeMihomoRuntime) Disable(context.Context) error {
	runtime.disableCalls++
	return nil
}

func (runtime *fakeMihomoRuntime) ApplySubscription(_ context.Context, configuration MihomoConfiguration, subscriptionURL, selectedProxy string) (MihomoAppStatus, error) {
	runtime.applyCalls++
	runtime.lastConfiguration = configuration
	runtime.lastSubscriptionURL, runtime.lastSelectedProxy = subscriptionURL, selectedProxy
	if runtime.applyErrOnce != nil {
		err := runtime.applyErrOnce
		runtime.applyErrOnce = nil
		return MihomoAppStatus{}, err
	}
	if runtime.applyErr != nil {
		return MihomoAppStatus{}, runtime.applyErr
	}
	if selectedProxy == "" && len(runtime.proxies) != 0 {
		selectedProxy = runtime.proxies[0]
	}
	runtime.lastSelectedProxy = selectedProxy
	return MihomoAppStatus{Mode: configuration.Mode, ProfileID: configuration.ProfileID, ProfileRevision: configuration.ProfileRevision, Configured: true, SelectedProxy: selectedProxy, Proxies: slices.Clone(runtime.proxies)}, nil
}
