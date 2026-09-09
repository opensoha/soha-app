package endpointservice

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestMihomoControllerAppliesSafeProxyOnlyConfiguration(t *testing.T) {
	secret := "test-mihomo-controller-secret-123456"
	var configurationPayload string
	failReset := false
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+secret {
			t.Fatalf("authorization was not set")
		}
		switch request.Method + " " + request.URL.Path {
		case "PUT /configs":
			if failReset {
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			var body struct {
				Payload string `json:"payload"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			configurationPayload = body.Payload
			writer.WriteHeader(http.StatusNoContent)
		case "PUT /providers/proxies/soha-managed":
			writer.WriteHeader(http.StatusNoContent)
		case "PUT /proxies/Soha":
			writer.WriteHeader(http.StatusNoContent)
		case "GET /configs":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"mixed-port":7890,"mode":"rule"}`))
		case "GET /proxies/Soha":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"all":["edge-a"],"now":"edge-a"}`))
		case "GET /connections":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"downloadTotal":4096,"uploadTotal":1024,"connections":[{"metadata":{"host":"must-not-leave-endpoint"}}]}`))
		default:
			t.Fatalf("unexpected controller request %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()

	controller, err := NewMihomoController(server.URL, secret)
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := mihomoOrigin(server.URL)
	configuration := managedMihomoConfiguration(port)
	readback, err := controller.Apply(context.Background(), configuration)
	if err != nil || readback.ProfileID != configuration.ProfileID || readback.SelectedProxy != "edge-a" {
		t.Fatalf("Apply() = %#v, %v", readback, err)
	}
	snapshot, err := controller.ProxyFlowSnapshot(context.Background())
	if err != nil || snapshot.DownloadTotal != 4096 || snapshot.UploadTotal != 1024 || snapshot.ActiveConnections != 1 || snapshot.SelectedProxy != "edge-a" {
		t.Fatalf("ProxyFlowSnapshot() = %#v, %v", snapshot, err)
	}
	for _, required := range []string{"allow-lan: false", "bind-address: \"127.0.0.1\"", "enable: false", "proxy: DIRECT", "10.20.0.0/16,DIRECT", "https://subscriptions.example.test/profile?id=1"} {
		if !strings.Contains(configurationPayload, required) {
			t.Fatalf("mihomo payload omitted %q: %s", required, configurationPayload)
		}
	}
	if strings.Contains(configurationPayload, "0.0.0.0/0") {
		t.Fatalf("mihomo payload took ownership of the default route: %s", configurationPayload)
	}
	failReset = true
	if err := controller.Disable(context.Background()); err == nil {
		t.Fatal("expected the controller reset to fail")
	}
	snapshot, err = controller.ProxyFlowSnapshot(context.Background())
	if err != nil || !snapshot.Active || snapshot.DownloadTotal != 4096 {
		t.Fatalf("failed reset lost the active proxy metrics: %#v, %v", snapshot, err)
	}
	failReset = false
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
	if mihomo.applyCalls != 2 {
		t.Fatal("WireGuard failure prevented independent mihomo reconciliation")
	}
}

func TestCoordinatedExecutorRollsBackManagedMihomo(t *testing.T) {
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
	if mihomo.applyCalls != 3 || mihomo.lastConfiguration.ProfileRevision != 1 || mihomo.lastConfiguration.SelectedProxy != "edge-a" || wireGuard.disableCalls != 0 {
		t.Fatalf("rollback runtime=%#v wireguard=%#v", mihomo, wireGuard)
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

func TestCoordinatedExecutorRollsBackAppSelection(t *testing.T) {
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
	if err == nil || status.SelectedProxy != "edge-a" || mihomo.lastSelectedProxy != "edge-a" {
		t.Fatalf("SelectMihomoApp() = %#v, %v runtime=%#v", status, err, mihomo)
	}
	state, err := loadMihomoAppState(statePath)
	if err != nil || state.SelectedProxy != "edge-a" || state.SubscriptionURL != subscriptionURL {
		t.Fatalf("persisted state = %#v, %v", state, err)
	}
}

func managedMihomoConfiguration(controllerPort int) MihomoConfiguration {
	return MihomoConfiguration{
		Mode: "managed_follow", SourceType: "managed_subscription", ProfileID: "mihomo-1", ProfileRevision: 1, MixedPort: 7890,
		ControllerPort: controllerPort, DNSMode: "disabled", SelectorGroup: "Soha", SelectedProxy: "edge-a",
		BypassCIDRs: []string{"10.20.0.0/16"}, BypassHosts: []string{"control.example.test"}, FailClosed: true,
		SubscriptionURL: "https://subscriptions.example.test/profile?id=1",
	}
}

func TestRenderMihomoConfigurationSupportsManualNode(t *testing.T) {
	configuration := managedMihomoConfiguration(9090)
	configuration.SourceType, configuration.SelectedProxy, configuration.SubscriptionURL = "manual_node", "", ""
	configuration.ManualNode = &MihomoManualNode{Protocol: "https", Server: "proxy.example.test", Port: 8443, Username: "alice", Password: "secret"}
	raw, err := renderMihomoConfiguration(configuration, "", "127.0.0.1", "127.0.0.1:9090", strings.Repeat("s", 32))
	if err != nil || !strings.Contains(raw, "type: \"http\"") || !strings.Contains(raw, "tls: true") || !strings.Contains(raw, "server: \"proxy.example.test\"") || strings.Contains(raw, "proxy-providers:") {
		t.Fatalf("manual mihomo configuration = %q, %v", raw, err)
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
