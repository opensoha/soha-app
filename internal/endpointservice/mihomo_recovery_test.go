//go:build !windows

package endpointservice

import (
	"context"
	"encoding/json"
	api "github.com/opensoha/soha-contracts/gen/go/sohaapi"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type recoveryControl struct {
	fakeControl
	client *ControlClient
}

func (c *recoveryControl) MihomoProjection(ctx context.Context, id string) (api.NetworkProxyEmployeeProjection, error) {
	return c.client.MihomoProjection(ctx, id)
}
func (c *recoveryControl) ReportMihomoProjection(ctx context.Context, id string, r api.NetworkProxyProjectionApplied) error {
	return c.client.ReportMihomoProjection(ctx, id, r)
}
func TestMihomoFreshCredentialColdRecoveryPreservesCeiling(t *testing.T) {
	for _, mode := range []string{"explicit_start", "poll", "wrong_boot"} {
		t.Run(mode, func(t *testing.T) { testMihomoFreshCredentialColdRecovery(t, mode) })
	}
}
func testMihomoFreshCredentialColdRecovery(t *testing.T, mode string) {
	now := time.Now().UTC()
	full := twoNodeBundle(now)
	configuration := narrowedBundle(t, full)
	configuration.Protection.PolicyVersion = 3
	oldExpiry := now.Add(2 * time.Second)
	configuration.Projection.Credential.ExpiresAt = oldExpiry
	var mu sync.Mutex
	grant := *configuration.Projection
	gets := 0
	wrongBoot := false
	receipts := []api.NetworkProxyProjectionApplied{}
	controlServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private, no-store")
		if strings.HasSuffix(r.URL.Path, "/receipt") {
			var receipt api.NetworkProxyProjectionApplied
			if json.NewDecoder(r.Body).Decode(&receipt) != nil {
				w.WriteHeader(400)
				return
			}
			receipts = append(receipts, receipt)
			w.WriteHeader(200)
			return
		}
		gets++
		copy := grant
		copy.ProcessEpoch = r.URL.Query().Get("processEpoch")
		if wrongBoot {
			copy.ProcessEpoch = "other-boot"
		}
		json.NewEncoder(w).Encode(copy)
	}))
	defer controlServer.Close()
	_, fixture := newMihomoControllerFixture(t, strings.Repeat("s", 32))
	kernelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"version":"fixture-v1"}`)
			return
		}
		fixture.serveHTTP(w, r)
	}))
	defer kernelServer.Close()
	controller, _ := NewMihomoController(kernelServer.URL, strings.Repeat("s", 32))
	processController, _ := processFixture(t)
	controller.process = processController.process
	configuration.ControllerPort = controller.port
	wg := &stoppedWireGuardFixture{fakeConfigurationExecutor: fakeConfigurationExecutor{outcome: ApplyOutcome{Status: "applied", ReadbackHash: emptyReadbackHash()}}}
	e, _ := NewCoordinatedExecutor(wg, controller, filepath.Join(t.TempDir(), "app.json"))
	defer e.Disable(context.Background())
	desired := ConfigurationDesired{ConfigurationVersion: 5, PolicyVersion: 3, ValidUntil: now.Add(3 * time.Minute), AccessProfile: "full", ProtectedResourceIDs: []string{}, NetworkLeases: []NetworkLease{}, ResourceLeases: []ResourceLease{}, Mihomo: &configuration}
	raw, _ := json.Marshal(desired)
	client, err := NewControlClient(controlServer.URL, "endpoint-1", controlServer.Client(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	control := &recoveryControl{fakeControl: fakeControl{configuration: RuntimeMessage{SchemaVersion: RuntimeSchemaVersion, MessageID: "message-1", MessageType: MessageConfiguration, ProducerID: "network-control", RuntimeID: "endpoint-1", RuntimeKind: "endpoint", OccurredAt: now, ExpiresAt: desired.ValidUntil, Payload: raw}}, client: client}
	statePath := filepath.Join(t.TempDir(), "floor.json")
	manager, err := NewManager(ManagerOptions{ControlURL: controlServer.URL, ConfigurationStatePath: statePath, RuntimeID: "endpoint-1", DeviceID: "device-1", PollInterval: time.Second, HeartbeatInterval: time.Minute, RenewBefore: 30 * time.Second, MaxClockSkew: time.Minute}, control, e, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := controller.ProcessStatus()
	if before.PID == 0 {
		t.Fatal("owned process did not start")
	}
	if mode != "poll" {
		if _, err = runProxyIPCAction(context.Background(), manager, IPCRequest{Action: "proxy_action", Proxy: &ProxyAction{Kind: "stop"}}); err != nil {
			t.Fatal(err)
		}
		if controller.ProcessStatus().PID != 0 {
			t.Fatal("old process/flows not stopped")
		}
	}
	time.Sleep(max(0, time.Until(oldExpiry)) + 20*time.Millisecond)
	oldRevival := *configuration.Projection
	oldRevival.ProcessEpoch = client.processEpoch
	oldRevival.Credential.ExpiresAt = time.Now().Add(time.Minute)
	if rememberEmployeeProjection(statePath, oldRevival) == nil {
		t.Fatal("expired credential ID revived with a later expiry")
	}
	oldRevival.Credential.Secret = strings.Repeat("different-secret", 3)
	if rememberEmployeeProjection(statePath, oldRevival) == nil {
		t.Fatal("expired credential ID revived with a different secret")
	}
	if mode == "poll" {
		if err = manager.Cycle(context.Background()); err != nil {
			t.Fatal(err)
		}
		if controller.ProcessStatus().PID != 0 {
			t.Fatal("expiry poll did not stop old process before recovery")
		}
	}
	// Current authenticated endpoint issues a NEW token; the old token is never renewed.
	mu.Lock()
	grant.Credential.CredentialID = "fresh-token"
	grant.Credential.Secret = strings.Repeat("fresh-secret", 4)
	grant.Credential.ExpiresAt = time.Now().Add(time.Minute)
	previousGets := gets
	wrongBoot = mode == "wrong_boot"
	mu.Unlock()
	if mode != "poll" {
		_, err = runProxyIPCAction(context.Background(), manager, IPCRequest{Action: "proxy_action", Proxy: &ProxyAction{Kind: "start"}})
	} else {
		err = manager.Cycle(context.Background())
	}
	if mode == "wrong_boot" {
		if err == nil || controller.ProcessStatus().PID != 0 || wg.disableCalls != 1 {
			t.Fatal("wrong-boot current grant did not fail closed")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	after := controller.ProcessStatus()
	if after.PID == 0 || after.ProcessEpoch == before.ProcessEpoch {
		t.Fatal("fresh token did not rebuild with a new engine epoch")
	}
	wantDisable, wantApply := 0, 1
	if mode == "poll" {
		wantDisable, wantApply = 1, 2
	}
	if controller.egress.projection.Load().Credential.CredentialID != "fresh-token" || wg.disableCalls != wantDisable || wg.applyCalls != wantApply {
		t.Fatalf("fresh start reused expired material or wrong cleanup: disable=%d apply=%d", wg.disableCalls, wg.applyCalls)
	}
	mu.Lock()
	if gets <= previousGets || len(receipts) == 0 || receipts[len(receipts)-1].Status != "applied" {
		t.Error("fresh start omitted authenticated fetch or verified receipt")
	}
	fresh := grant
	mu.Unlock()
	replay := *full.Projection
	replay.ProcessEpoch = client.processEpoch
	replay.Credential = fresh.Credential
	replay.Credential.NodeIDs = []string{"node-a", "node-b"}
	if rememberEmployeeProjection(statePath, replay) == nil {
		t.Fatal("fresh token widened persisted B ceiling")
	}
	old := *configuration.Projection
	old.ProcessEpoch = client.processEpoch
	if rememberEmployeeProjection(statePath, old) == nil {
		t.Fatal("old expired token replay accepted after recovery")
	}
}
