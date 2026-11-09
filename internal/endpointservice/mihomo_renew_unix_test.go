//go:build !windows

package endpointservice

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	api "github.com/opensoha/soha-contracts/gen/go/sohaapi"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMihomoProjectionRenewalKeepsOwnedProcessAndFailsClosed(t *testing.T) {
	now := time.Now().UTC()
	configuration, projection := bundleFixture(now)
	configuration.Projection = &projection
	secret := strings.Repeat("a", 32)
	server, fixture := newMihomoControllerFixture(t, secret)
	controller, err := NewMihomoController(server.URL, secret)
	if err != nil {
		t.Fatal(err)
	}
	configuration.ControllerPort = controller.port
	e, _ := NewCoordinatedExecutor(&fakeConfigurationExecutor{outcome: ApplyOutcome{Status: "applied"}}, controller, filepath.Join(t.TempDir(), "app.json"))
	defer e.Disable(context.Background())
	desired := ConfigurationDesired{PolicyVersion: configuration.Protection.PolicyVersion, ValidUntil: configuration.EnforcementUntil, Mihomo: &configuration}
	if outcome := e.Apply(context.Background(), desired, now); outcome.Status != "applied" {
		t.Fatalf("mapped apply=%#v", outcome)
	}
	processController, _ := processFixture(t)
	if err := processController.process.start(context.Background(), "", func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	controller.process = processController.process
	before := controller.ProcessStatus()
	gate := controller.egress
	next := cloneMihomoConfiguration(configuration)

	next.Projection.Credential.ExpiresAt = now.Add(90 * time.Second)
	renewed, err := e.RenewProjection(context.Background(), ConfigurationDesired{ValidUntil: desired.ValidUntil, Mihomo: &next}, now)
	if err != nil || !renewed {
		t.Fatalf("renewal=%v %v", renewed, err)
	}
	after := controller.ProcessStatus()
	if after.PID != before.PID || after.ProcessEpoch != before.ProcessEpoch || controller.egress != gate {
		t.Fatal("renewal restarted owned process or replaced gate")
	}
	if !gate.projection.Load().Credential.ExpiresAt.Equal(next.Projection.Credential.ExpiresAt) {
		t.Fatal("gate did not atomically update scoped credential")
	}
	changed := cloneMihomoConfiguration(next)
	changed.Projection.CredentialEpoch = 2
	changed.Projection.Credential.CredentialEpoch = 2
	if renewed, err = e.RenewProjection(context.Background(), ConfigurationDesired{ValidUntil: desired.ValidUntil, Mihomo: &changed}, now); err != nil || renewed {
		t.Fatal("authorization epoch change used narrow renewal")
	}
	fixture.mu.Lock()
	fixture.document.Rules = []string{"MATCH,DIRECT"}
	fixture.mu.Unlock()
	if _, err = e.RenewProjection(context.Background(), ConfigurationDesired{ValidUntil: desired.ValidUntil, Mihomo: &next}, now); err == nil {
		t.Fatal("drifted protection was renewed")
	}
	if e.mihomoActive || controller.egress != nil || controller.ProcessStatus().PID != 0 {
		t.Fatal("failed renewal did not stop owned process")
	}
}
func TestMihomoOldProjectionConnectionCannotExtendCredentialLease(t *testing.T) {
	left, right := netPipe(t)
	defer left.Close()
	defer right.Close()
	until := time.Now().Add(100 * time.Millisecond)
	conn := &projectionConnection{Conn: left, reader: bufio.NewReader(left), validUntil: until}
	if err := conn.SetDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("old credential connection survived expiry")
	}
}
func netPipe(t *testing.T) (net.Conn, net.Conn) { t.Helper(); return net.Pipe() }

func TestMihomoSameCredentialRenewalExtendsOnlyMatchingLease(t *testing.T) {
	_, p := bundleFixture(time.Now())
	gate := &mihomoEgress{}
	gate.refreshProjection(&p)
	old := gate.leaseFor(&p)
	initial := old.Load()
	renewed := p
	renewed.Credential.ExpiresAt = p.Credential.ExpiresAt.Add(20 * time.Second)
	gate.refreshProjection(&renewed)
	if gate.leaseFor(&renewed) != old || old.Load() <= initial {
		t.Fatal("same credential renewal did not extend existing lease")
	}
	rotated := renewed
	rotated.Credential.CredentialID = "rotated-credential"
	rotated.Credential.ExpiresAt = renewed.Credential.ExpiresAt.Add(20 * time.Second)
	beforeRotation := old.Load()
	gate.refreshProjection(&rotated)
	if gate.leaseFor(&rotated) == old || old.Load() != beforeRotation {
		t.Fatal("credential rotation extended old flow lease")
	}
}

type stoppedWireGuardFixture struct {
	fakeConfigurationExecutor
	verifyCalls int
}

func (w *stoppedWireGuardFixture) Verify(context.Context, ConfigurationDesired, time.Time) ApplyOutcome {
	w.verifyCalls++
	return w.outcome
}

type stoppedReceiptHTTPControl struct {
	bundleControl
	client *ControlClient
}

func (c *stoppedReceiptHTTPControl) ReportMihomoProjection(ctx context.Context, id string, receipt api.NetworkProxyProjectionApplied) error {
	return c.client.ReportMihomoProjection(ctx, id, receipt)
}

func TestMihomoLocallyStoppedPollPreservesWireGuardAndRejectsAppliedReceipt(t *testing.T) {
	for _, failure := range []string{"accepted", "conflict", "timeout"} {
		t.Run(failure, func(t *testing.T) {
			now := time.Now().UTC()
			configuration, projection := bundleFixture(now)
			configuration.Protection.PolicyVersion = 3
			controller, _ := processFixture(t)
			configuration.ControllerPort = controller.port
			wg := &stoppedWireGuardFixture{fakeConfigurationExecutor: fakeConfigurationExecutor{outcome: ApplyOutcome{Status: "applied", ReadbackHash: emptyReadbackHash()}}}
			e, _ := NewCoordinatedExecutor(wg, controller, filepath.Join(t.TempDir(), "app.json"))
			if err := e.SetMihomoProcessRunning(context.Background(), false); err != nil {
				t.Fatal(err)
			}
			desired := ConfigurationDesired{ConfigurationVersion: 5, PolicyVersion: 3, ValidUntil: now.Add(3 * time.Minute), AccessProfile: "full", ProtectedResourceIDs: []string{}, NetworkLeases: []NetworkLease{}, ResourceLeases: []ResourceLease{}, Mihomo: &configuration}
			raw, _ := json.Marshal(desired)
			var responseMode atomic.Int32
			if failure == "conflict" {
				responseMode.Store(1)
			} else if failure == "timeout" {
				responseMode.Store(2)
			}
			var calls, invalid atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var receipt api.NetworkProxyProjectionApplied
				decoder := json.NewDecoder(r.Body)
				decoder.DisallowUnknownFields()
				if r.Method != "POST" || r.URL.Path != "/api/network-control/v1/runtimes/endpoint-1/mihomo-profiles/"+projection.ProfileID+"/projection/receipt" || decoder.Decode(&receipt) != nil || !receipt.Status.Valid() || receipt.Status != "rejected" || receipt.ReasonCode != mihomoLocalStopReason || receipt.BundleID != projection.BundleID || receipt.Revision != projection.Revision || receipt.ProjectionHash != projection.ProjectionHash || receipt.ProcessEpoch != projection.ProcessEpoch {
					invalid.Add(1)
					w.WriteHeader(400)
					return
				}
				calls.Add(1)
				switch responseMode.Load() {
				case 1:
					w.WriteHeader(http.StatusConflict)
				case 2:
					select {
					case <-r.Context().Done():
					case <-time.After(time.Second):
					}
				default:
					w.WriteHeader(http.StatusOK)
				}
			}))
			defer server.Close()
			transport := server.Client()
			transport.Timeout = 100 * time.Millisecond
			client, err := NewControlClient(server.URL, "endpoint-1", transport, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			control := &stoppedReceiptHTTPControl{bundleControl: bundleControl{fakeControl: fakeControl{configuration: RuntimeMessage{SchemaVersion: RuntimeSchemaVersion, MessageID: "message-1", MessageType: MessageConfiguration, ProducerID: "network-control", RuntimeID: "endpoint-1", RuntimeKind: "endpoint", OccurredAt: now, ExpiresAt: desired.ValidUntil, Payload: raw}}, projection: projection}, client: client}
			manager, err := NewManager(ManagerOptions{ControlURL: server.URL, ConfigurationStatePath: filepath.Join(t.TempDir(), "floor.json"), RuntimeID: "endpoint-1", DeviceID: "device-1", PollInterval: time.Second, HeartbeatInterval: time.Minute, RenewBefore: 30 * time.Second, MaxClockSkew: time.Minute}, control, e, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			manager.now = func() time.Time { return now }
			assertStopped := func() {
				t.Helper()
				if wg.disableCalls != 0 || wg.applyCalls != 1 || e.mihomoActive || controller.ProcessStatus().PID != 0 {
					t.Fatal("receipt failure reset valid WireGuard or revived proxy")
				}
			}
			if err = manager.Cycle(context.Background()); err != nil {
				t.Fatal(err)
			}
			assertStopped()
			if manager.projectionReceiptPending() != (failure != "accepted") {
				t.Fatal("incorrect pending receipt state")
			}
			if failure != "accepted" && manager.Status().Diagnostic != "mihomo_stop_receipt_pending" {
				t.Fatal("receipt error was not observable")
			}
			// Identical projection must retry after verification, without a fresh Apply.
			before := calls.Load()
			if err = manager.Cycle(context.Background()); err != nil {
				t.Fatal(err)
			}
			assertStopped()
			if failure != "accepted" && calls.Load() != before+1 {
				t.Fatal("stable polling did not retry pending receipt")
			}
			// A renewed lease follows the same narrow exception, never global cleanup.
			control.projection.Credential.ExpiresAt = now.Add(90 * time.Second)
			if err = manager.Cycle(context.Background()); err != nil {
				t.Fatal(err)
			}
			assertStopped()
			responseMode.Store(0)
			if err = manager.Cycle(context.Background()); err != nil {
				t.Fatal(err)
			}
			assertStopped()
			if manager.projectionReceiptPending() || e.proxyReceiptPending || manager.Status().Diagnostic != mihomoLocalStopReason {
				t.Fatal("acknowledged stop receipt remained pending")
			}
			if invalid.Load() != 0 || calls.Load() == 0 {
				t.Fatal("receipt did not satisfy shared wire contract")
			}
			// Stop intent and pending receipt never excuse invalid device authorization.
			control.projection.Credential.DeviceID = "wrong-device"
			if err = manager.Cycle(context.Background()); err == nil || wg.disableCalls == 0 {
				t.Fatal("invalid authorization escaped fail-closed cleanup")
			}
		})
	}
}

type unrelatedReceiptFailureControl struct {
	bundleControl
	received api.NetworkProxyProjectionApplied
}

func (c *unrelatedReceiptFailureControl) ReportMihomoProjection(_ context.Context, _ string, receipt api.NetworkProxyProjectionApplied) error {
	c.received = receipt
	return errors.New("receipt unavailable")
}
func TestMihomoLocalStopDoesNotExcuseUnrelatedProxyFailure(t *testing.T) {
	controller, _ := processFixture(t)
	e, _ := NewCoordinatedExecutor(&fakeConfigurationExecutor{}, controller)
	if err := e.SetMihomoProcessRunning(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	configuration, projection := bundleFixture(time.Now())
	configuration.Projection = &projection
	control := &unrelatedReceiptFailureControl{}
	manager := &Manager{executor: e, control: control}
	if err := manager.deliverProjectionReceipt(context.Background(), ConfigurationDesired{Mihomo: &configuration}, "rejected", "unsafe_mihomo_configuration"); err == nil {
		t.Fatal("unrelated proxy failure received local-stop exemption")
	}
	if manager.projectionReceiptPending() || control.received.ReasonCode != "unsafe_mihomo_configuration" || control.received.Status != "rejected" {
		t.Fatal("unrelated failure was masked as a local stop")
	}
}
