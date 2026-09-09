package endpointservice

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testAccessGrantToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestControlClientConnectUsesEndpointRuntimeEnvelope(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/network-control/v1/runtimes/endpoint-1/vpn:connect" {
			t.Fatalf("path = %q", request.URL.Path)
		}
		var message RuntimeMessage
		if err := json.NewDecoder(request.Body).Decode(&message); err != nil {
			t.Fatal(err)
		}
		if message.RuntimeKind != "endpoint" || message.RuntimeID != "endpoint-1" || message.MessageType != MessageVPNConnectRequest {
			t.Fatalf("request = %#v", message)
		}
		var payload VPNConnectRequest
		if err := json.Unmarshal(message.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if payload.GatewayID != "gateway-b" || payload.Mode != "external_direct_ztna" || len(payload.ResourceIDs) != 1 || payload.ResourceIDs[0] != "resource-db" || payload.AccessGrantID != "grant-1" || payload.AccessGrantToken != testAccessGrantToken {
			t.Fatalf("connect payload = %#v", payload)
		}
		result, _ := json.Marshal(VPNConnectResult{RequestID: payload.RequestID, Decision: "deny", ReasonCode: "authorization_denied", PolicyVersion: 1, ValidUntil: now.Add(time.Minute), NetworkLeases: []NetworkLease{}, ResourceLeases: []ResourceLease{}})
		response := RuntimeMessage{SchemaVersion: RuntimeSchemaVersion, MessageID: "message-1", MessageType: MessageVPNConnectResult, ProducerID: "network-control", RuntimeID: "endpoint-1", RuntimeKind: "endpoint", OccurredAt: now, ExpiresAt: now.Add(time.Minute), Payload: result}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(response)
	}))
	defer server.Close()
	client, err := NewControlClient(server.URL, "endpoint-1", server.Client(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return now }
	result, err := client.Connect(context.Background(), VPNConnectRequest{RequestID: "request-1", SiteID: "site-1", NetworkSpaceID: "space-1", GatewayID: "gateway-b", Mode: "external_direct_ztna", ResourceIDs: []string{"resource-db"}, AccessGrantID: "grant-1", AccessGrantToken: testAccessGrantToken})
	if err != nil || result.ReasonCode != "authorization_denied" {
		t.Fatalf("Connect() = %#v, %v", result, err)
	}
}

func TestControlClientRejectsZTNAWithoutAccessGrant(t *testing.T) {
	t.Parallel()
	client, err := NewControlClient("https://control.example.com", "endpoint-1", http.DefaultClient, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Connect(context.Background(), VPNConnectRequest{RequestID: "request-1", SiteID: "site-1", NetworkSpaceID: "space-1", Mode: "internal_ztna", ResourceIDs: []string{"resource-db"}})
	if err == nil {
		t.Fatal("Connect() error = nil")
	}
}

func TestControlClientFetchesMihomoSourceWithoutCaching(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/network-control/v1/runtimes/endpoint-1/mihomo-profiles/mihomo-1/source" {
			t.Fatalf("path = %q", request.URL.Path)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		_, _ = writer.Write([]byte(`{"profileId":"mihomo-1","profileRevision":3,"sourceType":"managed_subscription","subscriptionUrl":"https://subscriptions.example.test/profile?id=1"}`))
	}))
	defer server.Close()
	client, err := NewControlClient(server.URL, "endpoint-1", server.Client(), time.Minute, "mihomo")
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.MihomoSource(context.Background(), "mihomo-1")
	if err != nil || got.SourceType != "managed_subscription" || got.ProfileRevision != 3 || got.SubscriptionURL != "https://subscriptions.example.test/profile?id=1" {
		t.Fatalf("MihomoSource() = %#v, %v", got, err)
	}
}

func TestControlClientRejectsRedirects(t *testing.T) {
	t.Parallel()
	var redirected atomic.Bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Store(true) }))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Redirect(writer, &http.Request{}, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client, err := NewControlClient(server.URL, "endpoint-1", server.Client(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Configuration(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 307") || redirected.Load() {
		t.Fatalf("Configuration() err=%v redirected=%v", err, redirected.Load())
	}
}

func TestTelemetryMapsEndpointStateToRuntimeHealth(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var batch IngestBatch
		if err := json.NewDecoder(request.Body).Decode(&batch); err != nil {
			t.Fatal(err)
		}
		var payload struct {
			Status string `json:"status"`
		}
		if len(batch.Events) != 1 || json.Unmarshal(batch.Events[0].Payload, &payload) != nil || payload.Status != "healthy" {
			t.Fatalf("heartbeat = %#v payload=%#v", batch, payload)
		}
		writer.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	client, err := NewTelemetryClient(server.URL, "endpoint-1", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Heartbeat(context.Background(), Status{State: StateDisconnected, RuntimeID: "endpoint-1", DeviceID: "device-1"}); err != nil {
		t.Fatal(err)
	}
}

func TestTelemetrySendsOnlyWindowedMihomoAggregates(t *testing.T) {
	t.Parallel()
	var batches []IngestBatch
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var batch IngestBatch
		if err := json.NewDecoder(request.Body).Decode(&batch); err != nil {
			t.Fatal(err)
		}
		batches = append(batches, batch)
		writer.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	source := &fakeProxyMetricsSource{snapshots: []ProxyFlowSnapshot{
		{Active: true, Engine: "mihomo", Mode: "app_subscription", ProfileID: "mihomo-1", ProfileRevision: 1, SelectedProxy: "edge-a", UploadTotal: 1000, DownloadTotal: 4000, ActiveConnections: 2},
		{Active: true, Engine: "mihomo", Mode: "app_subscription", ProfileID: "mihomo-1", ProfileRevision: 1, SelectedProxy: "edge-a", UploadTotal: 1250, DownloadTotal: 4600, ActiveConnections: 3},
	}}
	client, err := NewTelemetryClient(server.URL, "endpoint-1", server.Client(), source)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 2, 8, 0, 0, 0, time.UTC)
	client.now = func() time.Time { return now }
	status := Status{State: StateConnected, RuntimeID: "endpoint-1", DeviceID: "device-1"}
	if err := client.Heartbeat(context.Background(), status); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if err := client.Heartbeat(context.Background(), status); err != nil {
		t.Fatal(err)
	}
	if len(batches) != 2 || len(batches[1].Events) != 2 || batches[1].Events[1].Type != "proxy.flow.aggregate" {
		t.Fatalf("batches = %#v", batches)
	}
	var aggregate struct {
		UploadBytes       int64 `json:"uploadBytes"`
		DownloadBytes     int64 `json:"downloadBytes"`
		ActiveConnections int64 `json:"activeConnections"`
	}
	if err := json.Unmarshal(batches[1].Events[1].Payload, &aggregate); err != nil || aggregate.UploadBytes != 250 || aggregate.DownloadBytes != 600 || aggregate.ActiveConnections != 3 {
		t.Fatalf("aggregate = %#v, %v", aggregate, err)
	}
	if raw, _ := json.Marshal(batches); strings.Contains(string(raw), "destinationHost") || strings.Contains(string(raw), "subscriptionUrl") {
		t.Fatalf("proxy telemetry leaked connection metadata: %s", raw)
	}
}

type fakeProxyMetricsSource struct {
	snapshots []ProxyFlowSnapshot
}

func (source *fakeProxyMetricsSource) ProxyFlowSnapshot(context.Context) (ProxyFlowSnapshot, error) {
	snapshot := source.snapshots[0]
	source.snapshots = source.snapshots[1:]
	return snapshot, nil
}

func TestControlClientAcceptsLeaseRevokeResult(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/network-control/v1/runtimes/endpoint-1/leases:revoke" {
			t.Fatalf("path = %q", request.URL.Path)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"revokedLeaseCount":1}`))
	}))
	defer server.Close()
	client, err := NewControlClient(server.URL, "endpoint-1", server.Client(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	err = client.Revoke(context.Background(), LeaseRevoke{SessionID: "session-1", LeaseIDs: []string{"lease-1"}, ReasonCode: "configuration_expired", EffectiveAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
}
