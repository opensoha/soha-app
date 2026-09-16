package endpointservice

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestVPNProbeUsesOnlyApprovedFixedTargetsAndPreservesMissingSamples(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/vpn/probe" || r.Header.Get("Authorization") != "Bearer short-token" {
			t.Error("probe target or credential mismatch")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client, err := NewControlClient(server.URL, "endpoint-1", server.Client(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Minute)
	prepared := VPNManagedPrepareResult{RequestID: "request-1", IntentID: "intent-1", ProfileID: "profile-1", ProfileRevision: 1, SelectionPolicyRevision: 1, ExpiresAt: expires, SamplesPerGateway: 3, TimeoutMillis: 1000, MaxConcurrency: 2, Descriptors: []VPNProbeDescriptor{{GatewayID: "gw-1", RuntimeID: "gateway-1", URL: server.URL + "/vpn/probe", Token: "short-token", ExpiresAt: &expires}, {GatewayID: "gw-2", RuntimeID: "gateway-2"}}}
	batch, err := client.ProbeVPN(context.Background(), prepared)
	if err != nil || len(batch.Results) != 1 || batch.Results[0].GatewayID != "gw-1" || len(batch.Results[0].RTTSamplesMs) != 3 || calls.Load() != 3 {
		t.Fatalf("probe results: %+v %v", batch, err)
	}
	prepared.Descriptors[0].URL = server.URL + "/admin"
	if _, err := client.ProbeVPN(context.Background(), prepared); err == nil || calls.Load() != 3 {
		t.Fatal("arbitrary path was probed")
	}
	prepared.Descriptors[0].URL = server.URL + "/vpn/probe"
	prepared.MaxConcurrency = 100
	if _, err := client.ProbeVPN(context.Background(), prepared); err == nil {
		t.Fatal("unbounded concurrency accepted")
	}
	prepared.MaxConcurrency = 2
	prepared.ExpiresAt = time.Now().Add(-time.Second)
	if _, err := client.ProbeVPN(context.Background(), prepared); err == nil {
		t.Fatal("expired descriptors accepted")
	}
}

func TestVPNProbeFailuresNeverBecomeZeroLatency(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer server.Close()
	client, err := NewControlClient(server.URL, "endpoint-1", server.Client(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Minute)
	p := VPNManagedPrepareResult{ProfileID: "profile-1", ProfileRevision: 1, SelectionPolicyRevision: 1, ExpiresAt: expires, SamplesPerGateway: 3, TimeoutMillis: 1000, MaxConcurrency: 1, Descriptors: []VPNProbeDescriptor{{GatewayID: "gw-1", RuntimeID: "gateway-1", URL: server.URL + "/vpn/probe", Token: "token", ExpiresAt: &expires}}}
	batch, err := client.ProbeVPN(context.Background(), p)
	if err != nil || len(batch.Results) != 1 || batch.Results[0].SentCount != 3 || len(batch.Results[0].RTTSamplesMs) != 0 {
		t.Fatalf("failed probes became latency: %+v %v", batch, err)
	}
}

func TestVPNHandshakeRequiresFreshObservation(t *testing.T) {
	now := time.Now()
	for _, at := range []time.Time{time.Time{}, now.Add(-4 * time.Minute), now.Add(time.Minute)} {
		if validVPNHandshake(at, now) {
			t.Errorf("invalid handshake %v accepted", at)
		}
	}
	if !validVPNHandshake(now.Add(-time.Minute), now) {
		t.Fatal("fresh handshake rejected")
	}
}
