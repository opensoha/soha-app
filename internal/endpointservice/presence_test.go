package endpointservice

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

type presenceControlFunc func(context.Context, EndpointPresenceRequest) (EndpointPresenceResult, error)

func (f presenceControlFunc) PublishPresence(ctx context.Context, input EndpointPresenceRequest) (EndpointPresenceResult, error) {
	return f(ctx, input)
}

func TestProtectedServicePresenceIsIndependentOfVPNAndTelemetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := heartbeatTestManager(nil)
	manager.options.DeviceID, manager.options.RuntimeID = "device-1", "endpoint-1"
	manager.presenceBootID = randomID()
	manager.intervalJitter = func(delay time.Duration) time.Duration { return delay }
	var delays []time.Duration
	var requests []EndpointPresenceRequest
	manager.heartbeatWait = func(ctx context.Context, delay time.Duration) bool {
		delays = append(delays, delay)
		return ctx.Err() == nil
	}
	publisher := presenceControlFunc(func(_ context.Context, input EndpointPresenceRequest) (EndpointPresenceResult, error) {
		requests = append(requests, input)
		if len(requests) < 3 {
			return EndpointPresenceResult{}, errors.New("control offline")
		}
		cancel()
		return EndpointPresenceResult{Accepted: true, PresenceEpoch: 1, ReceivedAt: manager.now(), NextHeartbeatSeconds: 30}, nil
	})
	manager.runPresence(ctx, publisher)
	if len(requests) != 3 || !slices.Equal(delays, []time.Duration{time.Second, 2 * time.Second, 30 * time.Second}) {
		t.Fatalf("requests=%#v delays=%v", requests, delays)
	}
	for i, input := range requests {
		if input.BootID != manager.presenceBootID || input.Sequence != int64(i+1) || input.UIState != "unknown" || input.Status != "healthy" {
			t.Fatalf("presence=%#v", input)
		}
	}
	status := manager.Status()
	if status.State != StateDisconnected || status.PresenceState != "healthy" || status.PresenceLastReceivedAt == nil {
		t.Fatalf("status=%#v", status)
	}
}

func TestPresenceClientChecksProtocolAndDoesNotClaimUIOnline(t *testing.T) {
	now := time.Now().UTC()
	calls := 0
	wantUI := "unknown"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/network-control/v1/runtimes/endpoint-1/endpoint:presence" {
			t.Errorf("path=%s", r.URL.Path)
		}
		var message RuntimeMessage
		if err := json.NewDecoder(r.Body).Decode(&message); err != nil {
			t.Error(err)
		}
		var payload EndpointPresenceRequest
		if err := json.Unmarshal(message.Payload, &payload); err != nil || payload.UIState != wantUI || message.MessageType != MessageEndpointPresenceRequest || payload.UIState == "online" && (payload.UIObservedAt == nil || !payload.UIObservedAt.Equal(now)) {
			t.Errorf("payload=%#v error=%v", payload, err)
		}
		raw, _ := json.Marshal(EndpointPresenceResult{Accepted: true, PresenceEpoch: 1, ReceivedAt: now, NextHeartbeatSeconds: 30})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(RuntimeMessage{SchemaVersion: RuntimeSchemaVersion, MessageID: randomID(), MessageType: MessageEndpointPresenceResult, ProducerID: "network-control", RuntimeID: "endpoint-1", RuntimeKind: "endpoint", OccurredAt: now, ExpiresAt: now.Add(time.Minute), Payload: raw})
	}))
	defer server.Close()
	client, err := NewControlClient(server.URL, "endpoint-1", server.Client(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(client.capabilities, "endpoint-presence-v1") || slices.Contains(client.capabilities, "endpoint-ui-presence-v1") {
		t.Fatalf("capabilities=%v", client.capabilities)
	}
	input := EndpointPresenceRequest{DeviceID: "device-1", BootID: "boot-1", Sequence: 1, Status: "healthy", UIState: "unknown"}
	result, err := client.PublishPresence(context.Background(), input)
	if err != nil || result.NextHeartbeatSeconds != 30 || calls != 1 {
		t.Fatalf("result=%#v calls=%d error=%v", result, calls, err)
	}
	input.UIState = "online"
	if _, err := client.PublishPresence(context.Background(), input); err == nil || calls != 1 {
		t.Fatal("client claimed an unverified UI process")
	}
	attested, err := NewControlClient(server.URL, "endpoint-1", server.Client(), time.Minute, "endpoint-ui-presence-v1")
	if err != nil {
		t.Fatal(err)
	}
	wantUI, input.UIObservedAt = "online", &now
	if _, err := attested.PublishPresence(context.Background(), input); err != nil || calls != 2 {
		t.Fatal("attested UI observation did not reach the control protocol", err)
	}
}

func TestPresenceReadsAdmissionVersionWithoutChangingVPNVersion(t *testing.T) {
	manager := heartbeatTestManager(nil)
	manager.intervalJitter = func(delay time.Duration) time.Duration { return delay }
	manager.options.DeviceID, manager.options.RuntimeID = "device-1", "endpoint-1"
	manager.presenceBootID = randomID()
	manager.update(func(status *Status) { status.PolicyVersion = 2 })
	manager.heartbeatWait = func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var requests []EndpointPresenceRequest
	manager.runPresence(ctx, presenceControlFunc(func(_ context.Context, input EndpointPresenceRequest) (EndpointPresenceResult, error) {
		requests = append(requests, input)
		if len(requests) == 2 {
			cancel()
		}
		return EndpointPresenceResult{Accepted: true, PresenceEpoch: 1, ReceivedAt: manager.now(), NextHeartbeatSeconds: 30, AdmissionPolicyVersion: 7}, nil
	}))
	if len(requests) != 2 || requests[0].AdmissionPolicyVersion != 0 || requests[1].AdmissionPolicyVersion != 7 || requests[1].PolicyVersion != 2 || manager.Status().PolicyVersion != 2 {
		t.Fatalf("requests=%#v status=%#v", requests, manager.Status())
	}
}
