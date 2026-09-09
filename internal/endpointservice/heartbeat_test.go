package endpointservice

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"
)

func TestManagerHeartbeatsImmediatelyAndUsesLatestStatus(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release := make(chan struct{})
	delays := make(chan time.Duration, 2)
	statuses := make(chan Status, 2)
	telemetry := telemetryFunc(func(_ context.Context, status Status) error {
		statuses <- status
		return nil
	})
	manager := heartbeatTestManager(telemetry)
	manager.intervalJitter = func(delay time.Duration) time.Duration { return delay }
	manager.heartbeatWait = func(ctx context.Context, delay time.Duration) bool {
		delays <- delay
		select {
		case <-ctx.Done():
			return false
		case <-release:
			return true
		}
	}
	done := make(chan struct{})
	go func() {
		manager.runHeartbeats(ctx)
		close(done)
	}()

	if first := receive(t, statuses); first.State != StateDisconnected {
		t.Fatalf("first heartbeat state = %q", first.State)
	}
	if delay := receive(t, delays); delay != time.Minute {
		t.Fatalf("heartbeat delay = %s", delay)
	}
	manager.update(func(status *Status) { status.State = StateConnected })
	release <- struct{}{}
	if second := receive(t, statuses); second.State != StateConnected {
		t.Fatalf("second heartbeat state = %q", second.State)
	}
	cancel()
	waitDone(t, done)
}

func TestManagerHeartbeatRetriesWithBoundedBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	telemetry := telemetryFunc(func(_ context.Context, _ Status) error {
		calls++
		if calls < 8 {
			return errors.New("offline")
		}
		cancel()
		return nil
	})
	manager := heartbeatTestManager(telemetry)
	manager.intervalJitter = func(delay time.Duration) time.Duration { return delay }
	var delays []time.Duration
	manager.heartbeatWait = func(ctx context.Context, delay time.Duration) bool {
		if ctx.Err() != nil {
			return false
		}
		delays = append(delays, delay)
		return true
	}

	manager.runHeartbeats(ctx)
	if calls != 8 {
		t.Fatalf("heartbeat calls = %d", calls)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second}
	if !slices.Equal(delays, want) {
		t.Fatalf("retry delays = %v, want %v", delays, want)
	}
}

func TestRuntimeIntervalJitterStaysWithinTwentyPercent(t *testing.T) {
	for range 100 {
		delay := runtimeIntervalJitter(time.Minute)
		if delay < 48*time.Second || delay > 72*time.Second {
			t.Fatalf("heartbeat jitter = %s", delay)
		}
	}
}

type telemetryFunc func(context.Context, Status) error

func (fn telemetryFunc) Heartbeat(ctx context.Context, status Status) error {
	return fn(ctx, status)
}

func heartbeatTestManager(telemetry Telemetry) *Manager {
	now := time.Now
	return &Manager{
		options:   ManagerOptions{HeartbeatInterval: time.Minute},
		telemetry: telemetry,
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		startedAt: now().UTC(),
		now:       now,
		status:    Status{State: StateDisconnected, RuntimeID: "endpoint-1", DeviceID: "device-1"},
	}
}

func receive[T any](t *testing.T, values <-chan T) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for value")
		var zero T
		return zero
	}
}

func waitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for heartbeat loop to stop")
	}
}
