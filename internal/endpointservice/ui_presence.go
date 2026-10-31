package endpointservice

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

const uiPresenceTTL = 30 * time.Second

// Only the privileged service creates this observer from administrator provisioning.
type UIProcessPresence struct {
	verify       func(net.Conn) error
	mu           sync.Mutex
	lastObserved time.Time
}

func (presence *UIProcessPresence) Observe(connection net.Conn, now time.Time) error {
	if presence == nil || presence.verify == nil {
		return errors.New("trusted UI presence is not provisioned")
	}
	if err := presence.verify(connection); err != nil {
		return err
	}
	presence.mu.Lock()
	presence.lastObserved = now.UTC()
	presence.mu.Unlock()
	return nil
}

func (presence *UIProcessPresence) Snapshot(now time.Time) (string, *time.Time) {
	if presence == nil {
		return "unknown", nil
	}
	presence.mu.Lock()
	last := presence.lastObserved
	presence.mu.Unlock()
	if last.IsZero() {
		return "offline", nil
	}
	if now.Before(last) || now.Sub(last) >= uiPresenceTTL {
		return "offline", &last
	}
	return "online", &last
}

func validUIObservation(state string, observed *time.Time, capable bool, now time.Time) bool {
	if state == "unknown" {
		return observed == nil
	}
	if !capable || state != "online" && state != "offline" || observed != nil && observed.After(now) {
		return false
	}
	return state != "online" || observed != nil && now.Sub(*observed) < uiPresenceTTL
}

// RunNativeUIPresence is called by the native application host, never a renderer route.
func RunNativeUIPresence(ctx context.Context) {
	for ctx.Err() == nil {
		callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, _ = CallIPC(callCtx, "ui_presence", nil)
		cancel()
		if !waitFor(ctx, 10*time.Second) {
			return
		}
	}
}
