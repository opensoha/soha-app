package endpointservice

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestUIProcessPresenceRequiresVerifiedNativePeerAndExpires(t *testing.T) {
	now := time.Now().UTC()
	var absent *UIProcessPresence
	if state, observed := absent.Snapshot(now); state != "unknown" || observed != nil {
		t.Fatal("unprovisioned UI claimed a known state")
	}
	if err := absent.Observe(nil, now); err == nil {
		t.Fatal("unprovisioned UI accepted a heartbeat")
	}
	trusted := false
	presence := &UIProcessPresence{verify: func(net.Conn) error {
		if !trusted {
			return errors.New("wrong process")
		}
		return nil
	}}
	if err := presence.Observe(nil, now); err == nil {
		t.Fatal("untrusted peer refreshed UI presence")
	}
	if state, observed := presence.Snapshot(now); state != "offline" || observed != nil {
		t.Fatal("rejected peer changed UI state")
	}
	trusted = true
	if err := presence.Observe(nil, now); err != nil {
		t.Fatal(err)
	}
	if state, observed := presence.Snapshot(now.Add(uiPresenceTTL - time.Nanosecond)); state != "online" || observed == nil || !observed.Equal(now) {
		t.Fatal("verified native heartbeat was not online")
	}
	for _, when := range []time.Time{now.Add(uiPresenceTTL), now.Add(-time.Second)} {
		if state, observed := presence.Snapshot(when); state != "offline" || observed == nil || !observed.Equal(now) {
			t.Fatal("expired or future UI observation stayed online")
		}
	}
}

func TestUIObservationValidationRejectsUnattestedAndStaleOnline(t *testing.T) {
	now := time.Now().UTC()
	old, future := now.Add(-uiPresenceTTL), now.Add(time.Second)
	for _, input := range []struct {
		state    string
		observed *time.Time
		capable  bool
	}{
		{"online", &now, false}, {"offline", nil, false}, {"online", nil, true},
		{"online", &old, true}, {"online", &future, true}, {"unknown", &now, true}, {"invalid", nil, true},
	} {
		if validUIObservation(input.state, input.observed, input.capable, now) {
			t.Fatalf("unsafe UI observation accepted: %#v", input)
		}
	}
	for _, input := range []struct {
		state    string
		observed *time.Time
	}{
		{"unknown", nil}, {"online", &now}, {"offline", nil}, {"offline", &old},
	} {
		if !validUIObservation(input.state, input.observed, true, now) {
			t.Fatalf("valid UI observation rejected: %#v", input)
		}
	}
}

func TestUIPresenceIPCCannotAcceptRendererParameters(t *testing.T) {
	manager := heartbeatTestManager(nil)
	manager.options.DeviceID, manager.options.RuntimeID = "device-1", "endpoint-1"
	if result := ipcRoundTrip(t, manager, `{"version":1,"requestId":"ui-1","action":"ui_presence"}`); result.OK {
		t.Fatal("unprovisioned UI IPC succeeded")
	}
	verified := 0
	manager.options.UIPresence = &UIProcessPresence{verify: func(net.Conn) error { verified++; return nil }}
	for _, parameters := range []string{`,"connect":{}`, `,"mihomo":{}`, `,"admission":{}`, `,"online":true`} {
		if result := ipcRoundTrip(t, manager, `{"version":1,"requestId":"ui-2","action":"ui_presence"`+parameters+`}`); result.OK {
			t.Fatal("UI IPC accepted renderer parameters")
		}
	}
	if verified != 0 {
		t.Fatal("invalid UI request reached native verification")
	}
	if result := ipcRoundTrip(t, manager, `{"version":1,"requestId":"ui-3","action":"ui_presence"}`); !result.OK || verified != 1 {
		t.Fatal("native UI IPC did not authenticate its peer")
	}
}
