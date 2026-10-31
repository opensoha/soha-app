package endpointservice

import (
	ec "github.com/opensoha/soha-contracts/endpointcontrol"
	"testing"
	"time"
)

func TestNativeChannelFloorRejectsImplicitReleaseAndSameVersionMutation(t *testing.T) {
	m := &ChannelManager{deviceID: "device", runtimeID: "runtime", floor: channelFloor{Revision: 5, Controls: ec.Controls{USB: true, Print: true, Clipboard: true}}}
	now := time.Now().UTC()
	d := ec.Desired{SchemaVersion: ec.Version, DeviceID: "device", RuntimeID: "runtime", CredentialID: "credential", Challenge: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", IssuedAt: now, ValidUntil: now.Add(time.Minute)}
	if m.accept(d, now) == nil {
		t.Fatal("unconfigured response released prior native controls")
	}
	d.Configured = true
	d.PolicyVersion = 5
	if m.accept(d, now) == nil {
		t.Fatal("same revision changed controls")
	}
	if !m.floor.Controls.USB || !m.floor.Controls.Print || !m.floor.Controls.Clipboard {
		t.Fatal("rejected policy weakened floor")
	}
}
