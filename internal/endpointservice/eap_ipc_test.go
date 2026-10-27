package endpointservice

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestAdmissionIPCRejectsInjectedConfigurationAndCrossActionParameters(t *testing.T) {
	admission, control, _, _ := admissionFixture(t)
	manager, err := NewManager(ManagerOptions{Admission: admission, RuntimeID: "endpoint-1", DeviceID: "device-1", PollInterval: time.Minute, HeartbeatInterval: time.Minute, RenewBefore: time.Second, MaxClockSkew: time.Minute}, &fakeControl{}, &fakeConfigurationExecutor{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []string{
		`{"version":1,"requestId":"request-1","action":"admission_prepare","admission":{"profileId":"profile-1","adapterId":"wifi-1","xml":"untrusted"}}`,
		`{"version":1,"requestId":"request-1","action":"admission_prepare","admission":{"profileId":"profile-1","adapterId":"unknown-adapter"}}`,
		`{"version":1,"requestId":"request-1","action":"status","admission":{"profileId":"profile-1"}}`,
		`{"version":1,"requestId":"request-1","action":"admission_status","mihomo":{"subscriptionUrl":"https://untrusted.test"}}`,
	} {
		if response := ipcRoundTrip(t, manager, request); response.OK {
			t.Fatal("injected or unrelated parameters were accepted")
		}
	}
	response := ipcRoundTrip(t, manager, `{"version":1,"requestId":"request-2","action":"admission_status"}`)
	if !response.OK || response.Admission == nil || !validIPCAdmissionStatus(*response.Admission) || len(response.Admission.Profiles) != 1 || control.activations != 0 {
		t.Fatalf("status = %+v", response)
	}
	response = ipcRoundTrip(t, manager, `{"version":1,"requestId":"request-3","action":"admission_prepare","admission":{"profileId":"profile-1","adapterId":"wifi-1"}}`)
	if !response.OK || response.Admission.Profiles[0].State != "installation_required" || control.activations != 0 {
		t.Fatalf("prepare = %+v", response)
	}
	manager.options.Admission = nil
	status, err := runAdmissionIPCAction(context.Background(), manager, IPCRequest{Action: "admission_status"})
	if err != nil || status.Supported {
		t.Fatal("unsupported service build advertised native EAP")
	}
}
