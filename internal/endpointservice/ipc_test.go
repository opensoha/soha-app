package endpointservice

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestIPCStatusAndStrictInput(t *testing.T) {
	t.Parallel()
	privateKey, _ := wgtypes.GeneratePrivateKey()
	executor, _ := NewExecutor(privateKey, &fakeSystem{})
	manager, _ := NewManager(ManagerOptions{RuntimeID: "endpoint-1", DeviceID: "device-1", PollInterval: time.Second, HeartbeatInterval: time.Minute, RenewBefore: 10 * time.Second, MaxClockSkew: time.Minute}, &fakeControl{}, executor, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	response := ipcRoundTrip(t, manager, `{"version":1,"requestId":"request-1","action":"status"}`)
	if !response.OK || response.RequestID != "request-1" || response.Status.RuntimeID != "endpoint-1" {
		t.Fatalf("response = %#v", response)
	}
	response = ipcRoundTrip(t, manager, `{"version":1,"requestId":"request-2","action":"status","unexpected":true}`)
	if response.OK || response.ErrorCode != "invalid_request" {
		t.Fatalf("response = %#v", response)
	}
}

func ipcRoundTrip(t *testing.T, manager *Manager, request string) IPCResponse {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		serveIPCConnection(context.Background(), server, manager, slog.New(slog.NewTextHandler(io.Discard, nil)))
		close(done)
	}()
	if err := writeIPCFrame(client, []byte(request)); err != nil {
		t.Fatal(err)
	}
	raw, err := readIPCFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	var response IPCResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	<-done
	return response
}
