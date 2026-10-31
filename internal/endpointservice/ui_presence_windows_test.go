//go:build windows && eap_native_lab

package endpointservice

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
)

func windowsNativeUIPipeName(requestID string) string {
	return `\\.\pipe\OpenSoha-Task53-UI-` + requestID
}

func windowsNativeUIPipeClient(requestID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connection, err := winio.DialPipeContext(ctx, windowsNativeUIPipeName(requestID))
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(10 * time.Second))
	var ack [1]byte
	_, err = io.ReadFull(connection, ack[:])
	return err
}

func TestWindowsNativeUIPresenceAuthenticatesDesktopPipePeer(t *testing.T) {
	system, _ := windowsEAPLabSystem(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := readFileBounded(executable, 512<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	config := Config{AllowedUserSID: system.userSID, UIExecutable: executable, UICodeIdentity: fmt.Sprintf("sha256:%x", sha256.Sum256(raw))}
	presence, err := NewUIProcessPresence(config)
	if err != nil {
		t.Fatal(err)
	}
	requestID := randomID()
	listener, err := winio.ListenPipe(windowsNativeUIPipeName(requestID), &winio.PipeConfig{
		SecurityDescriptor: fmt.Sprintf("O:SYG:SYD:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;%s)", system.userSID),
		MessageMode:        true, InputBufferSize: 128, OutputBufferSize: 128,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	child := make(chan error, 1)
	go func() {
		_, err := callEAPUserHelper(ctx, system.userSID, eapUserRequest{Action: "lab_ui_pipe_client", DeviceID: system.deviceID, RequestID: requestID, Profile: &AdmissionProfile{}})
		child <- err
	}()
	// Closing the listener bounds Accept even if the desktop helper cannot launch.
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer func() {
		_, _ = server.Write([]byte{1})
		if err := <-child; err != nil {
			t.Error(err)
		}
	}()
	now := time.Now().UTC()
	if err := presence.Observe(server, now); err != nil {
		t.Fatal(err)
	}
	if state, _ := presence.Snapshot(now); state != "online" {
		t.Fatal("authenticated desktop process was not online")
	}
	config.AllowedUserSID += "1"
	other, err := NewUIProcessPresence(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Observe(server, now); err == nil {
		t.Fatal("desktop process impersonated a different configured SID")
	}
	if state, _ := other.Snapshot(now); state != "offline" {
		t.Fatal("rejected desktop process changed presence")
	}
}
