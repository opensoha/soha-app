//go:build darwin && cgo

package endpointservice

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func darwinTestCodeHash(t *testing.T, path string) string {
	t.Helper()
	output, err := exec.Command("/usr/bin/codesign", "-d", "--verbose=4", path).CombinedOutput()
	if err != nil {
		t.Fatalf("read native code identity: %v", err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if hash, ok := strings.CutPrefix(line, "CDHash="); ok {
			return "cdhash:" + strings.TrimSpace(hash)
		}
	}
	t.Fatal("native executable has no CodeDirectory hash")
	return ""
}

func TestDarwinUIPresenceAuthenticatesSocketPeerCode(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	presence, err := NewUIProcessPresence(Config{AllowedUserUID: &uid, UIExecutable: executable, UICodeIdentity: darwinTestCodeHash(t, executable)})
	if err != nil {
		t.Fatal(err)
	}
	// Darwin Unix socket paths cannot include the test runner's long temporary path.
	directory, err := os.MkdirTemp("/private/tmp", "soha-ui-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(directory, "ui.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	now := time.Now().UTC()
	if err := presence.Observe(server, now); err != nil {
		t.Fatal(err)
	}
	if state, _ := presence.Snapshot(now); state != "online" {
		t.Fatal("authenticated native process was not online")
	}
	other, err := NewUIProcessPresence(Config{AllowedUserUID: &uid, UIExecutable: "/bin/sleep", UICodeIdentity: darwinTestCodeHash(t, "/bin/sleep")})
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Observe(server, now); err == nil {
		t.Fatal("another executable under the same UID impersonated the pinned UI")
	}
	if state, _ := other.Snapshot(now); state != "offline" {
		t.Fatal("rejected process changed UI presence")
	}
}
