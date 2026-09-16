//go:build darwin

package endpointservice

import (
	"fmt"
	"golang.org/x/net/route"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDarwinReadbackRequiresSinglePeerSplitRoutesAndFreshHandshake(t *testing.T) {
	private, _ := wgtypes.GeneratePrivateKey()
	peer, _ := wgtypes.GeneratePrivateKey()
	now := time.Now()
	raw := fmt.Sprintf("private_key=%x\npublic_key=%x\npreshared_key=%s\nendpoint=127.0.0.1:51820\nlast_handshake_time_sec=%d\npersistent_keepalive_interval=25\nallowed_ip=10.252.240.0/24\n", private[:], peer[:], strings.Repeat("0", 64), now.Unix())
	state, err := parseDarwinWireGuard([]byte(raw), now)
	if err != nil || state.PublicKey != private.PublicKey().String() || state.Peer.PublicKey != peer.String() {
		t.Fatalf("valid readback rejected: %v", err)
	}
	for _, bad := range []string{strings.Replace(raw, "10.252.240.0/24", "0.0.0.0/0", 1), raw + fmt.Sprintf("public_key=%x\n", peer[:]), strings.Replace(raw, fmt.Sprint(now.Unix()), "1", 1), strings.Replace(raw, "preshared_key="+strings.Repeat("0", 64), "preshared_key="+strings.Repeat("1", 64), 1)} {
		if _, err := parseDarwinWireGuard([]byte(bad), now); err == nil {
			t.Fatal("unsafe state accepted")
		}
	}
}

func TestDarwinRoutePrefix(t *testing.T) {
	m := &route.RouteMessage{Addrs: make([]route.Addr, syscall.RTAX_MAX)}
	m.Addrs[syscall.RTAX_DST] = &route.Inet4Addr{IP: [4]byte{10, 252, 240, 0}}
	m.Addrs[syscall.RTAX_NETMASK] = &route.Inet4Addr{IP: [4]byte{255, 255, 255, 0}}
	p, ok := darwinRoutePrefix(m)
	if !ok || p.String() != "10.252.240.0/24" {
		t.Fatalf("incorrect route: %v", p)
	}
	m.Addrs[syscall.RTAX_NETMASK] = &route.Inet4Addr{IP: [4]byte{255, 0, 255, 0}}
	if _, ok := darwinRoutePrefix(m); ok {
		t.Fatal("noncontiguous mask accepted")
	}
}

func TestDarwinIPCAuthenticatesAndPreservesExistingFiles(t *testing.T) {
	directory, err := os.MkdirTemp("/private/tmp", "soha-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "service.sock")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenDarwinIPC(path, uint32(os.Geteuid())); err == nil {
		t.Fatal("replaced regular file")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	listener, err := listenDarwinIPC(path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if _, err := listenDarwinIPC(path, uint32(os.Geteuid())); err == nil {
		t.Fatal("second listener acquired live socket")
	}
	done := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err == nil {
			_, err = c.Write([]byte{1})
			_ = c.Close()
		}
		done <- err
	}()
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := c.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
