//go:build darwin && cgo

package endpointservice

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type darwinControllerWireFixture struct {
	mu            sync.Mutex
	local, remote net.Addr
	bytes         []byte
	closed        bool
}

func (c *darwinControllerWireFixture) Read([]byte) (int, error) { return 0, io.EOF }
func (c *darwinControllerWireFixture) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	c.bytes = append(c.bytes, b...)
	return len(b), nil
}
func (c *darwinControllerWireFixture) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}
func (c *darwinControllerWireFixture) LocalAddr() net.Addr            { return c.local }
func (c *darwinControllerWireFixture) RemoteAddr() net.Addr           { return c.remote }
func (*darwinControllerWireFixture) SetDeadline(time.Time) error      { return nil }
func (*darwinControllerWireFixture) SetReadDeadline(time.Time) error  { return nil }
func (*darwinControllerWireFixture) SetWriteDeadline(time.Time) error { return nil }
func (c *darwinControllerWireFixture) state() (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.bytes), c.closed
}

type darwinControllerFixture struct {
	process  *darwinRecoveryFixture
	record   nativeOwnedProcessIdentity
	session  nativeSession
	endpoint netip.AddrPort
	raw      *darwinControllerWireFixture
	releases atomic.Int32
	dials    int
}

func newDarwinControllerFixture(t *testing.T) *darwinControllerFixture {
	t.Helper()
	p := newDarwinRecoveryFixture(t)
	record := p.capture(t)
	session, err := p.platform.AcquireRestoreSession(context.Background(), p.session.Owner())
	if err != nil {
		t.Fatal(err)
	}
	endpoint := netip.MustParseAddrPort("127.0.0.1:7899")
	local := netip.MustParseAddrPort("127.0.0.1:45001")
	f := &darwinControllerFixture{process: p, record: record, session: session, endpoint: endpoint, raw: &darwinControllerWireFixture{local: net.TCPAddrFromAddrPort(local), remote: net.TCPAddrFromAddrPort(endpoint)}}
	c := p.platform.calls.recovery
	c.release = func(port uint32) {
		if port != 88 {
			t.Error("wrong task port released")
		}
		f.releases.Add(1)
	}
	c.terminate = func(uint32) error { t.Error("controller dial attempted termination"); return errDarwinRecovery }
	c.controllerSocket = func(pid uint32, server, client netip.AddrPort) ([4]uint64, error) {
		if pid != record.Proof.PID || server != endpoint || client != local {
			return [4]uint64{}, errDarwinRecovery
		}
		return [4]uint64{7, 11, 12, 13}, nil
	}
	c.dialController = func(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
		f.dials++
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if target != endpoint {
			return nil, errDarwinRecovery
		}
		return f.raw, nil
	}
	return f
}
func TestDarwinNativeOwnedControllerTupleGuard(t *testing.T) {
	f := newDarwinControllerFixture(t)
	f.process.meta.Parent = 1
	conn, gone, err := f.process.platform.DialOwnedController(context.Background(), f.session, f.record, f.endpoint)
	if err != nil || gone || conn == nil {
		t.Fatalf("old owned tuple: gone=%v err=%v", gone, err)
	}
	defer conn.Close()
	if n, _ := f.raw.state(); n != 0 || f.releases.Load() != 0 {
		t.Fatal("application bytes or task release before verification/Close")
	}
	if _, ok := conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	}); ok {
		t.Fatal("guard exposed raw socket bypass")
	}
	if n, err := conn.Write([]byte("verified")); err != nil || n != 8 {
		t.Fatal(err)
	}
	f.process.token[7]++
	if n, err := conn.Write([]byte("secret")); err == nil || n != 0 {
		t.Fatal("identity drift received application bytes")
	}
	n, closed := f.raw.state()
	if n != 8 || !closed || f.releases.Load() != 1 {
		t.Fatal("identity drift did not close exactly once")
	}
	conn.Close()
	if f.releases.Load() != 1 {
		t.Fatal("task right released twice")
	}
}
func TestDarwinNativeOwnedControllerGoneWithoutDial(t *testing.T) {
	for _, which := range []string{"gone", "start", "version"} {
		t.Run(which, func(t *testing.T) {
			f := newDarwinControllerFixture(t)
			switch which {
			case "gone":
				f.process.terminated = true
			case "start":
				f.process.meta.StartUsec++
			case "version":
				f.process.token[7]++
			}
			conn, gone, err := f.process.platform.DialOwnedController(context.Background(), f.session, f.record, f.endpoint)
			if err != nil || !gone || conn != nil || f.dials != 0 {
				t.Fatalf("gone/reused PID was dialled: %v", err)
			}
		})
	}
}
func TestDarwinNativeOwnedControllerFailureBeforeWrite(t *testing.T) {
	for _, which := range []string{"hash", "path", "args", "parent", "permission", "metadata", "foreign", "closed", "lan", "cancel"} {
		t.Run(which, func(t *testing.T) {
			f := newDarwinControllerFixture(t)
			c := f.process.platform.calls.recovery
			ctx := context.Background()
			switch which {
			case "hash":
				f.process.files.BinaryInode++
			case "path":
				c.path = func(uint32) (string, error) { return "/wrong/image", nil }
			case "args":
				c.args = func(uint32) ([]string, error) { return []string{"mihomo", "--wrong"}, nil }
			case "parent":
				f.process.meta.Parent = 444
			case "permission":
				c.task = func(uint32) (uint32, [8]uint32, error) { return 0, [8]uint32{}, errors.New("denied") }
			case "metadata":
				c.meta = func(uint32) (darwinRecoveryMeta, error) { return darwinRecoveryMeta{}, errors.New("unknown") }
			case "foreign":
				other, _ := nativeDarwinFixture()
				f.session, _ = other.AcquireRestoreSession(ctx, f.session.Owner())
			case "closed":
				f.session.Close()
			case "lan":
				f.endpoint = netip.MustParseAddrPort("192.0.2.1:7899")
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			conn, gone, err := f.process.platform.DialOwnedController(ctx, f.session, f.record, f.endpoint)
			if err == nil || gone || conn != nil || f.dials != 0 {
				t.Fatal("unverified process reached controller")
			}
			if n, _ := f.raw.state(); n != 0 {
				t.Fatal("pre-verification application bytes")
			}
		})
	}
}
func TestDarwinNativeOwnedControllerDialRebindAndUnknownTuple(t *testing.T) {
	for _, which := range []string{"gone", "rebound", "tuple", "cookie", "cancel", "remote", "dial-error"} {
		t.Run(which, func(t *testing.T) {
			f := newDarwinControllerFixture(t)
			c := f.process.platform.calls.recovery
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			socketCalls := 0
			c.dialController = func(context.Context, netip.AddrPort) (net.Conn, error) {
				f.dials++
				switch which {
				case "gone":
					f.process.terminated = true
				case "rebound":
					f.process.meta.StartUsec++
				case "cancel":
					cancel()
				case "remote":
					f.raw.remote = net.TCPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:7900"))
				case "dial-error":
					return f.raw, errors.New("dial failed")
				}
				return f.raw, nil
			}
			c.controllerSocket = func(uint32, netip.AddrPort, netip.AddrPort) ([4]uint64, error) {
				socketCalls++
				if which == "tuple" {
					return [4]uint64{}, errors.New("tuple mismatch/unknown")
				}
				cookie := [4]uint64{7, 11, 12, 13}
				if which == "cookie" && socketCalls > 1 {
					cookie[2]++
				}
				return cookie, nil
			}
			conn, gone, err := f.process.platform.DialOwnedController(ctx, f.session, f.record, f.endpoint)
			wantGone := which == "gone" || which == "rebound"
			if conn != nil || gone != wantGone || !wantGone && err == nil {
				t.Fatalf("unverified dial escaped: gone=%v err=%v", gone, err)
			}
			n, closed := f.raw.state()
			if n != 0 || !closed || f.releases.Load() != 1 || f.dials != 1 {
				t.Fatal("failure leaked bytes/socket/task or redialled")
			}
		})
	}
}
func TestDarwinNativeOwnedControllerCancellationAndAcceptWait(t *testing.T) {
	f := newDarwinControllerFixture(t)
	c := f.process.platform.calls.recovery
	calls := 0
	original := c.controllerSocket
	c.controllerSocket = func(pid uint32, s, l netip.AddrPort) ([4]uint64, error) {
		calls++
		if calls == 1 {
			return [4]uint64{}, errDarwinControllerNotReady
		}
		return original(pid, s, l)
	}
	c.wait = func(context.Context) error { return nil }
	ctx, cancel := context.WithCancel(context.Background())
	conn, gone, err := f.process.platform.DialOwnedController(ctx, f.session, f.record, f.endpoint)
	if err != nil || gone {
		t.Fatal(err)
	}
	if f.dials != 1 || calls < 3 {
		t.Fatal("accept wait redialled or skipped proof")
	}
	cancel()
	conn.Close()
	if n, err := conn.Write([]byte("secret")); n != 0 || err == nil {
		t.Fatal("cancelled controller received bytes")
	}
	if n, closed := f.raw.state(); n != 0 || !closed || f.releases.Load() != 1 {
		t.Fatal("cancellation leaked resources")
	}
}
func TestDarwinNativeOwnedControllerLoopbackTCP(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	listener.SetDeadline(time.Now().Add(3 * time.Second))
	accepted := make(chan net.Conn, 1)
	go func() { conn, _ := listener.AcceptTCP(); accepted <- conn }()
	f := newDarwinControllerFixture(t)
	f.endpoint = listener.Addr().(*net.TCPAddr).AddrPort()
	c := f.process.platform.calls.recovery
	c.dialController = darwinRecoveryControllerDial
	var server net.Conn
	received := make(chan []byte, 1)
	c.controllerSocket = func(pid uint32, endpoint, client netip.AddrPort) ([4]uint64, error) {
		if server == nil {
			server = <-accepted
			if server == nil {
				return [4]uint64{}, errDarwinRecovery
			}
			t.Cleanup(func() { server.Close() })
			server.SetReadDeadline(time.Now().Add(3 * time.Second))
			go func() { buf := make([]byte, 64); n, _ := server.Read(buf); received <- slices.Clone(buf[:n]) }()
		}
		serverLocal, _ := darwinControllerEndpoint(server.LocalAddr())
		serverRemote, _ := darwinControllerEndpoint(server.RemoteAddr())
		if pid != f.record.Proof.PID || serverLocal != endpoint || serverRemote != client {
			return [4]uint64{}, errDarwinRecovery
		}
		return [4]uint64{7, 11, 12, 13}, nil
	}
	conn, gone, err := f.process.platform.DialOwnedController(context.Background(), f.session, f.record, f.endpoint)
	if err != nil || gone {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case <-received:
		t.Fatal("application bytes before verified dial returned")
	default:
	}
	if _, err = conn.Write([]byte("verified-loopback")); err != nil {
		t.Fatal(err)
	}
	if got := <-received; string(got) != "verified-loopback" {
		t.Fatalf("wrong verified bytes: %q", got)
	}
	conn.Close()
	if f.releases.Load() != 1 {
		t.Fatal("loopback task right leaked")
	}
}
