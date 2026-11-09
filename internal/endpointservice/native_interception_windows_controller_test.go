package endpointservice

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type winControllerFakeLease struct {
	f      *winControllerFixture
	closes int
	once   sync.Once
}

func (l *winControllerFakeLease) Close() error { l.once.Do(func() { l.closes++ }); return nil }
func (l *winControllerFakeLease) Inspect(ctx context.Context) (winControllerObserved, bool, error) {
	l.f.inspections++
	if l.f.inspectAt != nil {
		l.f.inspectAt(l.f.inspections)
	}
	if err := ctx.Err(); err != nil {
		return winControllerObserved{}, false, err
	}
	return l.f.observed, l.f.dead, l.f.inspectErr
}

type winControllerFakeConn struct {
	local, remote  netip.AddrPort
	writes, closes int
	data           []byte
	closed         bool
}

func (c *winControllerFakeConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *winControllerFakeConn) Write(p []byte) (int, error) {
	if c.closed {
		return 0, net.ErrClosed
	}
	c.writes++
	c.data = append(c.data, p...)
	return len(p), nil
}
func (c *winControllerFakeConn) Close() error                     { c.closes++; c.closed = true; return nil }
func (c *winControllerFakeConn) LocalAddr() net.Addr              { return net.TCPAddrFromAddrPort(c.local) }
func (c *winControllerFakeConn) RemoteAddr() net.Addr             { return net.TCPAddrFromAddrPort(c.remote) }
func (c *winControllerFakeConn) SetDeadline(time.Time) error      { return nil }
func (c *winControllerFakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *winControllerFakeConn) SetWriteDeadline(time.Time) error { return nil }

type winControllerFixture struct {
	proof                                  nativeOwnedProcessProof
	observed                               winControllerObserved
	session                                winNativeTestSession
	parent                                 uint32
	parentCreated                          uint64
	leases                                 []*winControllerFakeLease
	conn                                   *winControllerFakeConn
	rows                                   []winControllerTuple
	dead                                   bool
	inspectErr, tupleErr, openErr, dialErr error
	opens, dials, inspections              int
	inspectAt                              func(int)
	dialAt                                 func()
	foreign                                bool
}

func newWinControllerFixture() *winControllerFixture {
	dir := `C:\ProgramData\Soha\mihomo-process\launch-a`
	proof := nativeOwnedProcessProof{PID: 77, ProcessEpoch: strings.Repeat("a", 32), BinarySHA256: strings.Repeat("b", 64), LaunchDirectory: dir, ExecutablePath: dir + `\mihomo.exe`}
	proof.Arguments = []string{proof.ExecutablePath, "-d", dir, "-f", dir + `\config.yaml`}
	stamp := winControllerStamp{Created: 1000, ParentPID: 22, ParentCreated: 500, BinaryVolume: 1, BinaryFile: 11, DirectoryVolume: 1, DirectoryFile: 22, ParentVolume: 1, ParentFile: 33}
	server := netip.MustParseAddrPort("127.0.0.1:7890")
	client := netip.MustParseAddrPort("127.0.0.1:53000")
	return &winControllerFixture{proof: proof, parent: 22, parentCreated: 500, observed: winControllerObserved{Stamp: stamp, PID: 77, Image: proof.ExecutablePath, Hash: proof.BinarySHA256, Arguments: slices.Clone(proof.Arguments), Trusted: true}, conn: &winControllerFakeConn{local: client, remote: server}, rows: []winControllerTuple{{Local: server, Remote: client, PID: 77, State: 5}, {Local: client, Remote: server, PID: 22, State: 5}}}
}
func (f *winControllerFixture) calls() winControllerCalls {
	return winControllerCalls{session: func(ctx context.Context, s nativeSession, restore bool) error {
		if f.foreign || s == nil {
			return errWinController
		}
		return s.Validate(ctx, restore)
	}, proof: func(p nativeOwnedProcessProof) bool { return winControllerProofValid(p, `C:\ProgramData\Soha`) }, parent: func() (uint32, uint64, error) { return f.parent, f.parentCreated, nil }, open: func(ctx context.Context, p nativeOwnedProcessProof, expected *winControllerStamp) (winControllerLease, bool, error) {
		f.opens++
		if f.openErr != nil {
			return nil, false, f.openErr
		}
		if f.dead || expected != nil && expected.Created != f.observed.Stamp.Created {
			return nil, true, nil
		}
		lease := &winControllerFakeLease{f: f}
		f.leases = append(f.leases, lease)
		return lease, false, nil
	}, dial: func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
		f.dials++
		if f.dialAt != nil {
			f.dialAt()
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if f.dialErr != nil {
			return nil, f.dialErr
		}
		return f.conn, nil
	}, tuples: func(context.Context, bool) ([]winControllerTuple, error) { return f.rows, f.tupleErr }, servicePID: f.parent}
}
func (f *winControllerFixture) capture(t *testing.T) nativeOwnedProcessIdentity {
	t.Helper()
	record, err := winControllerCapture(context.Background(), &f.session, f.proof, f.calls())
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Incarnation) > 200 || len(f.leases) != 1 || f.leases[0].closes != 1 {
		t.Fatal("capture leaked or exceeded identity bound")
	}
	return record
}
func TestWinNativeControllerIdentityAndPinnedWrite(t *testing.T) {
	f := newWinControllerFixture()
	record := f.capture(t)
	f.session.restoreOnly = true
	conn, gone, err := winControllerDial(context.Background(), &f.session, record, f.conn.remote, f.calls())
	if err != nil || gone || conn == nil {
		t.Fatal(gone, err)
	}
	if f.conn.writes != 0 {
		t.Fatal("application bytes before proof")
	}
	if _, ok := conn.(syscall.Conn); ok {
		t.Fatal("raw connection exposed")
	}
	if _, err := conn.Write([]byte("secret")); err != nil || f.conn.writes != 1 {
		t.Fatal("verified write rejected", err)
	}
	f.observed.Image = `C:\foreign.exe`
	if n, err := conn.Write([]byte("must-not-write")); err == nil || n != 0 || f.conn.writes != 1 {
		t.Fatal("proof drift sent bytes")
	}
	_ = conn.Close()
	_ = conn.Close()
	if f.conn.closes != 1 || f.leases[1].closes != 1 {
		t.Fatal("close did not release once")
	}
	if _, err := conn.Write([]byte("closed")); err == nil || f.conn.writes != 1 {
		t.Fatal("closed wrapper wrote")
	}
}
func TestWinNativeControllerCaptureRejectsProofDrift(t *testing.T) {
	for _, name := range []string{"image", "hash", "args", "parent", "parent creation", "private trust", "extra args"} {
		t.Run(name, func(t *testing.T) {
			f := newWinControllerFixture()
			switch name {
			case "image":
				f.observed.Image = `C:\foreign.exe`
			case "hash":
				f.observed.Hash = strings.Repeat("c", 64)
			case "args":
				f.observed.Arguments = []string{"foreign"}
			case "parent":
				f.observed.Stamp.ParentPID++
			case "parent creation":
				f.observed.Stamp.ParentCreated++
			case "private trust":
				f.observed.Trusted = false
			case "extra args":
				f.proof.Arguments = append(f.proof.Arguments, "--foreign")
			}
			if _, err := winControllerCapture(context.Background(), &f.session, f.proof, f.calls()); err == nil || f.dials != 0 {
				t.Fatal("capture accepted drift")
			}
			for _, l := range f.leases {
				if l.closes != 1 {
					t.Fatal("capture leaked")
				}
			}
		})
	}
}
func TestWinNativeControllerDialGoneAndUnknown(t *testing.T) {
	for _, name := range []string{"reused PID", "exited", "dial exit", "dial rebound", "wrong tuple", "unknown tuple", "permission", "commandline drift", "unknown metadata", "cancelled", "cancel in dial", "closed session", "foreign session"} {
		t.Run(name, func(t *testing.T) {
			f := newWinControllerFixture()
			record := f.capture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			wantGone := false
			switch name {
			case "reused PID":
				f.observed.Stamp.Created++
				wantGone = true
			case "exited":
				f.dead = true
				wantGone = true
			case "dial exit":
				f.dialAt = func() { f.dead = true }
				wantGone = true
			case "dial rebound":
				f.dialAt = func() { f.rows[0].PID = 88 }
			case "wrong tuple":
				f.rows[0].Remote = netip.MustParseAddrPort("127.0.0.1:53001")
			case "unknown tuple":
				f.tupleErr = errors.New("table unavailable")
			case "permission":
				f.openErr = errors.New("access denied")
			case "commandline drift":
				f.observed.Arguments = []string{"changed"}
			case "unknown metadata":
				f.inspectErr = errors.New("NT/PEB unavailable")
			case "cancelled":
				cancel()
			case "cancel in dial":
				f.dialAt = cancel
			case "closed session":
				f.session.denied = true
			case "foreign session":
				f.foreign = true
			}
			conn, gone, err := winControllerDial(ctx, &f.session, record, f.conn.remote, f.calls())
			if conn != nil || gone != wantGone || (err == nil) != wantGone || f.conn.writes != 0 {
				t.Fatalf("conn=%v gone=%v error=%v writes=%d", conn, gone, err, f.conn.writes)
			}
			for _, l := range f.leases {
				if l.closes != 1 {
					t.Fatal("dial leaked lease")
				}
			}
		})
	}
}
func TestWinNativeControllerOriginalParentAndWriteTuple(t *testing.T) {
	f := newWinControllerFixture()
	record := f.capture(t)
	f.parent = 99
	f.parentCreated = 1500
	f.rows[1].PID = 99
	conn, gone, err := winControllerDial(context.Background(), &f.session, record, f.conn.remote, f.calls())
	if err != nil || gone {
		t.Fatal("dial incorrectly required new service to be original parent", err)
	}
	f.rows[0].PID = 88
	if n, err := conn.Write([]byte("secret")); err == nil || n != 0 || f.conn.writes != 0 {
		t.Fatal("tuple rebound accepted on write")
	}
	_ = conn.Close()
}
func TestWinNativeControllerTupleLayouts(t *testing.T) {
	for _, ipv4 := range []bool{true, false} {
		stride := 56
		if ipv4 {
			stride = 24
		}
		buf := make([]byte, 4+stride)
		binary.LittleEndian.PutUint32(buf, 1)
		r := buf[4:]
		if ipv4 {
			binary.LittleEndian.PutUint32(r, 5)
			copy(r[4:], []byte{127, 0, 0, 1})
			binary.BigEndian.PutUint16(r[8:], 7890)
			copy(r[12:], []byte{127, 0, 0, 1})
			binary.BigEndian.PutUint16(r[16:], 53000)
			binary.LittleEndian.PutUint32(r[20:], 77)
		} else {
			r[15] = 1
			binary.BigEndian.PutUint16(r[20:], 7890)
			r[39] = 1
			binary.BigEndian.PutUint16(r[44:], 53000)
			binary.LittleEndian.PutUint32(r[48:], 5)
			binary.LittleEndian.PutUint32(r[52:], 77)
		}
		rows, err := winControllerParseTuples(buf, ipv4)
		if err != nil || len(rows) != 1 || rows[0].PID != 77 || rows[0].State != 5 || rows[0].Local.Port() != 7890 || rows[0].Remote.Port() != 53000 {
			t.Fatal("tuple table parsed incorrectly", err)
		}
		if _, err := winControllerParseTuples(buf[:len(buf)-1], ipv4); err == nil {
			t.Fatal("truncated table accepted")
		}
	}
}

func TestWinNativeControllerOriginalProofBinding(t *testing.T) {
	f := newWinControllerFixture()
	record := f.capture(t)
	record.Proof.ProcessEpoch = strings.Repeat("c", 32)
	if conn, gone, err := winControllerDial(context.Background(), &f.session, record, f.conn.remote, f.calls()); conn != nil || gone || err == nil || f.opens != 1 || f.dials != 0 {
		t.Fatal("altered original proof was not rejected before open")
	}
}
func TestWinNativeControllerWriteSessionAndTupleBoundaries(t *testing.T) {
	for _, name := range []string{"closed restore session", "foreign restore session", "wrong client PID", "duplicate server PID", "non-established"} {
		t.Run(name, func(t *testing.T) {
			f := newWinControllerFixture()
			record := f.capture(t)
			conn, gone, err := winControllerDial(context.Background(), &f.session, record, f.conn.remote, f.calls())
			if err != nil || gone {
				t.Fatal(err)
			}
			switch name {
			case "closed restore session":
				f.session.denied = true
			case "foreign restore session":
				f.foreign = true
			case "wrong client PID":
				f.rows[1].PID++
			case "duplicate server PID":
				row := f.rows[0]
				row.PID++
				f.rows = append(f.rows, row)
			case "non-established":
				f.rows[0].State = 2
			}
			if n, err := conn.Write([]byte("secret")); n != 0 || err == nil || f.conn.writes != 0 || f.conn.closes != 1 || f.leases[1].closes != 1 {
				t.Fatal("failed write leaked application bytes or handles")
			}
			_ = conn.Close()
		})
	}
}
func TestWinNativeControllerIPv6(t *testing.T) {
	f := newWinControllerFixture()
	f.conn.local = netip.MustParseAddrPort("[::1]:53000")
	f.conn.remote = netip.MustParseAddrPort("[::1]:7890")
	f.rows[0].Local, f.rows[0].Remote = f.conn.remote, f.conn.local
	f.rows[1].Local, f.rows[1].Remote = f.conn.local, f.conn.remote
	record := f.capture(t)
	conn, gone, err := winControllerDial(context.Background(), &f.session, record, f.conn.remote, f.calls())
	if err != nil || gone {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("verified")); err != nil {
		t.Fatal(err)
	}
	f.rows[0].LocalScope = 1
	if n, err := conn.Write([]byte("secret")); n != 0 || err == nil || f.conn.writes != 1 {
		t.Fatal("scope drift accepted")
	}
	_ = conn.Close()
}

func TestWinNativeControllerCaptureRequiresActiveSession(t *testing.T) {
	f := newWinControllerFixture()
	f.session.restoreOnly = true
	calls := f.calls()
	proofReads, parentReads := 0, 0
	proof, parent := calls.proof, calls.parent
	calls.proof = func(p nativeOwnedProcessProof) bool { proofReads++; return proof(p) }
	calls.parent = func() (uint32, uint64, error) { parentReads++; return parent() }
	if _, err := winControllerCapture(context.Background(), &f.session, f.proof, calls); err == nil {
		t.Error("restore-only session captured a new process proof")
	}
	if proofReads != 0 || parentReads != 0 || f.opens != 0 || f.inspections != 0 || f.dials != 0 {
		t.Fatalf("authorization preceded process/proof access: proof=%d parent=%d open=%d inspect=%d dial=%d", proofReads, parentReads, f.opens, f.inspections, f.dials)
	}
}
func TestWinNativeControllerRestoreDialCannotCaptureOrEnable(t *testing.T) {
	f := newWinControllerFixture()
	record := f.capture(t)
	f.session.restoreOnly = true
	conn, gone, err := winControllerDial(context.Background(), &f.session, record, f.conn.remote, f.calls())
	if err != nil || gone {
		t.Fatal("durable proof restoration dial rejected", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("owned-cleanup")); err != nil {
		t.Fatal("restore-only cleanup write rejected", err)
	}
	if err := f.session.Validate(context.Background(), false); err == nil {
		t.Fatal("restoration enabled active session authority")
	}
	opens := f.opens
	if _, err := winControllerCapture(context.Background(), &f.session, f.proof, f.calls()); err == nil || f.opens != opens {
		t.Fatal("restore dial permitted recapture")
	}
}

func TestWinNativeControllerCaptureRechecksActiveSession(t *testing.T) {
	f := newWinControllerFixture()
	f.inspectAt = func(n int) {
		if n == 2 {
			f.session.restoreOnly = true
		}
	}
	if record, err := winControllerCapture(context.Background(), &f.session, f.proof, f.calls()); err == nil || record.Incarnation != "" {
		t.Fatal("capture returned proof after session lost active authority")
	}
	if len(f.leases) != 1 || f.leases[0].closes != 1 || f.dials != 0 {
		t.Fatal("failed capture leaked lease or dialed")
	}
}
