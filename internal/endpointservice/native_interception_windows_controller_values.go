package endpointservice

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var errWinController = errors.New("owned controller identity or connection proof unavailable")

type winControllerStamp struct{ Created, ParentPID, ParentCreated, BinaryVolume, BinaryFile, DirectoryVolume, DirectoryFile, ParentVolume, ParentFile uint64 }
type winControllerObserved struct {
	Stamp       winControllerStamp
	PID         uint32
	Image, Hash string
	Arguments   []string
	Trusted     bool
}
type winControllerLease interface {
	Inspect(context.Context) (winControllerObserved, bool, error)
	Close() error
}
type winControllerCalls struct {
	session    func(context.Context, nativeSession, bool) error
	proof      func(nativeOwnedProcessProof) bool
	parent     func() (uint32, uint64, error)
	open       func(context.Context, nativeOwnedProcessProof, *winControllerStamp) (winControllerLease, bool, error)
	dial       func(context.Context, netip.AddrPort) (net.Conn, error)
	tuples     func(context.Context, bool) ([]winControllerTuple, error)
	servicePID uint32
}

func winControllerClean(p string) string { return path.Clean(strings.ReplaceAll(p, `\`, "/")) }
func winControllerProofValid(p nativeOwnedProcessProof, state string) bool {
	if strings.ContainsRune(p.ExecutablePath, 0) || strings.ContainsRune(p.LaunchDirectory, 0) {
		return false
	}
	if p.PID < 2 || len(p.ProcessEpoch) != 32 || len(p.BinarySHA256) != 64 || len(p.ExecutablePath) > 3200 || len(p.LaunchDirectory) > 3000 || p.ProcessEpoch != strings.ToLower(p.ProcessEpoch) || p.BinarySHA256 != strings.ToLower(p.BinarySHA256) {
		return false
	}
	if _, err := hex.DecodeString(p.ProcessEpoch); err != nil {
		return false
	}
	if _, err := hex.DecodeString(p.BinarySHA256); err != nil {
		return false
	}
	d, e := winControllerClean(p.LaunchDirectory), winControllerClean(p.ExecutablePath)
	if !strings.EqualFold(path.Dir(d), winControllerClean(state)+"/mihomo-process") || !strings.HasPrefix(path.Base(d), "launch-") || !strings.EqualFold(path.Dir(e), d) || (path.Base(e) != "mihomo.exe" && path.Base(e) != "mihomo") {
		return false
	}
	slash := "/"
	if strings.Contains(p.LaunchDirectory, `\`) {
		slash = `\`
	}
	return slices.Equal(p.Arguments, []string{p.ExecutablePath, "-d", p.LaunchDirectory, "-f", p.LaunchDirectory + slash + "config.yaml"})
}
func winControllerEncode(s winControllerStamp, proof nativeOwnedProcessProof) string {
	v := []uint64{1, s.Created, s.ParentPID, s.ParentCreated, s.BinaryVolume, s.BinaryFile, s.DirectoryVolume, s.DirectoryFile, s.ParentVolume, s.ParentFile}
	data := make([]byte, len(v)*8)
	for i, n := range v {
		binary.BigEndian.PutUint64(data[i*8:], n)
	}
	raw, _ := json.Marshal(proof)
	digest := sha256.Sum256(raw)
	data = append(data, digest[:]...)
	return "windows-ctrl-v1:" + base64.RawURLEncoding.EncodeToString(data)
}
func winControllerDecode(text string, proof nativeOwnedProcessProof) (winControllerStamp, error) {
	var s winControllerStamp
	if len(text) > 200 || !strings.HasPrefix(text, "windows-ctrl-v1:") {
		return s, errWinController
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(text, "windows-ctrl-v1:"))
	if err != nil || len(data) != 112 {
		return s, errWinController
	}
	v := make([]uint64, 10)
	for i := range v {
		v[i] = binary.BigEndian.Uint64(data[i*8:])
	}
	if v[0] != 1 || v[1] == 0 || v[2] < 2 || v[2] > 4294967295 || v[3] == 0 || v[3] > v[1] || v[5] == 0 || v[7] == 0 || v[9] == 0 {
		return s, errWinController
	}
	s = winControllerStamp{v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9]}
	if winControllerEncode(s, proof) != text {
		return s, errWinController
	}
	return s, nil
}
func winControllerCheck(o winControllerObserved, p nativeOwnedProcessProof, expected *winControllerStamp) error {
	if !o.Trusted || o.PID != p.PID || !strings.EqualFold(winControllerClean(o.Image), winControllerClean(p.ExecutablePath)) || o.Hash != p.BinarySHA256 || !slices.Equal(o.Arguments, p.Arguments) {
		return errWinController
	}
	if expected != nil && o.Stamp != *expected {
		return errWinController
	}
	return nil
}
func winControllerCapture(ctx context.Context, s nativeSession, p nativeOwnedProcessProof, c winControllerCalls) (nativeOwnedProcessIdentity, error) {
	var zero nativeOwnedProcessIdentity
	if err := c.session(ctx, s, false); err != nil {
		return zero, err
	}
	if !c.proof(p) {
		return zero, errWinController
	}
	p.Arguments = slices.Clone(p.Arguments)
	lease, gone, err := c.open(ctx, p, nil)
	if err != nil {
		if lease != nil {
			_ = lease.Close()
		}
		return zero, err
	}
	if lease != nil {
		defer lease.Close()
	}
	if gone || lease == nil {
		return zero, errWinController
	}
	first, gone, err := lease.Inspect(ctx)
	if err != nil || gone {
		return zero, errWinController
	}
	if err := winControllerCheck(first, p, nil); err != nil {
		return zero, err
	}
	parent, created, err := c.parent()
	if err != nil || first.Stamp.ParentPID != uint64(parent) || first.Stamp.ParentCreated != created {
		return zero, errWinController
	}
	second, gone, err := lease.Inspect(ctx)
	if err != nil || gone {
		return zero, errWinController
	}
	if err := winControllerCheck(second, p, &first.Stamp); err != nil {
		return zero, err
	}
	if err := c.session(ctx, s, false); err != nil {
		return zero, err
	}
	inc := winControllerEncode(first.Stamp, p)
	if _, err := winControllerDecode(inc, p); err != nil {
		return zero, err
	}
	return nativeOwnedProcessIdentity{Proof: p, Incarnation: inc}, nil
}

type winControllerTuple struct {
	Local, Remote                       netip.AddrPort
	PID, State, LocalScope, RemoteScope uint32
}

func winControllerTupleOwned(rows []winControllerTuple, server, client netip.AddrPort, owner, service uint32) error {
	if !server.IsValid() || !client.IsValid() || !server.Addr().IsLoopback() || !client.Addr().IsLoopback() || server.Port() == 0 || client.Port() == 0 || owner == 0 || service == 0 || server == client || server.Addr().Is4() != client.Addr().Is4() || server.Addr().Is4In6() || client.Addr().Is4In6() || server.Addr().Zone() != "" || client.Addr().Zone() != "" {
		return errWinController
	}
	sf, cf := false, false
	for _, r := range rows {
		serverSide := r.Local == server && r.Remote == client
		clientSide := r.Local == client && r.Remote == server
		if !serverSide && !clientSide {
			continue
		}
		if r.State != 5 || r.LocalScope != 0 || r.RemoteScope != 0 {
			return errWinController
		}
		if serverSide {
			if r.PID != owner {
				return errWinController
			}
			sf = true
		}
		if clientSide {
			if r.PID != service {
				return errWinController
			}
			cf = true
		}
	}
	if !sf || !cf {
		return errWinController
	}
	return nil
}
func winControllerParseTuples(buf []byte, ipv4 bool) ([]winControllerTuple, error) {
	if len(buf) < 4 {
		return nil, errWinController
	}
	count := binary.LittleEndian.Uint32(buf)
	stride := 56
	if ipv4 {
		stride = 24
	}
	if uint64(count)*uint64(stride) > uint64(len(buf)-4) {
		return nil, errWinController
	}
	out := make([]winControllerTuple, 0, count)
	for n := uint32(0); n < count; n++ {
		r := buf[4+int(n)*stride : 4+(int(n)+1)*stride]
		var row winControllerTuple
		if ipv4 {
			row.State = binary.LittleEndian.Uint32(r)
			row.Local = netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[4:8])), binary.BigEndian.Uint16(r[8:10]))
			row.Remote = netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[12:16])), binary.BigEndian.Uint16(r[16:18]))
			row.PID = binary.LittleEndian.Uint32(r[20:24])
		} else {
			row.Local = netip.AddrPortFrom(netip.AddrFrom16([16]byte(r[:16])), binary.BigEndian.Uint16(r[20:22]))
			row.Remote = netip.AddrPortFrom(netip.AddrFrom16([16]byte(r[24:40])), binary.BigEndian.Uint16(r[44:46]))
			row.LocalScope = binary.LittleEndian.Uint32(r[16:20])
			row.RemoteScope = binary.LittleEndian.Uint32(r[40:44])
			row.State = binary.LittleEndian.Uint32(r[48:52])
			row.PID = binary.LittleEndian.Uint32(r[52:56])
		}
		out = append(out, row)
	}
	return out, nil
}
func winControllerDial(ctx context.Context, s nativeSession, record nativeOwnedProcessIdentity, endpoint netip.AddrPort, c winControllerCalls) (net.Conn, bool, error) {
	if err := c.session(ctx, s, true); err != nil {
		return nil, false, err
	}
	if !c.proof(record.Proof) || !endpoint.IsValid() || endpoint.Port() == 0 || !endpoint.Addr().IsLoopback() || endpoint.Addr().Is4In6() || endpoint.Addr().Zone() != "" {
		return nil, false, errWinController
	}
	stamp, err := winControllerDecode(record.Incarnation, record.Proof)
	if err != nil {
		return nil, false, err
	}
	record.Proof.Arguments = slices.Clone(record.Proof.Arguments)
	lease, gone, err := c.open(ctx, record.Proof, &stamp)
	if err != nil {
		if lease != nil {
			_ = lease.Close()
		}
		return nil, false, err
	}
	if gone {
		if lease != nil {
			lease.Close()
		}
		return nil, true, nil
	}
	if lease == nil {
		return nil, false, errWinController
	}
	keep := false
	defer func() {
		if !keep {
			lease.Close()
		}
	}()
	check := func(ctx context.Context) (bool, error) {
		if err := c.session(ctx, s, true); err != nil {
			return false, err
		}
		o, gone, err := lease.Inspect(ctx)
		if err != nil {
			return false, err
		}
		if gone {
			return true, nil
		}
		return false, winControllerCheck(o, record.Proof, &stamp)
	}
	if gone, err := check(ctx); err != nil || gone {
		return nil, gone, err
	}
	conn, err := c.dial(ctx, endpoint)
	if err != nil {
		if gone, checkErr := check(ctx); gone && checkErr == nil {
			return nil, true, nil
		}
		return nil, false, err
	}
	connKeep := false
	defer func() {
		if !connKeep {
			conn.Close()
		}
	}()
	local, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		return nil, false, errWinController
	}
	remote, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil || remote != endpoint {
		return nil, false, errWinController
	}
	verify := func(ctx context.Context) (bool, error) {
		gone, err := check(ctx)
		if err != nil || gone {
			return gone, err
		}
		rows, err := c.tuples(ctx, endpoint.Addr().Is4())
		if err != nil {
			return false, err
		}
		if err := winControllerTupleOwned(rows, endpoint, local, record.Proof.PID, c.servicePID); err != nil {
			return false, err
		}
		return check(ctx)
	}
	if gone, err := verify(ctx); err != nil || gone {
		return nil, gone, err
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	keep, connKeep = true, true
	return &winControllerConn{conn: conn, lease: lease, verify: verify}, false, nil
}

type winControllerConn struct {
	conn     net.Conn
	lease    winControllerLease
	verify   func(context.Context) (bool, error)
	mu       sync.Mutex
	once     sync.Once
	closed   atomic.Bool
	closeErr error
}

func (c *winControllerConn) Read(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.conn.Read(p)
}
func (c *winControllerConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed.Load() {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	gone, err := c.verify(ctx)
	cancel()
	if err != nil || gone {
		c.mu.Unlock()
		_ = c.Close()
		if err == nil {
			err = errWinController
		}
		return 0, err
	}
	if c.closed.Load() {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	n, err := c.conn.Write(p)
	c.mu.Unlock()
	if err != nil {
		_ = c.Close()
	}
	return n, err
}
func (c *winControllerConn) Close() error {
	c.once.Do(func() {
		c.closed.Store(true)
		first := c.conn.Close()
		c.mu.Lock()
		c.closeErr = errors.Join(first, c.lease.Close())
		c.mu.Unlock()
	})
	return c.closeErr
}
func (c *winControllerConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *winControllerConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *winControllerConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *winControllerConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *winControllerConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
