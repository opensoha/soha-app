//go:build darwin && cgo

package endpointservice

/*
#include <stdlib.h>
#include <stdint.h>
int ni_recovery_meta(unsigned int,uint64_t *);
int ni_recovery_path(unsigned int,char *,int);
char *ni_recovery_args(unsigned int,int *);
int ni_recovery_task(unsigned int,unsigned int *,unsigned int *);
int ni_recovery_audit(unsigned int,unsigned int *);
int ni_recovery_terminate(unsigned int);
void ni_recovery_release(unsigned int);
int ni_recovery_controller(unsigned int,int,const void *,unsigned short,const void *,unsigned short,uint64_t *);
*/
import "C"

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

var errDarwinRecovery = errors.New("macOS owned process identity or task permission could not be verified")
var errDarwinProcessGone = errors.New("exact macOS process is absent")
var errDarwinControllerNotReady = errors.New("owned controller accepted tuple not yet visible")

type darwinRecoveryMeta struct{ StartSec, StartUsec, UID, RUID, Parent, Group, Status uint64 }
type darwinRecoveryFiles struct{ BinaryDevice, BinaryInode, BinaryCTimeSec, BinaryCTimeNS, DirectoryDevice, DirectoryInode uint64 }
type darwinRecoveryIdentity struct {
	Meta    darwinRecoveryMeta
	Version uint32
	Files   darwinRecoveryFiles
}
type darwinRecoveryCalls struct {
	controllerSocket func(uint32, netip.AddrPort, netip.AddrPort) ([4]uint64, error)
	dialController   func(context.Context, netip.AddrPort) (net.Conn, error)
	meta             func(uint32) (darwinRecoveryMeta, error)
	path             func(uint32) (string, error)
	args             func(uint32) ([]string, error)
	files            func(nativeOwnedProcessProof) (darwinRecoveryFiles, error)
	task             func(uint32) (uint32, [8]uint32, error)
	audit            func(uint32) ([8]uint32, error)
	terminate        func(uint32) error
	release          func(uint32)
	self             func() uint32
	uid              func() uint32
	wait             func(context.Context) error
}

func darwinRecoverySystemCalls() *darwinRecoveryCalls {
	return &darwinRecoveryCalls{controllerSocket: darwinRecoveryControllerSocket, dialController: darwinRecoveryControllerDial, meta: darwinRecoveryReadMeta, path: darwinRecoveryPath, args: darwinRecoveryArgs, files: darwinRecoveryVerifyFiles, task: darwinRecoveryTask, audit: darwinRecoveryAudit, terminate: darwinRecoveryTerminate, release: func(port uint32) { C.ni_recovery_release(C.uint(port)) }, self: func() uint32 { return uint32(os.Getpid()) }, uid: func() uint32 { return uint32(os.Geteuid()) }, wait: func(ctx context.Context) error {
		timer := time.NewTimer(25 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}}
}
func (p *darwinNativePlatform) recovery() *darwinRecoveryCalls {
	if p.calls.recovery != nil {
		return p.calls.recovery
	}
	return darwinRecoverySystemCalls()
}
func darwinRecoveryProofValid(p nativeOwnedProcessProof) bool {
	if p.PID < 2 || p.PID > 2147483647 || len(p.ProcessEpoch) != 32 || len(p.BinarySHA256) != 64 || p.ProcessEpoch != strings.ToLower(p.ProcessEpoch) || p.BinarySHA256 != strings.ToLower(p.BinarySHA256) {
		return false
	}
	if _, err := hex.DecodeString(p.ProcessEpoch); err != nil {
		return false
	}
	if _, err := hex.DecodeString(p.BinarySHA256); err != nil {
		return false
	}
	if !filepath.IsAbs(p.LaunchDirectory) || filepath.Clean(p.LaunchDirectory) != p.LaunchDirectory || len(p.LaunchDirectory) > 3000 || !strings.HasPrefix(filepath.Base(p.LaunchDirectory), "launch-") {
		return false
	}
	if p.ExecutablePath != filepath.Join(p.LaunchDirectory, "mihomo") {
		return false
	}
	return slices.Equal(p.Arguments, []string{p.ExecutablePath, "-d", p.LaunchDirectory, "-f", filepath.Join(p.LaunchDirectory, "config.yaml")})
}
func darwinRecoveryEncode(identity darwinRecoveryIdentity) string {
	values := []uint64{1, identity.Meta.StartSec, identity.Meta.StartUsec, identity.Meta.UID, identity.Meta.RUID, identity.Meta.Parent, identity.Meta.Group, uint64(identity.Version), identity.Files.BinaryDevice, identity.Files.BinaryInode, identity.Files.BinaryCTimeSec, identity.Files.BinaryCTimeNS, identity.Files.DirectoryDevice, identity.Files.DirectoryInode}
	data := make([]byte, len(values)*8)
	for i, v := range values {
		binary.BigEndian.PutUint64(data[i*8:], v)
	}
	return "darwin-v1:" + base64.RawURLEncoding.EncodeToString(data)
}
func darwinRecoveryDecode(text string) (darwinRecoveryIdentity, error) {
	var id darwinRecoveryIdentity
	if len(text) > 200 || !strings.HasPrefix(text, "darwin-v1:") {
		return id, errDarwinRecovery
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(text, "darwin-v1:"))
	if err != nil || len(data) != 14*8 {
		return id, errDarwinRecovery
	}
	v := make([]uint64, 14)
	for i := range v {
		v[i] = binary.BigEndian.Uint64(data[i*8:])
	}
	if v[0] != 1 || v[1] == 0 || v[2] >= 1000000 || v[7] == 0 || v[7] > 4294967295 {
		return id, errDarwinRecovery
	}
	id.Meta = darwinRecoveryMeta{StartSec: v[1], StartUsec: v[2], UID: v[3], RUID: v[4], Parent: v[5], Group: v[6]}
	id.Version = uint32(v[7])
	id.Files = darwinRecoveryFiles{v[8], v[9], v[10], v[11], v[12], v[13]}
	if darwinRecoveryEncode(id) != text {
		return id, errDarwinRecovery
	}
	return id, nil
}
func darwinRecoverySameStart(a, b darwinRecoveryMeta) bool {
	return a.StartSec == b.StartSec && a.StartUsec == b.StartUsec
}
func darwinRecoveryToken(token [8]uint32, pid, version uint32, meta darwinRecoveryMeta) bool {
	return token[5] == pid && token[7] > 0 && (version == 0 || token[7] == version) && uint64(token[1]) == meta.UID && uint64(token[3]) == meta.RUID
}
func darwinRecoveryInspect(c *darwinRecoveryCalls, proof nativeOwnedProcessProof, meta darwinRecoveryMeta) (darwinRecoveryFiles, error) {
	actual, err := c.path(proof.PID)
	if err != nil || actual != proof.ExecutablePath {
		return darwinRecoveryFiles{}, errDarwinRecovery
	}
	args, err := c.args(proof.PID)
	if err != nil || !slices.Equal(args, proof.Arguments) {
		return darwinRecoveryFiles{}, errDarwinRecovery
	}
	files, err := c.files(proof)
	if err != nil {
		return files, errDarwinRecovery
	}
	second, err := c.meta(proof.PID)
	if err != nil || !darwinRecoverySameStart(second, meta) || second.UID != meta.UID || second.RUID != meta.RUID || second.Group != meta.Group || second.Parent != meta.Parent {
		return files, errDarwinRecovery
	}
	return files, nil
}
func (p *darwinNativePlatform) CaptureOwnedProcess(ctx context.Context, session nativeSession, proof nativeOwnedProcessProof) (nativeOwnedProcessIdentity, error) {
	var result nativeOwnedProcessIdentity
	if err := p.session(session, ctx, false); err != nil {
		return result, err
	}
	if !darwinRecoveryProofValid(proof) {
		return result, errDarwinRecovery
	}
	c := p.recovery()
	meta, err := c.meta(proof.PID)
	if err != nil {
		return result, err
	}
	if meta.Parent != uint64(c.self()) || meta.Group != uint64(proof.PID) || meta.UID != uint64(c.uid()) || meta.RUID != uint64(c.uid()) || meta.StartSec == 0 || meta.StartUsec >= 1000000 {
		return result, errDarwinRecovery
	}
	port, token, err := c.task(proof.PID)
	if err != nil {
		if port != 0 {
			c.release(port)
		}
		return result, errDarwinRecovery
	}
	if port == 0 {
		return result, errDarwinRecovery
	}
	defer c.release(port)
	if !darwinRecoveryToken(token, proof.PID, 0, meta) {
		return result, errDarwinRecovery
	}
	files, err := darwinRecoveryInspect(c, proof, meta)
	if err != nil {
		return result, err
	}
	final, err := c.audit(port)
	if err != nil || final != token {
		return result, errDarwinRecovery
	}
	if err = p.session(session, ctx, false); err != nil {
		return result, err
	}
	result = nativeOwnedProcessIdentity{Proof: proof, Incarnation: darwinRecoveryEncode(darwinRecoveryIdentity{Meta: meta, Version: token[7], Files: files})}
	result.Proof.Arguments = slices.Clone(proof.Arguments)
	return result, nil
}
func (p *darwinNativePlatform) RecoverOwnedProcess(ctx context.Context, session nativeSession, identity nativeOwnedProcessIdentity) (string, error) {
	if err := p.session(session, ctx, true); err != nil {
		return "", err
	}
	if !darwinRecoveryProofValid(identity.Proof) {
		return "", errDarwinRecovery
	}
	saved, err := darwinRecoveryDecode(identity.Incarnation)
	if err != nil {
		return "", err
	}
	proof := identity.Proof
	c := p.recovery()
	meta, err := c.meta(proof.PID)
	if errors.Is(err, errDarwinProcessGone) {
		return "gone", nil
	}
	if err != nil {
		return "", errDarwinRecovery
	}
	if !darwinRecoverySameStart(meta, saved.Meta) {
		return "gone", nil
	}
	if meta.Group != uint64(proof.PID) || meta.Group != saved.Meta.Group || meta.UID != saved.Meta.UID || meta.RUID != saved.Meta.RUID || meta.UID != uint64(c.uid()) || (meta.Parent != saved.Meta.Parent && meta.Parent != 1 && meta.Parent != uint64(c.self())) {
		return "", errDarwinRecovery
	}
	port, token, err := c.task(proof.PID)
	if err != nil {
		if port != 0 {
			c.release(port)
		}
		return "", errDarwinRecovery
	}
	if port == 0 {
		return "", errDarwinRecovery
	}
	defer c.release(port)
	if token[5] != proof.PID || token[7] == 0 {
		return "", errDarwinRecovery
	}
	if token[7] != saved.Version {
		return "gone", nil
	}
	if !darwinRecoveryToken(token, proof.PID, saved.Version, meta) {
		return "", errDarwinRecovery
	}
	files, err := darwinRecoveryInspect(c, proof, meta)
	if err != nil || files != saved.Files {
		return "", errDarwinRecovery
	}
	final, err := c.audit(port)
	if err != nil || final != token {
		return "", errDarwinRecovery
	}
	if err = p.session(session, ctx, true); err != nil {
		return "", err
	}
	if err = c.terminate(port); err != nil {
		return "", errDarwinRecovery
	}
	waitCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for {
		actual, readErr := c.meta(proof.PID)
		if errors.Is(readErr, errDarwinProcessGone) || readErr == nil && !darwinRecoverySameStart(actual, saved.Meta) {
			return "stopped", nil
		}
		if readErr != nil {
			return "", errDarwinRecovery
		}
		if waitCtx.Err() != nil {
			return "", errors.New("macOS exact task termination is not yet confirmed")
		}
		if err = c.wait(waitCtx); err != nil {
			return "", errors.New("macOS exact task termination is not yet confirmed")
		}
	}
}
func darwinRecoveryReadMeta(pid uint32) (darwinRecoveryMeta, error) {
	var values [7]C.uint64_t
	status := C.ni_recovery_meta(C.uint(pid), &values[0])
	if status == 1 {
		return darwinRecoveryMeta{}, errDarwinProcessGone
	}
	if status != 0 {
		return darwinRecoveryMeta{}, errDarwinRecovery
	}
	return darwinRecoveryMeta{uint64(values[0]), uint64(values[1]), uint64(values[2]), uint64(values[3]), uint64(values[4]), uint64(values[5]), uint64(values[6])}, nil
}
func darwinRecoveryPath(pid uint32) (string, error) {
	buf := make([]byte, 4096)
	if C.ni_recovery_path(C.uint(pid), (*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf))) != 0 {
		return "", errDarwinRecovery
	}
	end := slices.Index(buf, byte(0))
	if end < 1 {
		return "", errDarwinRecovery
	}
	return string(buf[:end]), nil
}
func darwinRecoveryArgs(pid uint32) ([]string, error) {
	var size C.int
	ptr := C.ni_recovery_args(C.uint(pid), &size)
	if ptr == nil {
		return nil, errDarwinRecovery
	}
	defer C.free(unsafe.Pointer(ptr))
	raw := C.GoBytes(unsafe.Pointer(ptr), size)
	defer clear(raw)
	if len(raw) == 0 || raw[len(raw)-1] != 0 {
		return nil, errDarwinRecovery
	}
	return strings.Split(string(raw[:len(raw)-1]), "\x00"), nil
}
func darwinRecoveryTask(pid uint32) (uint32, [8]uint32, error) {
	var port C.uint
	var token [8]uint32
	if C.ni_recovery_task(C.uint(pid), &port, (*C.uint)(unsafe.Pointer(&token[0]))) != 0 {
		return 0, token, errDarwinRecovery
	}
	return uint32(port), token, nil
}
func darwinRecoveryAudit(port uint32) ([8]uint32, error) {
	var token [8]uint32
	if C.ni_recovery_audit(C.uint(port), (*C.uint)(unsafe.Pointer(&token[0]))) != 0 {
		return token, errDarwinRecovery
	}
	return token, nil
}
func darwinRecoveryTerminate(port uint32) error {
	if C.ni_recovery_terminate(C.uint(port)) != 0 {
		return errDarwinRecovery
	}
	return nil
}

// Walk through descriptors so symlink substitution cannot redirect the pinned image read.
func darwinRecoveryVerifyFiles(proof nativeOwnedProcessProof) (darwinRecoveryFiles, error) {
	var result darwinRecoveryFiles
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return result, err
	}
	defer func() { unix.Close(fd) }()
	parts := strings.Split(strings.TrimPrefix(proof.LaunchDirectory, "/"), "/")
	for i, part := range parts {
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return result, err
		}
		unix.Close(fd)
		fd = next
		var st unix.Stat_t
		if err = unix.Fstat(fd, &st); err != nil {
			return result, err
		}
		if st.Uid != 0 && st.Uid != uint32(os.Geteuid()) {
			return result, errDarwinRecovery
		}
		if st.Mode&0022 != 0 && !(st.Mode&unix.S_ISVTX != 0 && st.Uid == 0) {
			return result, errDarwinRecovery
		}
		if i == len(parts)-1 {
			if st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0700 {
				return result, errDarwinRecovery
			}
			result.DirectoryDevice = uint64(st.Dev)
			result.DirectoryInode = st.Ino
		}
	}
	binaryFD, err := unix.Openat(fd, "mihomo", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return result, err
	}
	file := os.NewFile(uintptr(binaryFD), proof.ExecutablePath)
	defer file.Close()
	var before unix.Stat_t
	if err = unix.Fstat(binaryFD, &before); err != nil {
		return result, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != uint32(os.Geteuid()) || before.Mode&0077 != 0 || before.Mode&0100 == 0 || before.Size <= 0 || before.Size > 256<<20 {
		return result, errDarwinRecovery
	}
	var config unix.Stat_t
	if err = unix.Fstatat(fd, "config.yaml", &config, unix.AT_SYMLINK_NOFOLLOW); err != nil || config.Mode&unix.S_IFMT != unix.S_IFREG || config.Uid != uint32(os.Geteuid()) || config.Mode&0777 != 0600 {
		return result, errDarwinRecovery
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, 256<<20+1))
	if err != nil || n != before.Size || hex.EncodeToString(hash.Sum(nil)) != proof.BinarySHA256 {
		return result, errDarwinRecovery
	}
	var after unix.Stat_t
	if err = unix.Fstat(binaryFD, &after); err != nil {
		return result, err
	}
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Uid != after.Uid || before.Gid != after.Gid || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return result, errDarwinRecovery
	}
	result.BinaryDevice = uint64(after.Dev)
	result.BinaryInode = after.Ino
	result.BinaryCTimeSec = uint64(after.Ctim.Sec)
	result.BinaryCTimeNS = uint64(after.Ctim.Nsec)
	// The path must still name the opened inode after hashing.
	var named unix.Stat_t
	if err = unix.Fstatat(fd, "mihomo", &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || named.Ino != after.Ino || named.Dev != after.Dev {
		return result, errDarwinRecovery
	}
	return result, nil
}

var _ nativeOwnedProcessRecovery = (*darwinNativePlatform)(nil)

func darwinRecoveryControllerSocket(pid uint32, server, client netip.AddrPort) ([4]uint64, error) {
	var result [4]uint64
	var cookie [4]C.uint64_t
	family := unix.AF_INET6
	if server.Addr().Is4() {
		family = unix.AF_INET
	}
	local, remote := server.Addr().AsSlice(), client.Addr().AsSlice()
	status := C.ni_recovery_controller(C.uint(pid), C.int(family), unsafe.Pointer(&local[0]), C.ushort(server.Port()), unsafe.Pointer(&remote[0]), C.ushort(client.Port()), &cookie[0])
	if status == 1 {
		return result, errDarwinControllerNotReady
	}
	if status != 0 {
		return result, errDarwinRecovery
	}
	for i := range result {
		result[i] = uint64(cookie[i])
	}
	return result, nil
}
func darwinRecoveryControllerDial(ctx context.Context, endpoint netip.AddrPort) (net.Conn, error) {
	network := "tcp6"
	if endpoint.Addr().Is4() {
		network = "tcp4"
	}
	return (&net.Dialer{}).DialContext(ctx, network, endpoint.String())
}
func darwinControllerEndpoint(addr net.Addr) (netip.AddrPort, error) {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}, errDarwinRecovery
	}
	endpoint := tcp.AddrPort()
	endpoint = netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port())
	if !endpoint.IsValid() || !endpoint.Addr().IsLoopback() || endpoint.Addr().Zone() != "" || endpoint.Port() == 0 {
		return netip.AddrPort{}, errDarwinRecovery
	}
	return endpoint, nil
}
func darwinControllerMeta(meta darwinRecoveryMeta, saved darwinRecoveryIdentity, pid uint32, c *darwinRecoveryCalls) bool {
	return darwinRecoverySameStart(meta, saved.Meta) && meta.Group == uint64(pid) && meta.Group == saved.Meta.Group && meta.UID == saved.Meta.UID && meta.RUID == saved.Meta.RUID && meta.UID == uint64(c.uid()) && (meta.Parent == saved.Meta.Parent || meta.Parent == 1 || meta.Parent == uint64(c.self()))
}
func darwinControllerGone(c *darwinRecoveryCalls, pid uint32, saved darwinRecoveryIdentity, port uint32) (bool, error) {
	meta, err := c.meta(pid)
	if errors.Is(err, errDarwinProcessGone) {
		return true, nil
	}
	if err != nil {
		return false, errDarwinRecovery
	}
	if !darwinRecoverySameStart(meta, saved.Meta) {
		return true, nil
	}
	if port != 0 {
		token, err := c.audit(port)
		if err != nil {
			return false, errDarwinRecovery
		}
		if token[5] != pid || token[7] == 0 {
			return false, errDarwinRecovery
		}
		if token[7] != saved.Version {
			return true, nil
		}
	}
	return false, nil
}

// Only the journal's old task may receive application bytes on this connection.
func (p *darwinNativePlatform) DialOwnedController(ctx context.Context, session nativeSession, record nativeOwnedProcessIdentity, endpoint netip.AddrPort) (net.Conn, bool, error) {
	if err := p.session(session, ctx, true); err != nil {
		return nil, false, err
	}
	if !darwinRecoveryProofValid(record.Proof) || !endpoint.IsValid() || !endpoint.Addr().IsLoopback() || endpoint.Addr().Is4In6() || endpoint.Addr().Zone() != "" || endpoint.Port() == 0 {
		return nil, false, errDarwinRecovery
	}
	saved, err := darwinRecoveryDecode(record.Incarnation)
	if err != nil {
		return nil, false, err
	}
	record.Proof.Arguments = slices.Clone(record.Proof.Arguments)
	c := p.recovery()
	if c.controllerSocket == nil || c.dialController == nil {
		return nil, false, errDarwinRecovery
	}
	meta, err := c.meta(record.Proof.PID)
	if errors.Is(err, errDarwinProcessGone) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, errDarwinRecovery
	}
	if !darwinRecoverySameStart(meta, saved.Meta) {
		return nil, true, nil
	}
	if !darwinControllerMeta(meta, saved, record.Proof.PID, c) {
		return nil, false, errDarwinRecovery
	}
	port, token, err := c.task(record.Proof.PID)
	if err != nil {
		if port != 0 {
			c.release(port)
		}
		return nil, false, errDarwinRecovery
	}
	if port == 0 {
		return nil, false, errDarwinRecovery
	}
	transferred := false
	defer func() {
		if !transferred {
			c.release(port)
		}
	}()
	if token[5] != record.Proof.PID || token[7] == 0 {
		return nil, false, errDarwinRecovery
	}
	if token[7] != saved.Version {
		return nil, true, nil
	}
	if !darwinRecoveryToken(token, record.Proof.PID, saved.Version, meta) {
		return nil, false, errDarwinRecovery
	}
	files, err := darwinRecoveryInspect(c, record.Proof, meta)
	if err != nil || files != saved.Files {
		return nil, false, errDarwinRecovery
	}
	currentToken, err := c.audit(port)
	if err != nil || currentToken != token {
		return nil, false, errDarwinRecovery
	}
	if err = p.session(session, ctx, true); err != nil {
		return nil, false, err
	}
	raw, err := c.dialController(ctx, endpoint)
	if err != nil {
		if raw != nil {
			raw.Close()
		}
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		gone, checkErr := darwinControllerGone(c, record.Proof.PID, saved, port)
		if gone {
			return nil, true, nil
		}
		return nil, false, errors.Join(err, checkErr)
	}
	if raw == nil {
		return nil, false, errDarwinRecovery
	}
	owned := &darwinOwnedControllerConn{raw: raw, platform: p, session: session, ctx: ctx, calls: c, port: port, token: token, record: record, saved: saved, server: endpoint}
	remote, remoteErr := darwinControllerEndpoint(raw.RemoteAddr())
	client, localErr := darwinControllerEndpoint(raw.LocalAddr())
	owned.client = client
	if remoteErr != nil || localErr != nil || remote != endpoint || client.Addr().Is4() != endpoint.Addr().Is4() {
		raw.Close()
		return nil, false, errDarwinRecovery
	}
	// A successful handshake may precede accept(), so only "not yet present"
	// is polled, with no application bytes and no socket replacement or redial.
	tupleCtx, cancelTuple := context.WithTimeout(ctx, time.Second)
	for attempt := 0; attempt < 16; attempt++ {
		owned.cookie, err = c.controllerSocket(record.Proof.PID, endpoint, client)
		if !errors.Is(err, errDarwinControllerNotReady) {
			break
		}
		gone, checkErr := darwinControllerGone(c, record.Proof.PID, saved, port)
		if gone {
			cancelTuple()
			raw.Close()
			return nil, true, nil
		}
		if checkErr != nil {
			err = checkErr
			break
		}
		if waitErr := c.wait(tupleCtx); waitErr != nil {
			err = waitErr
			break
		}
	}
	cancelTuple()
	if err == nil {
		err = owned.validate()
	}
	if err != nil {
		raw.Close()
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		gone, checkErr := darwinControllerGone(c, record.Proof.PID, saved, port)
		if gone {
			return nil, true, nil
		}
		return nil, false, errors.Join(err, checkErr)
	}
	// Register cancellation before publishing; Close owns the task right from now on.
	owned.portMu.Lock()
	owned.stop = context.AfterFunc(ctx, func() { owned.Close() })
	transferred = true
	owned.portMu.Unlock()
	if ctx.Err() != nil {
		owned.Close()
		return nil, false, ctx.Err()
	}
	return owned, false, nil
}

type darwinOwnedControllerConn struct {
	raw            net.Conn
	platform       *darwinNativePlatform
	session        nativeSession
	ctx            context.Context
	calls          *darwinRecoveryCalls
	port           uint32
	token          [8]uint32
	record         nativeOwnedProcessIdentity
	saved          darwinRecoveryIdentity
	server, client netip.AddrPort
	cookie         [4]uint64
	portMu         sync.Mutex
	writeMu        sync.Mutex
	closeOnce      sync.Once
	closed         atomic.Bool
	stop           func() bool
	closeErr       error
}

func (c *darwinOwnedControllerConn) validate() error {
	c.portMu.Lock()
	defer c.portMu.Unlock()
	if c.closed.Load() {
		return net.ErrClosed
	}
	if err := c.platform.session(c.session, c.ctx, true); err != nil {
		return err
	}
	token, err := c.calls.audit(c.port)
	if err != nil || token != c.token {
		return errDarwinRecovery
	}
	meta, err := c.calls.meta(c.record.Proof.PID)
	if err != nil || !darwinControllerMeta(meta, c.saved, c.record.Proof.PID, c.calls) {
		return errDarwinRecovery
	}
	files, err := darwinRecoveryInspect(c.calls, c.record.Proof, meta)
	if err != nil || files != c.saved.Files {
		return errDarwinRecovery
	}
	cookie, err := c.calls.controllerSocket(c.record.Proof.PID, c.server, c.client)
	if err != nil || cookie != c.cookie || cookie[1] == 0 || cookie[2] == 0 || cookie[3] == 0 {
		return errDarwinRecovery
	}
	token, err = c.calls.audit(c.port)
	if err != nil || token != c.token {
		return errDarwinRecovery
	}
	return c.platform.session(c.session, c.ctx, true)
}
func (c *darwinOwnedControllerConn) Write(data []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.validate(); err != nil {
		c.Close()
		return 0, err
	}
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	n, err := c.raw.Write(data)
	if err != nil {
		c.Close()
	}
	return n, err
}
func (c *darwinOwnedControllerConn) Read(data []byte) (int, error) {
	n, err := c.raw.Read(data)
	if err != nil {
		c.Close()
	}
	return n, err
}
func (c *darwinOwnedControllerConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.closeErr = c.raw.Close()
		c.portMu.Lock()
		defer c.portMu.Unlock()
		if c.stop != nil {
			c.stop()
		}
		c.calls.release(c.port)
	})
	return c.closeErr
}
func (c *darwinOwnedControllerConn) LocalAddr() net.Addr           { return c.raw.LocalAddr() }
func (c *darwinOwnedControllerConn) RemoteAddr() net.Addr          { return c.raw.RemoteAddr() }
func (c *darwinOwnedControllerConn) SetDeadline(t time.Time) error { return c.raw.SetDeadline(t) }
func (c *darwinOwnedControllerConn) SetReadDeadline(t time.Time) error {
	return c.raw.SetReadDeadline(t)
}
func (c *darwinOwnedControllerConn) SetWriteDeadline(t time.Time) error {
	return c.raw.SetWriteDeadline(t)
}
