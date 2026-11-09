//go:build darwin && cgo

package endpointservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type darwinRecoveryFixture struct {
	platform                                  *darwinNativePlatform
	session                                   *darwinNativeSession
	proof                                     nativeOwnedProcessProof
	meta                                      darwinRecoveryMeta
	token                                     [8]uint32
	files                                     darwinRecoveryFiles
	terminated                                bool
	terminationCalls, releaseCalls, pathCalls int
}

func newDarwinRecoveryFixture(t *testing.T) *darwinRecoveryFixture {
	t.Helper()
	p, s := nativeDarwinFixture()
	dir := "/private/tmp/launch-native-fixture"
	proof := nativeOwnedProcessProof{PID: 314, ProcessEpoch: strings.Repeat("a", 32), BinarySHA256: strings.Repeat("b", 64), LaunchDirectory: dir, ExecutablePath: filepath.Join(dir, "mihomo")}
	proof.Arguments = []string{proof.ExecutablePath, "-d", dir, "-f", filepath.Join(dir, "config.yaml")}
	f := &darwinRecoveryFixture{platform: p, session: s, proof: proof, meta: darwinRecoveryMeta{StartSec: 1700000000, StartUsec: 12345, UID: 501, RUID: 501, Parent: 99, Group: 314}, token: [8]uint32{501, 501, 20, 501, 20, 314, 77, 9}, files: darwinRecoveryFiles{1, 2, 3, 4, 5, 6}}
	p.calls.recovery = &darwinRecoveryCalls{
		meta: func(uint32) (darwinRecoveryMeta, error) {
			if f.terminated {
				return darwinRecoveryMeta{}, errDarwinProcessGone
			}
			return f.meta, nil
		},
		path: func(uint32) (string, error) { f.pathCalls++; return proof.ExecutablePath, nil }, args: func(uint32) ([]string, error) { return slices.Clone(proof.Arguments), nil }, files: func(nativeOwnedProcessProof) (darwinRecoveryFiles, error) { return f.files, nil },
		task: func(uint32) (uint32, [8]uint32, error) { return 88, f.token, nil }, audit: func(port uint32) ([8]uint32, error) {
			if port != 88 {
				t.Fatal("unstable task port")
			}
			return f.token, nil
		}, terminate: func(port uint32) error {
			if port != 88 {
				t.Fatal("termination did not use stable task")
			}
			f.terminationCalls++
			f.terminated = true
			return nil
		}, release: func(port uint32) {
			if port != 88 {
				t.Fatal("wrong task released")
			}
			f.releaseCalls++
		}, self: func() uint32 { return 99 }, uid: func() uint32 { return 501 }, wait: func(context.Context) error { return context.DeadlineExceeded },
	}
	return f
}
func (f *darwinRecoveryFixture) capture(t *testing.T) nativeOwnedProcessIdentity {
	t.Helper()
	identity, err := f.platform.CaptureOwnedProcess(context.Background(), f.session, f.proof)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if len(identity.Incarnation) > 200 || f.terminationCalls != 0 {
		t.Fatal("capture changed process or unbounded identity")
	}
	return identity
}
func TestDarwinNativeRecoveryStableTask(t *testing.T) {
	f := newDarwinRecoveryFixture(t)
	identity := f.capture(t)
	decoded, err := darwinRecoveryDecode(identity.Incarnation)
	if err != nil || decoded.Meta.StartSec != f.meta.StartSec || decoded.Version != 9 {
		t.Fatal("OS start or PID-version not captured")
	}
	restore, _ := f.platform.AcquireRestoreSession(context.Background(), f.session.Owner())
	f.meta.Parent = 1
	state, err := f.platform.RecoverOwnedProcess(context.Background(), restore, identity)
	if err != nil || state != "stopped" || f.terminationCalls != 1 || f.releaseCalls != 2 {
		t.Fatalf("stable task recovery: %s %v", state, err)
	}
}
func TestDarwinNativeRecoveryGoneAndReusedPID(t *testing.T) {
	for _, kind := range []string{"gone", "start", "version"} {
		t.Run(kind, func(t *testing.T) {
			f := newDarwinRecoveryFixture(t)
			identity := f.capture(t)
			f.pathCalls = 0
			switch kind {
			case "gone":
				f.terminated = true
			case "start":
				f.meta.StartUsec++
			case "version":
				f.token[7]++
			}
			state, err := f.platform.RecoverOwnedProcess(context.Background(), f.session, identity)
			if err != nil || state != "gone" || f.terminationCalls != 0 || f.pathCalls != 0 {
				t.Fatalf("reused process touched: %s %v", state, err)
			}
		})
	}
}
func TestDarwinNativeRecoveryRefusals(t *testing.T) {
	for _, kind := range []string{"permission", "read", "image", "path", "argv", "parent", "audit", "session", "confirmation"} {
		t.Run(kind, func(t *testing.T) {
			f := newDarwinRecoveryFixture(t)
			identity := f.capture(t)
			c := f.platform.calls.recovery
			switch kind {
			case "permission":
				c.task = func(uint32) (uint32, [8]uint32, error) { return 0, [8]uint32{}, errors.New("denied") }
			case "read":
				c.meta = func(uint32) (darwinRecoveryMeta, error) { return darwinRecoveryMeta{}, errors.New("unreadable") }
			case "image":
				f.files.BinaryInode++
			case "path":
				c.path = func(uint32) (string, error) { return "/other/image", nil }
			case "argv":
				c.args = func(uint32) ([]string, error) { return []string{"mihomo", "-f", "/other/config"}, nil }
			case "parent":
				f.meta.Parent = 444
			case "audit":
				c.audit = func(uint32) ([8]uint32, error) { v := f.token; v[7]++; return v, nil }
			case "session":
				f.session.Close()
			case "confirmation":
				c.terminate = func(uint32) error { f.terminationCalls++; return nil }
			}
			state, err := f.platform.RecoverOwnedProcess(context.Background(), f.session, identity)
			if err == nil || state != "" {
				t.Fatalf("unsafe terminal result: %s %v", state, err)
			}
			if kind != "confirmation" && f.terminationCalls != 0 {
				t.Fatal("refusal terminated a task")
			}
		})
	}
}
func TestDarwinNativeCaptureRefusals(t *testing.T) {
	for _, kind := range []string{"parent", "group", "args", "image", "permission", "restore", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			f := newDarwinRecoveryFixture(t)
			ctx := context.Background()
			var session nativeSession = f.session
			switch kind {
			case "parent":
				f.meta.Parent = 444
			case "group":
				f.meta.Group = 99
			case "args":
				f.proof.Arguments = append(f.proof.Arguments, "--arbitrary")
			case "image":
				f.platform.calls.recovery.files = func(nativeOwnedProcessProof) (darwinRecoveryFiles, error) {
					return darwinRecoveryFiles{}, errors.New("hash mismatch")
				}
			case "permission":
				f.platform.calls.recovery.task = func(uint32) (uint32, [8]uint32, error) { return 0, [8]uint32{}, errors.New("denied") }
			case "restore":
				session, _ = f.platform.AcquireRestoreSession(ctx, f.session.Owner())
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := f.platform.CaptureOwnedProcess(ctx, session, f.proof); err == nil || f.terminationCalls != 0 {
				t.Fatal("invalid capture accepted")
			}
		})
	}
}
func TestDarwinNativeRecoveryPrivateImage(t *testing.T) {
	base, err := os.MkdirTemp("/private/tmp", "task122-recovery-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	dir := filepath.Join(base, "launch-fixture")
	if err = os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	image := []byte("non-executable fixture bytes")
	hash := sha256.Sum256(image)
	proof := nativeOwnedProcessProof{LaunchDirectory: dir, ExecutablePath: filepath.Join(dir, "mihomo"), BinarySHA256: hex.EncodeToString(hash[:])}
	if err = os.WriteFile(proof.ExecutablePath, image, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "config.yaml"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	original, err := darwinRecoveryVerifyFiles(proof)
	if err != nil || original.BinaryInode == 0 {
		t.Fatalf("private image: %v", err)
	}
	if err = os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err = darwinRecoveryVerifyFiles(proof); err == nil {
		t.Fatal("nonprivate launch accepted")
	}
	os.Chmod(dir, 0700)
	os.Remove(proof.ExecutablePath)
	if err = os.Symlink(filepath.Join(dir, "config.yaml"), proof.ExecutablePath); err != nil {
		t.Fatal(err)
	}
	if _, err = darwinRecoveryVerifyFiles(proof); err == nil {
		t.Fatal("image symlink accepted")
	}
}
func TestDarwinNativePeerEndpointSameReadback(t *testing.T) {
	f := newDarwinWGFixture(t)
	ctx := context.Background()
	original := f.system.expected.Peer.Endpoint
	pin := f.system.peerEndpoint
	got, err := f.system.NativePeerEndpoint(ctx, f.session)
	if err != nil || got != pin || f.system.expected.Peer.Endpoint != original {
		t.Fatalf("numeric peer/hostname ACK: %v", err)
	}
	c := f.prepare(t)
	f.system.nativeDNSDelegate = &darwinWGDNSEpoch{change: c, grant: f.system.expected.Readback(), owner: f.session.Owner()}
	f.current = []string{"127.0.0.1", "::1"}
	f.system.nativeDNSVerifyEndpoint = func(context.Context, string, netip.AddrPort) bool {
		t.Fatal("delegated peer performed fresh DNS")
		return false
	}
	got, err = f.system.NativePeerEndpoint(ctx, f.session)
	if err != nil || got != pin {
		t.Fatal(err)
	}
	f.system.nativeDNSReadback = func(context.Context) (TunnelReadback, error) { return TunnelReadback{}, errors.New("WG changed") }
	if _, err = f.system.NativePeerEndpoint(ctx, f.session); err == nil {
		t.Fatal("unknown peer accepted")
	}
	restore, _ := f.session.platform.AcquireRestoreSession(ctx, f.session.Owner())
	if _, err = f.system.NativePeerEndpoint(ctx, restore); err == nil {
		t.Fatal("restore session authorized new peer route")
	}
}
