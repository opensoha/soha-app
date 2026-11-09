//go:build !windows

package endpointservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

func TestNativeInterceptionOwnerLockCloseOnExec(t *testing.T) {
	if path := os.Getenv("SOHA_NATIVE_TEST_LOCK_PATH"); path != "" {
		var wanted unix.Stat_t
		if err := unix.Stat(path, &wanted); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir("/dev/fd")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			fd, err := strconv.Atoi(entry.Name())
			if err != nil {
				continue
			}
			var actual unix.Stat_t
			if unix.Fstat(fd, &actual) == nil && actual.Dev == wanted.Dev && actual.Ino == wanted.Ino {
				t.Fatalf("native owner lock inherited through exec on fd %d", fd)
			}
		}
		return
	}
	path := filepath.Join(t.TempDir(), "owner.lock")
	release, err := lockMihomoProcess(path)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if second, err := lockMihomoProcess(path); err == nil {
		second()
		t.Fatal("live service lock was not exclusive")
	}
	command := exec.Command(os.Args[0], "-test.run=^TestNativeInterceptionOwnerLockCloseOnExec$", "-test.count=1")
	command.Env = append(os.Environ(), "SOHA_NATIVE_TEST_LOCK_PATH="+path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("exec inherited owner lock: %v %s", err, output)
	}
}

func TestNativeInterceptionOwnedProofUsesImmutableLaunchCopy(t *testing.T) {
	c, config := processFixture(t)
	if err := c.process.start(context.Background(), "rules: []\n", func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.MihomoProcess.Binary, []byte("operator source replaced"), 0700); err != nil {
		t.Fatal(err)
	}
	proof, err := c.nativeOwnedProof()
	if err != nil {
		t.Fatal(err)
	}
	if proof.ExecutablePath == config.MihomoProcess.Binary || proof.LaunchDirectory != filepath.Dir(proof.ExecutablePath) || len(proof.Arguments) != 5 || proof.Arguments[0] != proof.ExecutablePath {
		t.Fatal("recovery proof used operator source", proof)
	}
	raw, err := os.ReadFile(proof.ExecutablePath)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	if hex.EncodeToString(hash[:]) != proof.BinarySHA256 {
		t.Fatal("recovery proof hash did not identify actual launch copy")
	}
	if release, err := c.nativeRecoveryLock(proof); err == nil {
		release()
		t.Fatal("recovery raced an owned live process")
	}
	if err = c.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	release, err := c.nativeRecoveryLock(proof)
	if err != nil {
		t.Fatal(err)
	}
	release()
}
