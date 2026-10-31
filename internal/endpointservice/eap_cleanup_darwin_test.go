//go:build darwin

package endpointservice

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"testing"
)

func TestDarwinEAPCleanupDeletesOnlyUnchangedOwnedExportsAndKeys(t *testing.T) {
	system := &DarwinEAPSystem{directory: t.TempDir(), home: t.TempDir(), uid: uint32(os.Getuid()), deviceID: "device-1"}
	raw := []byte("owned EAP export")
	path, err := system.exportEAPFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	artifact := EAPArtifact{Path: path, SHA256: fmt.Sprintf("%x", sha256.Sum256(raw))}
	if err := system.Cleanup(context.Background(), EAPCleanup{Artifacts: []EAPArtifact{artifact}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("owned export was not removed")
	}
	path, err = system.exportEAPFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	artifact.Path = path
	if err := os.WriteFile(path, []byte("user changed this file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := system.Cleanup(context.Background(), EAPCleanup{Artifacts: []EAPArtifact{artifact}}); err == nil {
		t.Fatal("changed export was removed")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("changed export was not preserved")
	}
	if _, err := system.CreateCSR(context.Background(), "request-1"); err != nil {
		t.Fatal(err)
	}
	if err := system.Cleanup(context.Background(), EAPCleanup{RequestID: "request-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(system.eapKeyPath("request-1")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("obsolete protected key was not removed")
	}
	if err := system.Cleanup(context.Background(), EAPCleanup{RequestID: "../escape"}); err == nil {
		t.Fatal("invalid cleanup key reference was accepted")
	}
}
