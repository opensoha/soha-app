//go:build darwin

package endpointservice

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestDarwinEAPExportRecoveryRetainsCurrentAndRemovesOrphan(t *testing.T) {
	system := &DarwinEAPSystem{directory: t.TempDir(), home: t.TempDir(), uid: uint32(os.Getuid())}
	raw := []byte("dedicated EAP identity")
	export := func() EAPArtifact {
		t.Helper()
		path, err := system.exportEAPFile(raw)
		if err != nil {
			t.Fatal(err)
		}
		return EAPArtifact{Path: path, SHA256: fmt.Sprintf("%x", sha256.Sum256(raw))}
	}
	retained, orphan := export(), export()
	if err := system.RecoverArtifacts(context.Background(), []EAPArtifact{retained}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(retained.Path); err != nil {
		t.Fatal("current export was removed", err)
	}
	for _, path := range []string{orphan.Path, system.exportReceiptPath(orphan)} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("orphan export or its receipt survived recovery", err)
		}
	}
	if err := system.RecoverArtifacts(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestDarwinEAPExportRecoveryHandlesInterruptedWrite(t *testing.T) {
	system := &DarwinEAPSystem{directory: t.TempDir(), home: t.TempDir(), uid: uint32(os.Getuid())}
	raw := []byte("dedicated EAP identity")
	path, err := system.exportEAPFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	artifact := EAPArtifact{Path: path, SHA256: fmt.Sprintf("%x", sha256.Sum256(raw))}
	receipt, err := system.loadExportReceipt(artifact)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Complete = false
	if err := system.saveExportReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, 4); err != nil {
		t.Fatal(err)
	}
	missing := EAPArtifact{Path: filepath.Join(filepath.Dir(path), "Soha-EAP-not-created.mobileconfig"), SHA256: artifact.SHA256}
	if err := system.saveExportReceipt(eapExportReceipt{Artifact: missing}); err != nil {
		t.Fatal(err)
	}
	if err := system.RecoverArtifacts(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{path, system.exportReceiptPath(artifact), system.exportReceiptPath(missing)} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("interrupted export or receipt survived recovery", err)
		}
	}
}

func TestDarwinEAPExportRecoveryPreservesReplacement(t *testing.T) {
	system := &DarwinEAPSystem{directory: t.TempDir(), home: t.TempDir(), uid: uint32(os.Getuid())}
	raw := []byte("same bytes in another file")
	path, err := system.exportEAPFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the original inode alive so the replacement cannot reuse its identity.
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := system.RecoverArtifacts(context.Background(), nil); err == nil {
		t.Fatal("replacement was accepted as an owned export")
	}
	if result, err := os.ReadFile(path); err != nil || string(result) != string(raw) {
		t.Fatal("replacement was not preserved", err)
	}
}
