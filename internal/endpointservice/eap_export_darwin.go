//go:build darwin

package endpointservice

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type eapExportReceipt struct {
	Artifact EAPArtifact `json:"artifact"`
	Device   uint64      `json:"device"`
	Inode    uint64      `json:"inode"`
	Complete bool        `json:"complete"`
}

func (system *DarwinEAPSystem) exportReceiptPath(artifact EAPArtifact) string {
	return filepath.Join(system.directory, fmt.Sprintf(".eap-export-%x.json", sha256.Sum256([]byte(artifact.Path))))
}

func (system *DarwinEAPSystem) saveExportReceipt(receipt eapExportReceipt) error {
	if !filepath.IsAbs(system.directory) {
		return errors.New("EAP export receipt has no protected directory")
	}
	raw, err := json.Marshal(receipt)
	if err != nil || len(raw) > 4096 {
		return errors.New("EAP export receipt is invalid")
	}
	file, err := os.CreateTemp(system.directory, ".export-receipt-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(raw)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), system.exportReceiptPath(receipt.Artifact)); err != nil {
		return err
	}
	directory, err := os.Open(system.directory)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func (system *DarwinEAPSystem) loadExportReceipt(artifact EAPArtifact) (eapExportReceipt, error) {
	raw, err := readFileBounded(system.exportReceiptPath(artifact), 4096, true)
	if err != nil {
		return eapExportReceipt{}, err
	}
	var receipt eapExportReceipt
	if err := decodeStrict(raw, &receipt); err != nil || receipt.Artifact != artifact {
		return eapExportReceipt{}, errors.New("EAP export does not match its protected receipt")
	}
	return receipt, nil
}

func (system *DarwinEAPSystem) RecoverArtifacts(ctx context.Context, retained []EAPArtifact) error {
	entries, err := os.ReadDir(system.directory)
	if err != nil {
		return err
	}
	count := 0
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".eap-export-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		count++
		if count > 64 {
			return errors.New("EAP export recovery exceeds the safe limit")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, err := readFileBounded(filepath.Join(system.directory, entry.Name()), 4096, true)
		if err != nil {
			return err
		}
		var receipt eapExportReceipt
		if decodeStrict(raw, &receipt) != nil || filepath.Base(system.exportReceiptPath(receipt.Artifact)) != entry.Name() {
			return errors.New("EAP export recovery receipt is invalid")
		}
		if slices.Contains(retained, receipt.Artifact) {
			continue
		}
		if err := system.removeEAPArtifact(receipt.Artifact); err != nil {
			return err
		}
	}
	return nil
}
