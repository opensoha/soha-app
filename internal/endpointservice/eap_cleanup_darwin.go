//go:build darwin

package endpointservice

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func (system *DarwinEAPSystem) Cleanup(ctx context.Context, job EAPCleanup) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, artifact := range job.Artifacts {
		if err := system.removeEAPArtifact(artifact); err != nil {
			return err
		}
	}
	// Profile removal/update owns the installed Keychain payloads and trust anchors.
	if job.RequestID == "" {
		return nil
	}
	key, err := system.loadEAPKey(job.RequestID)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if key != nil && job.Certificate != nil {
		certificate, err := parseEAPCertificate(job.Certificate.CertificatePEM)
		if err != nil {
			return err
		}
		public, ok := certificate.PublicKey.(*ecdsa.PublicKey)
		if !ok || !key.PublicKey.Equal(public) {
			return errors.New("obsolete EAP certificate does not match its protected key")
		}
	}
	for _, path := range []string{system.eapKeyPath(job.RequestID), filepath.Join(system.directory, eapPayloadUUID(job.RequestID)+".csr")} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (system *DarwinEAPSystem) removeEAPArtifact(artifact EAPArtifact) error {
	relative, err := filepath.Rel(system.home, artifact.Path)
	parent := filepath.Join("Library", "Application Support", "Soha", "EAP")
	if err != nil || !filepath.IsLocal(relative) || filepath.Dir(relative) != parent || !strings.HasPrefix(filepath.Base(relative), "Soha-EAP-") || filepath.Ext(relative) != ".mobileconfig" || len(artifact.SHA256) != 64 {
		return errors.New("obsolete EAP export is outside the managed directory")
	}
	root, err := os.OpenRoot(system.home)
	if err != nil {
		return err
	}
	defer root.Close()
	receipt, err := system.loadExportReceipt(artifact)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if errors.Is(err, os.ErrNotExist) {
		if _, statErr := root.Lstat(relative); errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
		return errors.New("obsolete EAP export has no ownership receipt")
	}
	file, err := root.OpenFile(relative, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return os.Remove(system.exportReceiptPath(artifact))
	}
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return errors.New("obsolete EAP export has an invalid file type or size")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != system.uid && (receipt.Complete || owner.Uid != uint32(os.Geteuid())) || uint64(owner.Dev) != receipt.Device || owner.Ino != receipt.Inode || receipt.Inode == 0 {
		return errors.New("obsolete EAP export belongs to another user")
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, io.LimitReader(file, (1<<20)+1)); err != nil {
		return err
	}
	if receipt.Complete && fmt.Sprintf("%x", digest.Sum(nil)) != artifact.SHA256 {
		return errors.New("obsolete EAP export changed; preserve it for manual recovery")
	}
	current, err := root.Lstat(relative)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(info, current) {
		return errors.New("obsolete EAP export changed during cleanup")
	}
	if err := root.Remove(relative); err != nil {
		return err
	}
	return os.Remove(system.exportReceiptPath(artifact))
}
