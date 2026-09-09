//go:build !windows

package endpointservice

import (
	"errors"
	"os"
)

func protectSecret(payload []byte, _ string) ([]byte, error) {
	return append([]byte(nil), payload...), nil
}

func unprotectSecret(payload []byte, _ string) ([]byte, error) {
	return append([]byte(nil), payload...), nil
}

func secureStateDirectory(path string) error {
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	entry, err := os.Stat(path)
	if err != nil || !entry.IsDir() || entry.Mode().Perm()&0o077 != 0 {
		return os.ErrPermission
	}
	return nil
}

func secureSecretFile(_ string, entry os.FileInfo) error {
	if entry.Mode().Perm()&0o077 != 0 {
		return errors.New("secret file must not be group- or world-accessible")
	}
	return nil
}
