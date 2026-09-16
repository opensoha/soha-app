//go:build darwin

package endpointservice

import (
	"errors"
	"os"
	"syscall"
)

// The launchd service stores secrets in its root-only state directory. Keys are
// never copied into the desktop user's preferences or exposed through IPC.
func protectSecret(payload []byte, _ string) ([]byte, error) {
	return append([]byte(nil), payload...), nil
}
func unprotectSecret(payload []byte, _ string) ([]byte, error) {
	return append([]byte(nil), payload...), nil
}

func secureStateDirectory(path string) error {
	entry, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := entry.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || !entry.IsDir() || entry.Mode()&os.ModeSymlink != 0 {
		return os.ErrPermission
	}
	return os.Chmod(path, 0o700)
}

func secureSecretFile(_ string, entry os.FileInfo) error {
	stat, ok := entry.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || entry.Mode().Perm()&0o077 != 0 {
		return errors.New("secret file must be owned by the service and inaccessible to other users")
	}
	return nil
}
