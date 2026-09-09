package endpointservice

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const privateKeyDescription = "OpenSoha endpoint WireGuard private key"

func LoadOrCreatePrivateKey(path string) (wgtypes.Key, error) {
	if !filepath.IsAbs(path) {
		return wgtypes.Key{}, errors.New("WireGuard private key path must be absolute")
	}
	if key, err := loadPrivateKey(path); err == nil {
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return wgtypes.Key{}, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return wgtypes.Key{}, fmt.Errorf("create endpoint state directory: %w", err)
	}
	if err := secureStateDirectory(filepath.Dir(path)); err != nil {
		return wgtypes.Key{}, fmt.Errorf("secure endpoint state directory: %w", err)
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("generate WireGuard private key: %w", err)
	}
	plain := []byte(key.String())
	protected, err := protectSecret(plain, privateKeyDescription)
	clear(plain)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("protect WireGuard private key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return loadPrivateKey(path)
	}
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("create WireGuard private key: %w", err)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(protected); err != nil {
		return wgtypes.Key{}, fmt.Errorf("write WireGuard private key: %w", err)
	}
	if err := file.Sync(); err != nil {
		return wgtypes.Key{}, fmt.Errorf("sync WireGuard private key: %w", err)
	}
	if err := file.Close(); err != nil {
		return wgtypes.Key{}, fmt.Errorf("close WireGuard private key: %w", err)
	}
	remove = false
	return key, nil
}

func loadPrivateKey(path string) (wgtypes.Key, error) {
	raw, err := readFileBounded(path, 4096, true)
	if err != nil {
		return wgtypes.Key{}, err
	}
	plain, err := unprotectSecret(raw, privateKeyDescription)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("unprotect WireGuard private key: %w", err)
	}
	defer clear(plain)
	key, err := wgtypes.ParseKey(strings.TrimSpace(string(plain)))
	if err != nil {
		return wgtypes.Key{}, errors.New("stored WireGuard private key is invalid")
	}
	return key, nil
}
