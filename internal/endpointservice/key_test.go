package endpointservice

import (
	"path/filepath"
	"testing"
)

func TestLoadOrCreatePrivateKeyIsStable(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "wireguard.key")
	first, err := LoadOrCreatePrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreatePrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first.PublicKey() == first {
		t.Fatal("private key was not persisted safely")
	}
}
