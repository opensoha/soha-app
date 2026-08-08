package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowPositionStoreRoundTrip(t *testing.T) {
	store := &windowPositionStore{path: filepath.Join(t.TempDir(), "nested", "position.json")}
	want := windowPosition{X: 144, Y: -20}
	if err := store.save(want); err != nil {
		t.Fatalf("save position: %v", err)
	}
	got, ok := store.load()
	if !ok || got != want {
		t.Fatalf("load position = %#v, %v; want %#v, true", got, ok, want)
	}
	info, err := os.Stat(store.path)
	if err != nil {
		t.Fatalf("stat position: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("position mode = %o; want 600", info.Mode().Perm())
	}
}

func TestWindowPositionStoreRejectsInvalidState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "position.json")
	if err := os.WriteFile(path, []byte(`{"x":100001,"y":0}`), 0o600); err != nil {
		t.Fatalf("write invalid state: %v", err)
	}
	store := &windowPositionStore{path: path}
	if _, ok := store.load(); ok {
		t.Fatal("invalid position was accepted")
	}
}
