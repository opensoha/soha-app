package main

import (
	"path/filepath"
	"testing"
)

func TestInitialServerConfigurationRestoresBlockedEnvironmentSession(t *testing.T) {
	store := newConfigStore(filepath.Join(t.TempDir(), "config.json"))
	if err := store.Save("https://soha.example.com", true); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOHA_SERVER_URL", "https://soha.example.com")
	serverURL, locked, source, blocked := initialServerConfiguration(store)
	if serverURL != "https://soha.example.com" || !locked || source != "environment" || !blocked {
		t.Fatalf("environment session state = %q, %v, %q, %v", serverURL, locked, source, blocked)
	}

	t.Setenv("SOHA_SERVER_URL", "https://other.example.com")
	_, _, _, blocked = initialServerConfiguration(store)
	if blocked {
		t.Fatal("blocked state from another server was reused")
	}
}
