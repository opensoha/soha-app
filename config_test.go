package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestNormalizeServerURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "loopback IPv4 HTTP", input: " http://127.0.0.1:8080/ ", want: "http://127.0.0.1:8080"},
		{name: "loopback IPv6 HTTP", input: "http://[::1]:8080", want: "http://[::1]:8080"},
		{name: "remote HTTPS", input: "https://soha.example.com", want: "https://soha.example.com"},
		{name: "remote IP HTTPS", input: "https://10.0.0.8:8443", want: "https://10.0.0.8:8443"},
		{name: "empty", input: "", wantErr: true},
		{name: "remote HTTP", input: "http://soha.example.com", wantErr: true},
		{name: "hostname loopback HTTP", input: "http://localhost:8080", wantErr: true},
		{name: "credentials", input: "https://user:password@soha.example.com", wantErr: true},
		{name: "path", input: "https://soha.example.com/base", wantErr: true},
		{name: "query", input: "https://soha.example.com?token=value", wantErr: true},
		{name: "fragment", input: "https://soha.example.com/#fragment", wantErr: true},
		{name: "wrong scheme", input: "ftp://soha.example.com", wantErr: true},
		{name: "invalid port", input: "https://soha.example.com:0", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := normalizeServerURL(test.input)
			if test.wantErr {
				if err == nil {
					t.Fatalf("normalizeServerURL(%q) succeeded, want error", test.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeServerURL(%q): %v", test.input, err)
			}
			if got != test.want {
				t.Fatalf("normalizeServerURL(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestConfigStoreSaveAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.json")
	store := newConfigStore(path)

	if err := store.Save("http://127.0.0.1:8080/", false); err != nil {
		t.Fatal(err)
	}
	if err := store.Save("https://soha.example.com", true); err != nil {
		t.Fatal(err)
	}
	config, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if config.ServerURL != "https://soha.example.com" || !config.CredentialsBlocked {
		t.Fatalf("loaded config = %#v", config)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("config permissions = %o, want no group/world access", info.Mode().Perm())
	}
}

func TestConfigStoreRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"serverUrl":"https://soha.example.com","token":"secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newConfigStore(path).Load(); err == nil {
		t.Fatal("expected config with unknown field to fail")
	}
}

func TestConfigStoreConcurrentSaveAndLoad(t *testing.T) {
	store := newConfigStore(filepath.Join(t.TempDir(), "config.json"))
	if err := store.Save(defaultServerURL, false); err != nil {
		t.Fatal(err)
	}

	const workers = 16
	errors := make(chan error, workers)
	var group sync.WaitGroup
	for index := range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := store.Save(fmt.Sprintf("https://soha-%d.example.com", index), index%2 == 0); err != nil {
				errors <- err
				return
			}
			config, err := store.Load()
			if err != nil {
				errors <- err
				return
			}
			if config.Version != configVersion || config.ServerURL == "" {
				errors <- fmt.Errorf("invalid concurrent config: %#v", config)
			}
		}()
	}
	group.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}
