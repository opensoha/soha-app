package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
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
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("config permissions = %o, want no group/world access", info.Mode().Perm())
	}
}

func TestLoadOrCreateDeviceIDPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device-id")
	first, err := loadOrCreateDeviceID(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateDeviceID(path)
	if err != nil {
		t.Fatal(err)
	}
	if first == "" || first != second {
		t.Fatalf("device ids = %q and %q", first, second)
	}
	if !strings.HasPrefix(first, "endpoint-") || !validDeviceID(first) {
		t.Fatalf("invalid device id %q", first)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("device id permissions = %o, want 600", info.Mode().Perm())
	}
	assertNoDeviceIDTemps(t, path)
}

func TestLoadOrCreateDeviceIDPreservesExistingFiles(t *testing.T) {
	for _, contents := range []string{"endpoint-existing\n", " endpoint-existing \n", "", "\n", "invalid/device-id\n"} {
		t.Run(fmt.Sprintf("contents=%q", contents), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "device-id")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			id, err := loadOrCreateDeviceID(path)
			want := strings.TrimSpace(contents)
			if validDeviceID(want) {
				if err != nil || id != want {
					t.Fatalf("existing id = %q, %v; want %q", id, err, want)
				}
			} else if err == nil || id != "" {
				t.Fatalf("corrupt identity accepted: %q, %v", id, err)
			}
			after, statErr := os.Stat(path)
			raw, readErr := os.ReadFile(path)
			if statErr != nil || readErr != nil || !os.SameFile(before, after) || string(raw) != contents {
				t.Fatalf("existing identity changed: %q, %v, %v", raw, statErr, readErr)
			}
			assertNoDeviceIDTemps(t, path)
		})
	}
}

func TestPublishFileDoesNotReplaceExisting(t *testing.T) {
	directory := t.TempDir()
	source, target := filepath.Join(directory, "candidate"), filepath.Join(directory, "device-id")
	for path, contents := range map[string]string{source: "endpoint-candidate\n", target: "endpoint-winner\n"} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := publishFile(source, target); !errors.Is(err, os.ErrExist) {
		t.Fatalf("publish to existing target = %v, want ErrExist", err)
	}
	for path, want := range map[string]string{source: "endpoint-candidate\n", target: "endpoint-winner\n"} {
		raw, err := os.ReadFile(path)
		if err != nil || string(raw) != want {
			t.Fatalf("publication changed %s: %q, %v", path, raw, err)
		}
	}
}

func TestLoadOrCreateDeviceIDDanglingSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires Windows privileges or Developer Mode")
	}
	directory := t.TempDir()
	path, target := filepath.Join(directory, "device-id"), filepath.Join(directory, "missing")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestDeviceIDProcessHelper$")
	command.Env = append(os.Environ(), "SOHA_APP_DEVICE_ID_TEST_PATH="+path, "SOHA_APP_DEVICE_ID_TEST_EXPECT_MISSING=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("dangling identity lookup did not return an error promptly: %v, %s", err, output)
	}
	if got, err := os.Readlink(path); err != nil || got != target {
		t.Fatalf("dangling symlink changed: %q, %v", got, err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing symlink target changed: %v", err)
	}
	assertNoDeviceIDTemps(t, path)
}

func TestLoadOrCreateDeviceIDConcurrentProcesses(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "nested", "device-id")
	const workers = 16
	commands := make([]*exec.Cmd, workers)
	outputs := make([]bytes.Buffer, workers)
	inputs := make([]io.WriteCloser, workers)
	for index := range workers {
		command := exec.Command(executable, "-test.run=^TestDeviceIDProcessHelper$")
		command.Env = append(os.Environ(), "SOHA_APP_DEVICE_ID_TEST_PATH="+path)
		command.Stdout, command.Stderr = &outputs[index], &outputs[index]
		input, err := command.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = input.Close()
			if command.Process != nil {
				_ = command.Process.Kill()
				_ = command.Wait()
			}
		})
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		commands[index], inputs[index] = command, input
	}
	for _, input := range inputs {
		_ = input.Close()
	}
	winner := ""
	for index, command := range commands {
		if err := command.Wait(); err != nil {
			t.Fatalf("device id process %d failed: %v, %s", index, err, &outputs[index])
		}
		id := outputs[index].String()
		if !validDeviceID(id) || winner != "" && id != winner {
			t.Fatalf("device ids diverged: winner %q, process %d returned %q", winner, index, id)
		}
		winner = id
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != winner+"\n" {
		t.Fatalf("stored device id = %q, %v; want %q", raw, err, winner)
	}
	assertNoDeviceIDTemps(t, path)
}

func TestDeviceIDProcessHelper(t *testing.T) {
	path := os.Getenv("SOHA_APP_DEVICE_ID_TEST_PATH")
	if path == "" {
		return
	}
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		t.Fatal(err)
	}
	id, err := loadOrCreateDeviceID(path)
	if os.Getenv("SOHA_APP_DEVICE_ID_TEST_EXPECT_MISSING") == "1" {
		if !errors.Is(err, os.ErrNotExist) || id != "" {
			t.Fatalf("missing device identity = %q, %v", id, err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	fmt.Print(id)
	os.Exit(0)
}

func assertNoDeviceIDTemps(t *testing.T, path string) {
	t.Helper()
	temps, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".device-id-*"))
	if err != nil || len(temps) != 0 {
		t.Fatalf("device id temporary files remain: %v, %v", temps, err)
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
