//go:build !windows

package endpointservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func processFixture(t *testing.T) (*MihomoController, Config) {
	t.Helper()
	directory := t.TempDir()
	binary := filepath.Join(directory, "fixture")
	raw := []byte("#!/bin/sh\ncase \"$1\" in\n-v) echo fixture-v1; exit 0;;\n-t) exit 0;;\nesac\nexec sleep 60\n")
	if err := os.WriteFile(binary, raw, 0700); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	config := Config{StateDirectory: directory, MihomoControllerURL: "http://127.0.0.1:12345", MihomoControllerSecretFile: filepath.Join(directory, "secret"), MihomoProcess: MihomoProcessConfig{Ownership: "soha_owned", Binary: binary, SHA256: hex.EncodeToString(hash[:]), Version: "fixture-v1"}}
	c, err := NewConfiguredMihomoController(config, strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c.process.authority = listener.Addr().String()
	_ = listener.Close()
	t.Cleanup(func() { _ = c.Disable(context.Background()) })
	return c, config
}

func TestOwnedMihomoLifecycle(t *testing.T) {
	c, _ := processFixture(t)
	p := c.process
	healthy := func(context.Context) error { return nil }
	if err := p.start(context.Background(), "rules: []\n", healthy); err != nil {
		t.Fatal(err)
	}
	first := c.ProcessStatus()
	if first.PID == 0 || first.ProcessEpoch == "" || first.State != "running" {
		t.Fatalf("missing identity: %#v", first)
	}
	other := &mihomoProcess{config: p.config, directory: p.directory, authority: p.authority}
	if err := other.start(context.Background(), "", healthy); err == nil {
		t.Fatal("second owner acquired running instance")
	}
	if err := p.stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if files, _ := filepath.Glob(filepath.Join(p.directory, "launch-*")); len(files) != 0 {
		t.Fatalf("launch secrets remain: %v", files)
	}
	if err := p.start(context.Background(), "", healthy); err != nil {
		t.Fatal(err)
	}
	second := c.ProcessStatus()
	if second.ProcessEpoch == first.ProcessEpoch {
		t.Fatal("epoch reused")
	}
	p.mu.Lock()
	cmd, done := p.cmd, p.done
	p.mu.Unlock()
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("crash was not reaped")
	}
	if state := c.ProcessStatus(); state.State != "exited" || state.PID != 0 {
		t.Fatalf("bad crash observation: %#v", state)
	}
	if err := p.start(context.Background(), "", healthy); err != nil {
		t.Fatalf("crash repair: %v", err)
	}
}

func TestOwnedMihomoRejectsUnsafeStart(t *testing.T) {
	for _, scenario := range []string{"hash", "version", "occupied", "check_failure", "health_timeout", "exits", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			c, _ := processFixture(t)
			p := c.process
			ctx := context.Background()
			health := func(context.Context) error { return nil }
			switch scenario {
			case "hash":
				p.config.SHA256 = strings.Repeat("0", 64)
			case "version":
				p.config.Version = "wrong"
			case "occupied":
				l, err := net.Listen("tcp", p.authority)
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
			case "check_failure":
				raw := []byte("#!/bin/sh\nif [ \"$1\" = -v ]; then echo fixture-v1; exit 0; fi\nexit 1\n")
				if err := os.WriteFile(p.config.Binary, raw, 0700); err != nil {
					t.Fatal(err)
				}
				hash := sha256.Sum256(raw)
				p.config.SHA256 = hex.EncodeToString(hash[:])
			case "health_timeout":
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 150*time.Millisecond)
				defer cancel()
				health = func(context.Context) error { return errors.New("unhealthy") }
			case "exits":
				raw := []byte("#!/bin/sh\nif [ \"$1\" = -v ]; then echo fixture-v1; fi\nexit 0\n")
				if err := os.WriteFile(p.config.Binary, raw, 0700); err != nil {
					t.Fatal(err)
				}
				hash := sha256.Sum256(raw)
				p.config.SHA256 = hex.EncodeToString(hash[:])
				health = func(context.Context) error { return errors.New("unhealthy") }
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err := p.start(ctx, "", health); err == nil {
				t.Fatal("unsafe launch accepted")
			}
			if s := c.ProcessStatus(); s.PID != 0 {
				t.Fatalf("child survived failure: %#v", s)
			}
			if files, _ := filepath.Glob(filepath.Join(p.directory, "launch-*")); len(files) != 0 {
				t.Fatalf("launch resources leaked: %v", files)
			}
		})
	}
}

func TestMihomoExplicitStopSurvivesPollAndReconstruction(t *testing.T) {
	c, config := processFixture(t)
	wg := &fakeConfigurationExecutor{outcome: ApplyOutcome{Status: "applied"}}
	e, err := NewCoordinatedExecutor(wg, c)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.SetMihomoProcessRunning(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if c.ProcessStatus().DesiredRunning {
		t.Fatal("stopped process reports running intent")
	}
	if err = c.process.start(context.Background(), "", func(context.Context) error { return nil }); err == nil {
		t.Fatal("poll revived stopped process")
	}
	recovered, err := NewConfiguredMihomoController(config, strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	if !recovered.process.stopped {
		t.Fatal("stop intention lost after reconstruction")
	}
	if err = e.SetMihomoProcessRunning(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if err = c.process.start(context.Background(), "", func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	before := c.ProcessStatus().ProcessEpoch
	if err := e.RestartMihomoProcess(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(context.Background(), nil); err != nil {
		t.Fatalf("disabled readback: %v", err)
	}
	if err := c.process.start(context.Background(), "", func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if c.ProcessStatus().ProcessEpoch == before {
		t.Fatal("restart reused epoch")
	}
	if wg.disableCalls != 0 {
		t.Fatal("process control modified WireGuard")
	}
}

func TestExternalMihomoProcessControlUnsupported(t *testing.T) {
	c, err := NewMihomoController("http://127.0.0.1:12345", strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	e, _ := NewCoordinatedExecutor(&fakeConfigurationExecutor{}, c)
	if err = e.SetMihomoProcessRunning(context.Background(), false); !errors.Is(err, ErrMihomoProcessUnsupported) {
		t.Fatalf("external stop: %v", err)
	}
	if s := c.ProcessStatus(); s.Ownership != "external" || s.State != "unsupported" || s.PID != 0 {
		t.Fatalf("misleading external status: %#v", s)
	}
}
