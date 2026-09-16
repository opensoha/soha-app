//go:build darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/opensoha/soha-app/internal/endpointservice"
)

var serviceVersion string

func resolvedVersion() string {
	if serviceVersion != "" {
		return serviceVersion
	}
	return "0.2.0"
}
func main() {
	if err := runDarwin(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func runDarwin(args []string) error {
	if len(args) == 1 && args[0] == "version" {
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"name": "soha-app-service", "version": resolvedVersion()})
	}
	if len(args) > 1 || (len(args) == 1 && args[0] != "run") {
		return errors.New("usage: soha-app-service [run|version]")
	}
	if os.Geteuid() != 0 {
		return errors.New("run the macOS network service using its installed launch daemon")
	}
	path := filepath.Join(endpointservice.DarwinStateDirectory, "service.json")
	if err := validateDarwinPath(path); err != nil {
		return err
	}
	config, err := endpointservice.LoadConfig(path)
	if err != nil {
		return err
	}
	if config.AllowedUserUID == nil || config.AllowedUserSID != "" || config.StateDirectory != endpointservice.DarwinStateDirectory {
		return errors.New("macOS service requires an explicit user UID and the fixed protected state directory")
	}
	for _, path := range []string{config.ControlCAFile, config.ControlCertFile, config.ControlKeyFile, config.IngestCAFile, config.IngestCertFile, config.IngestKeyFile, config.MihomoControllerSecretFile} {
		if path != "" {
			if err := validateDarwinPath(path); err != nil {
				return err
			}
		}
	}
	if config.EnrollmentTokenFile != "" {
		if _, err := os.Lstat(config.EnrollmentTokenFile); err == nil {
			if err := validateDarwinPath(config.EnrollmentTokenFile); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	runtime, err := newEndpointRuntime(path, resolvedVersion(), slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	return runtime.Run(ctx)
}

// Resolve only Apple's /var alias; reject symlinks and writable parents below it.
func validateDarwinPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(filepath.Dir(path)) != endpointservice.DarwinStateDirectory {
		return errors.New("macOS service files must be in its protected state directory")
	}
	actual := "/private" + path
	for current := actual; current != "/"; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("unsafe macOS service path: %s", current)
		}
		if current == actual && !info.Mode().IsRegular() {
			return errors.New("macOS service file is not regular")
		}
	}
	return nil
}
func newPlatformSystem(endpointservice.Config) (*endpointservice.DarwinSystem, error) {
	return endpointservice.NewDarwinSystem()
}
