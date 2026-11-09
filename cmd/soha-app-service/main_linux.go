//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/opensoha/soha-app/internal/endpointservice"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

var serviceVersion string

func resolvedVersion() string {
	if serviceVersion != "" {
		return serviceVersion
	}
	return "0.2.0"
}
func main() {
	if err := runLinux(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func runLinux(args []string) error {
	if len(args) == 1 && args[0] == "version" {
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"name": "soha-app-service", "version": resolvedVersion()})
	}
	if len(args) > 1 || len(args) == 1 && args[0] != "run" {
		return errors.New("usage: soha-app-service [run|version]")
	}
	if os.Geteuid() != 0 {
		return errors.New("Linux network service requires its root service account")
	}
	path := filepath.Join(endpointservice.LinuxStateDirectory, "service.json")
	if err := endpointservice.ValidateLinuxServiceFile(path); err != nil {
		return err
	}
	c, err := endpointservice.LoadConfig(path)
	if err != nil {
		return err
	}
	if c.AllowedUserUID == nil || *c.AllowedUserUID == 0 || c.AllowedUserSID != "" || c.StateDirectory != endpointservice.LinuxStateDirectory || c.MihomoConfigured() {
		return errors.New("Linux admission requires the protected state directory and an explicit desktop UID")
	}
	for _, p := range []string{c.ControlCAFile, c.ControlCertFile, c.ControlKeyFile, c.IngestCAFile, c.IngestCertFile, c.IngestKeyFile} {
		if p != "" {
			if err := endpointservice.ValidateLinuxServiceFile(p); err != nil {
				return err
			}
		}
	}
	if c.EnrollmentTokenFile != "" {
		if _, err := os.Lstat(c.EnrollmentTokenFile); err == nil {
			if err := endpointservice.ValidateLinuxServiceFile(c.EnrollmentTokenFile); err != nil {
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
func newPlatformSystem(endpointservice.Config) (*endpointservice.LinuxAdmissionSystem, error) {
	return &endpointservice.LinuxAdmissionSystem{}, nil
}
