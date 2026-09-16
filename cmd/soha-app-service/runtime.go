//go:build windows || darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/opensoha/soha-app/internal/endpointservice"
	"log/slog"
	"net"
	"os"
	"time"
)

type endpointRuntime struct {
	manager  *endpointservice.Manager
	listener net.Listener
	logger   *slog.Logger
}

func newEndpointRuntime(configPath, version string, logger *slog.Logger) (*endpointRuntime, error) {
	config, err := endpointservice.LoadConfig(configPath)
	if err != nil {
		return nil, err
	}
	controlHTTP, devicePublicKey, err := config.ControlHTTPClient()
	if err != nil {
		return nil, err
	}
	privateKey, err := endpointservice.LoadOrCreatePrivateKey(config.PrivateKeyPath())
	if err != nil {
		return nil, err
	}
	var mihomo endpointservice.MihomoRuntime
	var capabilities []string
	if config.MihomoConfigured() {
		secret, err := config.MihomoControllerSecret()
		if err != nil {
			return nil, err
		}
		mihomo, err = endpointservice.NewMihomoController(config.MihomoControllerURL, secret)
		if err != nil {
			return nil, err
		}
		capabilities = []string{"mihomo"}
	}
	control, err := endpointservice.NewControlClient(config.ControlURL, config.RuntimeID, controlHTTP, 5*time.Minute, capabilities...)
	if err != nil {
		return nil, err
	}
	if err := ensureEnrollment(config, privateKey.PublicKey().String(), devicePublicKey, version, control); err != nil {
		return nil, err
	}
	system, err := newPlatformSystem(config)
	if err != nil {
		return nil, err
	}
	wireGuard, err := endpointservice.NewExecutor(privateKey, system)
	if err != nil {
		return nil, err
	}
	var executor endpointservice.ConfigurationExecutor = wireGuard
	if mihomo != nil {
		executor, err = endpointservice.NewCoordinatedExecutor(wireGuard, mihomo, config.MihomoAppStatePath())
		if err != nil {
			return nil, err
		}
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	err = executor.Disable(cleanupCtx)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("disable stale endpoint tunnel: %w", err)
	}
	var telemetry endpointservice.Telemetry
	if config.IngestURL != "" {
		ingestHTTP, err := config.IngestHTTPClient()
		if err != nil {
			return nil, err
		}
		if proxyMetrics, ok := mihomo.(endpointservice.ProxyMetricsSource); ok {
			telemetry, err = endpointservice.NewTelemetryClient(config.IngestURL, config.RuntimeID, ingestHTTP, proxyMetrics)
		} else {
			telemetry, err = endpointservice.NewTelemetryClient(config.IngestURL, config.RuntimeID, ingestHTTP)
		}
		if err != nil {
			return nil, err
		}
	}
	manager, err := endpointservice.NewManager(endpointservice.ManagerOptions{CheckVPNHealth: system.CheckVPNHealth, RuntimeID: config.RuntimeID, DeviceID: config.DeviceID, PollInterval: time.Minute, HeartbeatInterval: time.Minute, RenewBefore: 30 * time.Second, MaxClockSkew: 5 * time.Minute}, control, executor, telemetry, logger)
	if err != nil {
		return nil, err
	}
	listener, err := endpointservice.ListenIPC(config.IPCIdentity())
	if err != nil {
		return nil, err
	}
	return &endpointRuntime{manager: manager, listener: listener, logger: logger}, nil
}

func ensureEnrollment(config endpointservice.Config, wireGuardPublicKey, devicePublicKey, version string, control *endpointservice.ControlClient) error {
	if config.EnrollmentID == "" {
		return nil
	}
	completed, err := endpointservice.EnrollmentCompleted(config.EnrollmentMarkerPath(), config.EnrollmentID)
	if err != nil {
		return err
	}
	if !completed {
		enrollment, err := config.Enrollment(wireGuardPublicKey, devicePublicKey, version)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		_, err = control.Enroll(ctx, enrollment)
		cancel()
		if err != nil {
			return err
		}
		if err := endpointservice.RecordEnrollment(config.EnrollmentMarkerPath(), config.EnrollmentID); err != nil {
			return err
		}
	}
	if err := os.Remove(config.EnrollmentTokenFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove consumed endpoint enrollment token: %w", err)
	}
	return nil
}

func (runtime *endpointRuntime) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsChannel := make(chan error, 2)
	go func() { errorsChannel <- runtime.manager.Run(runCtx) }()
	go func() {
		errorsChannel <- endpointservice.ServeIPC(runCtx, runtime.listener, runtime.manager, runtime.logger)
	}()
	var result error
	received := 0
	select {
	case <-ctx.Done():
	case result = <-errorsChannel:
		received = 1
	}
	cancel()
	shutdown := time.NewTimer(15 * time.Second)
	defer shutdown.Stop()
	for ; received < 2; received++ {
		select {
		case err := <-errorsChannel:
			result = errors.Join(result, err)
		case <-shutdown.C:
			return errors.Join(result, errors.New("endpoint service shutdown timed out"))
		}
	}
	return result
}
