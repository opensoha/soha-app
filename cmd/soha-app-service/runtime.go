//go:build windows || darwin || linux

package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/opensoha/soha-app/internal/endpointservice"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"
)

type endpointRuntime struct {
	manager  *endpointservice.Manager
	listener net.Listener
	logger   *slog.Logger
	native   *endpointservice.CoordinatedExecutor
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
	uiPresence, err := endpointservice.NewUIProcessPresence(config)
	if err != nil {
		return nil, err
	}
	privateKey, err := endpointservice.LoadOrCreatePrivateKey(config.PrivateKeyPath())
	if err != nil {
		return nil, err
	}
	var mihomo endpointservice.MihomoRuntime
	var capabilities []string
	if endpointservice.NativeChannelsSupported() {
		capabilities = append(capabilities, "windows-channel-controls-v1")
	}
	if config.MihomoConfigured() {
		secret, err := config.MihomoControllerSecret()
		if err != nil {
			return nil, err
		}
		mihomo, err = endpointservice.NewConfiguredMihomoController(config, secret)
		if err != nil {
			return nil, err
		}
		capabilities = append(capabilities, "mihomo", "mihomo-policy-v1", "mihomo-dns-pin-v1")
	}
	var eapSystem endpointservice.EAPSystem
	if endpointservice.NativeEAPSupported() {
		eapSystem, err = endpointservice.NewNativeEAPSystem(config)
		if err != nil {
			return nil, err
		}
		capabilities = append(capabilities, "eap-profile-v1", "eap-certificate-lifecycle-v1")
		tlsSupported := true
		capabilityCtx, cancelCapability := context.WithTimeout(context.Background(), 3*time.Second)
		if tlsSystem, ok := eapSystem.(interface {
			TLSSupport(context.Context, endpointservice.AdmissionProfile) (bool, string)
		}); ok {
			tlsSupported, _ = tlsSystem.TLSSupport(capabilityCtx, endpointservice.AdmissionProfile{WifiSecurity: "wpa2-enterprise"})
		}
		if tlsSupported {
			capabilities = append(capabilities, "radius-eap-tls-v1")
		}
		defer cancelCapability()
		if passwordSystem, ok := eapSystem.(endpointservice.EAPPasswordSystem); ok {
			if supported, _ := passwordSystem.PasswordSupport(capabilityCtx, endpointservice.AdmissionProfile{EAPMethod: "ttls", InnerMethod: "pap", WifiSecurity: "wpa2-enterprise"}); supported {
				capabilities = append(capabilities, "radius-eap-ttls-pap-v1")
			}
		}
	}
	if uiPresence != nil {
		capabilities = append(capabilities, "endpoint-ui-presence-v1")
	}
	control, err := endpointservice.NewControlClient(config.ControlURL, config.RuntimeID, controlHTTP, 5*time.Minute, capabilities...)
	if err != nil {
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
	var native *endpointservice.CoordinatedExecutor
	if mihomo != nil {
		native, err = endpointservice.NewCoordinatedExecutor(wireGuard, mihomo, config.MihomoAppStatePath())
		executor = native
		if err != nil {
			return nil, err
		}
	}
	if native != nil {
		if err = native.ConfigureNativeInterception(config, uiPresence, controlHTTP); err != nil {
			logger.Warn("native recovery pending", "event", "endpoint_native.recovery.pending")
		}
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	err = executor.Disable(cleanupCtx)
	cancel()
	if err != nil {
		if native == nil || !native.LocalProxyInterception().CleanupPending {
			return nil, fmt.Errorf("disable stale endpoint tunnel: %w", err)
		}
		// Keep IPC available to report/retry precise native recovery. The old VPN
		// must still be disabled before any fresh authorization can be accepted.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		wgErr := wireGuard.Disable(cleanupCtx)
		cancel()
		if wgErr != nil {
			return nil, wgErr
		}
	}
	if native == nil || !native.LocalProxyInterception().CleanupPending {
		if err := ensureEnrollment(config, privateKey.PublicKey().String(), devicePublicKey, version, control); err != nil {
			return nil, err
		}
	}

	var telemetry endpointservice.Telemetry
	if config.IngestURL != "" {
		ingestHTTP, err := config.IngestHTTPClient()
		if err != nil {
			return nil, err
		}
		if native != nil {
			if err = native.AttachNativeHTTPClient(ingestHTTP); err != nil {
				return nil, err
			}
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
	var admission *endpointservice.AdmissionManager
	if eapSystem != nil {
		admission, err = endpointservice.NewAdmissionManager(config.StateDirectory, config.DeviceID, control, eapSystem)
		if err != nil {
			return nil, err
		}
	}
	var channels *endpointservice.ChannelManager
	if endpointservice.NativeChannelsSupported() {
		native, err := endpointservice.NewNativeChannelSystem(config)
		if err != nil {
			return nil, err
		}
		channels, err = endpointservice.NewChannelManager(config, control, native)
		if err != nil {
			return nil, err
		}
	}
	manager, err := endpointservice.NewManager(endpointservice.ManagerOptions{Channels: channels, ControlURL: config.ControlURL, ConfigurationStatePath: filepath.Join(config.StateDirectory, "configuration-floor.json"), Admission: admission, UIPresence: uiPresence, CheckVPNHealth: system.CheckVPNHealth, RuntimeID: config.RuntimeID, DeviceID: config.DeviceID, PollInterval: time.Minute, HeartbeatInterval: time.Minute, RenewBefore: 30 * time.Second, MaxClockSkew: 5 * time.Minute}, control, executor, telemetry, logger)
	if err != nil {
		return nil, err
	}
	listener, err := endpointservice.ListenIPC(config.IPCIdentity())
	if err != nil {
		return nil, err
	}
	return &endpointRuntime{manager: manager, listener: listener, logger: logger, native: native}, nil
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
	if runtime.native != nil {
		go runtime.native.RunInterceptionMonitor(runCtx)
	}
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
