//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/opensoha/soha-app/internal/endpointservice"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName        = "SohaNetworkService"
	serviceDisplayName = "Soha Network Service"
	serviceDescription = "Applies Soha endpoint WireGuard and optional mihomo proxy policy."
	defaultVersion     = "0.2.0"
)

var serviceVersion string

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	command := "run"
	if len(args) == 1 {
		command = args[0]
	}
	if len(args) > 1 {
		return usage()
	}
	var err error
	switch command {
	case "run":
		err = runService(false)
	case "debug":
		err = runService(true)
	case "install":
		err = installService()
	case "uninstall":
		err = uninstallService()
	case "start":
		err = startService()
	case "stop":
		err = stopService()
	case "version":
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"name": "soha-app-service", "version": resolvedVersion()})
		return 0
	default:
		return usage()
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func usage() int {
	_, _ = fmt.Fprintln(os.Stderr, "usage: soha-app-service [run|debug|install|uninstall|start|stop|version]")
	return 2
}

func runService(isDebug bool) error {
	configPath, err := serviceConfigPath()
	if err != nil {
		return err
	}
	if isDebug {
		return debug.Run(serviceName, &serviceHandler{configPath: configPath, logger: slog.New(slog.NewJSONHandler(os.Stdout, nil))})
	}
	log, err := eventlog.Open(serviceName)
	if err != nil {
		return fmt.Errorf("open Windows event log: %w", err)
	}
	defer log.Close()
	logger := slog.New(slog.NewTextHandler(eventLogWriter{log}, nil))
	return svc.Run(serviceName, &serviceHandler{configPath: configPath, logger: logger})
}

type eventLogWriter struct{ log *eventlog.Log }

func (writer eventLogWriter) Write(payload []byte) (int, error) {
	if err := writer.log.Info(1, string(payload)); err != nil {
		return 0, err
	}
	return len(payload), nil
}

type serviceHandler struct {
	configPath string
	logger     *slog.Logger
}

func (handler *serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	runtime, err := newEndpointRuntime(handler.configPath, resolvedVersion(), handler.logger)
	if err != nil {
		handler.logger.Error("endpoint service initialization failed", "event", "endpoint_service.initialization.failed", "error", err.Error())
		return false, 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	status := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	changes <- status
	for {
		select {
		case request, ok := <-requests:
			if !ok {
				cancel()
				err = <-done
				if err != nil {
					return false, 1
				}
				return false, 0
			}
			switch request.Cmd {
			case svc.Interrogate:
				changes <- status
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				err = <-done
				if err != nil {
					handler.logger.Error("endpoint service shutdown failed", "event", "endpoint_service.shutdown.failed", "error", err.Error())
					return false, 1
				}
				return false, 0
			}
		case err = <-done:
			cancel()
			if err != nil {
				handler.logger.Error("endpoint service runtime failed", "event", "endpoint_service.runtime.failed", "error", err.Error())
				return false, 1
			}
			return false, 0
		}
	}
}

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
	system, err := endpointservice.NewWindowsSystem(config.WireGuardExecutable, config.TunnelConfigPath())
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
	manager, err := endpointservice.NewManager(endpointservice.ManagerOptions{RuntimeID: config.RuntimeID, DeviceID: config.DeviceID, PollInterval: time.Minute, HeartbeatInterval: time.Minute, RenewBefore: 30 * time.Second, MaxClockSkew: 5 * time.Minute}, control, executor, telemetry, logger)
	if err != nil {
		return nil, err
	}
	listener, err := endpointservice.ListenIPC(config.AllowedUserSID)
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

func serviceConfigPath() (string, error) {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", fmt.Errorf("resolve ProgramData: %w", err)
	}
	return filepath.Join(programData, "OpenSoha", "Soha", "service.json"), nil
}

func installService() error {
	configPath, err := serviceConfigPath()
	if err != nil {
		return err
	}
	configured := true
	if _, err := os.Stat(configPath); errors.Is(err, os.ErrNotExist) {
		configured = false
	} else if err != nil {
		return fmt.Errorf("inspect service config before installation: %w", err)
	} else if _, err := endpointservice.LoadConfig(configPath); err != nil {
		return fmt.Errorf("validate service config before installation: %w", err)
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	startType := uint32(mgr.StartManual)
	if configured {
		startType = mgr.StartAutomatic
	}
	configuration := mgr.Config{DisplayName: serviceDisplayName, Description: serviceDescription, StartType: startType, ErrorControl: mgr.ErrorNormal, DelayedAutoStart: configured, SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED}
	service, err := manager.OpenService(serviceName)
	created := false
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		service, err = manager.CreateService(serviceName, executable, configuration)
		created = err == nil
	} else if err == nil {
		configuration.BinaryPathName = executable
		err = service.UpdateConfig(configuration)
	}
	if err != nil {
		return err
	}
	defer service.Close()
	if created {
		if err := eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
			_ = service.Delete()
			return err
		}
	}
	if !configured {
		return stopOpenedService(service)
	}
	if status, err := service.Query(); err == nil && status.State == svc.Running {
		return nil
	}
	if err := service.Start(); err != nil {
		return err
	}
	return waitServiceState(service, svc.Running, 30*time.Second)
}

func startService() error {
	manager, service, err := openService()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	defer service.Close()
	status, err := service.Query()
	if err != nil || status.State == svc.Running {
		return err
	}
	if err := service.Start(); err != nil {
		return err
	}
	return waitServiceState(service, svc.Running, 30*time.Second)
}

func stopService() error {
	manager, service, err := openService()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	defer service.Close()
	return stopOpenedService(service)
}

func uninstallService() error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer service.Close()
	if err := stopOpenedService(service); err != nil {
		return err
	}
	if err := service.Delete(); err != nil {
		return err
	}
	if err := eventlog.Remove(serviceName); err != nil {
		return err
	}
	return nil
}

func openService() (*mgr.Mgr, *mgr.Service, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return nil, nil, err
	}
	service, err := manager.OpenService(serviceName)
	if err != nil {
		_ = manager.Disconnect()
		return nil, nil, err
	}
	return manager, service, nil
}

func stopOpenedService(service *mgr.Service) error {
	status, err := service.Query()
	if err != nil || status.State == svc.Stopped {
		return err
	}
	if _, err := service.Control(svc.Stop); err != nil {
		return err
	}
	return waitServiceState(service, svc.Stopped, 30*time.Second)
}

func waitServiceState(service *mgr.Service, wanted svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State == wanted {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("Windows service did not reach state %d", wanted)
}

func resolvedVersion() string {
	if serviceVersion != "" {
		return serviceVersion
	}
	return defaultVersion
}

var _ io.Writer = eventLogWriter{}
