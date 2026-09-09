package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/opensoha/soha-app/internal/endpointservice"
	"github.com/wailsapp/wails/v3/pkg/updater"
)

func TestAppRuntimeReportsInfoAndRejectsUnconfiguredUpdates(t *testing.T) {
	runtimeAPI := &appRuntime{version: "0.2.0"}

	infoResponse := httptest.NewRecorder()
	runtimeAPI.ServeHTTP(infoResponse, httptest.NewRequest(http.MethodGet, "/app/v1/info", nil))
	if infoResponse.Code != http.StatusOK {
		t.Fatalf("unexpected info status: %d", infoResponse.Code)
	}
	var info appInfo
	if err := json.NewDecoder(infoResponse.Body).Decode(&info); err != nil {
		t.Fatal(err)
	}
	if info.Name != "Soha" || info.Version != "0.2.0" || info.UpdateSupported {
		t.Fatalf("unexpected info: %#v", info)
	}

	statusResponse := httptest.NewRecorder()
	runtimeAPI.ServeHTTP(statusResponse, httptest.NewRequest(http.MethodGet, "/app/v1/updates/status", nil))
	if statusResponse.Code != http.StatusOK {
		t.Fatalf("unexpected status endpoint response: %d", statusResponse.Code)
	}
	var status updateStatus
	if err := json.NewDecoder(statusResponse.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if status.Supported || status.InstallMode != "disabled" || status.State != string(updater.StateUnconfigured) || status.CurrentVersion != "0.2.0" {
		t.Fatalf("unexpected disabled update status: %#v", status)
	}

	updateResponse := httptest.NewRecorder()
	runtimeAPI.ServeHTTP(updateResponse, httptest.NewRequest(http.MethodPost, "/app/v1/updates/check", nil))
	if updateResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("unexpected update status: %d", updateResponse.Code)
	}
	var updateError struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(updateResponse.Body).Decode(&updateError); err != nil {
		t.Fatal(err)
	}
	if updateError.Error.Code != "updates_unavailable" || updateError.Error.Message == "" {
		t.Fatalf("unexpected update error: %#v", updateError)
	}

	installResponse := httptest.NewRecorder()
	runtimeAPI.ServeHTTP(installResponse, httptest.NewRequest(http.MethodPost, "/app/v1/updates/install", nil))
	if installResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("unexpected install status: %d", installResponse.Code)
	}
}

func TestAppRuntimeNetworkIPC(t *testing.T) {
	t.Parallel()
	var action string
	var input *endpointservice.ConnectInput
	runtimeAPI := &appRuntime{networkCall: func(_ context.Context, gotAction string, gotInput *endpointservice.ConnectInput) (endpointservice.Status, error) {
		action, input = gotAction, gotInput
		return endpointservice.Status{State: endpointservice.StateConnected, RuntimeID: "endpoint-1", DeviceID: "device-1", UptimeSeconds: 10}, nil
	}}

	response := httptest.NewRecorder()
	runtimeAPI.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/app/v1/network/connect", strings.NewReader(`{"siteId":"site-1","networkSpaceId":"space-1","gatewayId":"gateway-b","mode":"internal_ztna","resourceIds":["resource-db"],"accessGrantId":"grant-1","accessGrantToken":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)))
	if response.Code != http.StatusOK || action != "connect" || input == nil || input.SiteID != "site-1" || input.NetworkSpaceID != "space-1" || input.GatewayID != "gateway-b" || input.AccessGrantID != "grant-1" || input.AccessGrantToken != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" || strings.Contains(response.Body.String(), input.AccessGrantToken) {
		t.Fatalf("connect response=%d action=%q input=%#v", response.Code, action, input)
	}

	response = httptest.NewRecorder()
	runtimeAPI.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/app/v1/network/status", nil))
	if response.Code != http.StatusOK || action != "status" || input != nil {
		t.Fatalf("status response=%d action=%q input=%#v", response.Code, action, input)
	}
}

func TestAppRuntimeReportsNativeNetworkLink(t *testing.T) {
	t.Parallel()
	runtimeAPI := &appRuntime{networkLinkStatus: func() NetworkLinkStatus {
		return NetworkLinkStatus{Connected: true, Medium: "wifi", InterfaceName: "en0", IPAddress: "192.0.2.10", Gateway: "192.0.2.1", DNSServers: []string{"192.0.2.53"}}
	}}
	response := httptest.NewRecorder()
	runtimeAPI.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/app/v1/network/link", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"gateway":"192.0.2.1"`) {
		t.Fatalf("link response=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAppRuntimeDoesNotExposeNetworkIPCError(t *testing.T) {
	t.Parallel()
	runtimeAPI := &appRuntime{networkCall: func(context.Context, string, *endpointservice.ConnectInput) (endpointservice.Status, error) {
		return endpointservice.Status{}, errors.New("secret endpoint detail")
	}}
	response := httptest.NewRecorder()
	runtimeAPI.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/app/v1/network/status", nil))
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "secret endpoint detail") {
		t.Fatalf("response=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAppRuntimeMihomoSubscriptionIsWriteOnly(t *testing.T) {
	t.Parallel()
	const subscriptionURL = "https://subscriptions.example.test/private?token=secret"
	var action string
	var input *endpointservice.MihomoAppInput
	runtimeAPI := &appRuntime{networkMihomoCall: func(_ context.Context, gotAction string, gotInput *endpointservice.MihomoAppInput) (endpointservice.MihomoAppStatus, error) {
		action, input = gotAction, gotInput
		return endpointservice.MihomoAppStatus{Mode: "app_subscription", ProfileID: "mihomo-1", ProfileRevision: 1, Configured: true, SelectedProxy: "edge-a", Proxies: []string{"edge-a"}}, nil
	}}

	response := httptest.NewRecorder()
	runtimeAPI.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/app/v1/network/mihomo", strings.NewReader(`{"subscriptionUrl":"`+subscriptionURL+`"}`)))
	if response.Code != http.StatusOK || action != "mihomo_configure" || input == nil || input.SubscriptionURL != subscriptionURL || strings.Contains(response.Body.String(), subscriptionURL) || strings.Contains(response.Body.String(), "token=secret") {
		t.Fatalf("configure response=%d action=%q input=%#v body=%s", response.Code, action, input, response.Body.String())
	}

	response = httptest.NewRecorder()
	runtimeAPI.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/app/v1/network/mihomo/selection", strings.NewReader(`{"selectedProxy":"edge-b"}`)))
	if response.Code != http.StatusOK || action != "mihomo_select" || input == nil || input.SelectedProxy != "edge-b" {
		t.Fatalf("selection response=%d action=%q input=%#v", response.Code, action, input)
	}
}

type fakeUpdateEngine struct {
	state        updater.State
	release      *updater.Release
	checkErr     error
	installErr   error
	checkStarted chan struct{}
	checkRelease chan struct{}
	checkCalls   atomic.Int64
	installCalls atomic.Int64
}

func (engine *fakeUpdateEngine) State() updater.State { return engine.state }

func (engine *fakeUpdateEngine) Check(context.Context) (*updater.Release, error) {
	engine.checkCalls.Add(1)
	if engine.checkStarted != nil {
		select {
		case engine.checkStarted <- struct{}{}:
		default:
		}
	}
	if engine.checkRelease != nil {
		<-engine.checkRelease
	}
	if engine.checkErr != nil {
		engine.state = updater.StateError
		return nil, engine.checkErr
	}
	if engine.release == nil {
		engine.state = updater.StateUpToDate
	} else {
		engine.state = updater.StateAvailable
	}
	return engine.release, nil
}

func (engine *fakeUpdateEngine) CheckAndInstall(context.Context) error {
	engine.installCalls.Add(1)
	if engine.installErr != nil {
		engine.state = updater.StateError
		return engine.installErr
	}
	engine.state = updater.StateReady
	return nil
}

func TestAppRuntimeSeparatesCheckFromUserInstall(t *testing.T) {
	engine := &fakeUpdateEngine{
		state: updater.StateIdle,
		release: &updater.Release{
			Version: "0.2.1",
			Metadata: map[string]any{
				updateMetadataInstallMode:  "self",
				updateMetadataDownloadMode: "delta",
				updateMetadataReleaseURL:   "https://github.com/opensoha/soha-app/releases/tag/v0.2.1",
			},
		},
	}
	runtimeAPI := &appRuntime{version: "0.2.0", updater: engine}

	checkResponse := httptest.NewRecorder()
	runtimeAPI.ServeHTTP(checkResponse, httptest.NewRequest(http.MethodPost, "/app/v1/updates/check", nil))
	if checkResponse.Code != http.StatusOK {
		t.Fatalf("unexpected check status: %d: %s", checkResponse.Code, checkResponse.Body.String())
	}
	var status updateStatus
	if err := json.NewDecoder(checkResponse.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if engine.checkCalls.Load() != 1 || engine.installCalls.Load() != 0 {
		t.Fatalf("check/install calls: %d/%d", engine.checkCalls.Load(), engine.installCalls.Load())
	}
	if status.State != string(updater.StateAvailable) || status.AvailableVersion != "0.2.1" || status.DownloadMode != "delta" || status.InstallMode != "self" {
		t.Fatalf("unexpected available status: %#v", status)
	}

	installResponse := httptest.NewRecorder()
	runtimeAPI.ServeHTTP(installResponse, httptest.NewRequest(http.MethodPost, "/app/v1/updates/install", nil))
	if installResponse.Code != http.StatusOK {
		t.Fatalf("unexpected install status: %d: %s", installResponse.Code, installResponse.Body.String())
	}
	if engine.installCalls.Load() != 1 {
		t.Fatalf("expected one user-triggered install, got %d", engine.installCalls.Load())
	}
}

func TestAppRuntimeRejectsExternalInstall(t *testing.T) {
	engine := &fakeUpdateEngine{
		state: updater.StateAvailable,
		release: &updater.Release{Version: "0.2.1", Metadata: map[string]any{
			updateMetadataInstallMode:  "external",
			updateMetadataDownloadMode: "full",
		}},
	}
	runtimeAPI := &appRuntime{version: "0.2.0", updater: engine}
	checkResponse := httptest.NewRecorder()
	runtimeAPI.ServeHTTP(checkResponse, httptest.NewRequest(http.MethodPost, "/app/v1/updates/check", nil))

	installResponse := httptest.NewRecorder()
	runtimeAPI.ServeHTTP(installResponse, httptest.NewRequest(http.MethodPost, "/app/v1/updates/install", nil))
	if installResponse.Code != http.StatusConflict {
		t.Fatalf("unexpected external install status: %d", installResponse.Code)
	}
	if engine.installCalls.Load() != 0 {
		t.Fatal("external update must not start the Wails installer")
	}
}

func TestAppRuntimeRejectsDisabledInstall(t *testing.T) {
	engine := &fakeUpdateEngine{state: updater.StateAvailable}
	runtimeAPI := &appRuntime{
		version: "0.2.0",
		updater: engine,
		status:  updateStatus{Supported: true, InstallMode: "disabled", State: string(updater.StateAvailable)},
	}
	response := httptest.NewRecorder()
	runtimeAPI.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/app/v1/updates/install", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unexpected disabled install status: %d", response.Code)
	}
	if engine.installCalls.Load() != 0 {
		t.Fatal("disabled update must not start the Wails installer")
	}
}

func TestAppRuntimeDropsConcurrentChecks(t *testing.T) {
	engine := &fakeUpdateEngine{state: updater.StateIdle, checkStarted: make(chan struct{}, 1), checkRelease: make(chan struct{})}
	runtimeAPI := &appRuntime{version: "0.2.0", updater: engine}
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		runtimeAPI.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/app/v1/updates/check", nil))
	}()
	<-engine.checkStarted

	secondResponse := httptest.NewRecorder()
	runtimeAPI.ServeHTTP(secondResponse, httptest.NewRequest(http.MethodPost, "/app/v1/updates/check", nil))
	if secondResponse.Code != http.StatusOK {
		t.Fatalf("unexpected duplicate status: %d", secondResponse.Code)
	}
	if engine.checkCalls.Load() != 1 {
		t.Fatalf("duplicate check started a second operation: %d", engine.checkCalls.Load())
	}
	close(engine.checkRelease)
	<-firstDone
}

func TestAppRuntimeDoesNotExposeUpdaterErrors(t *testing.T) {
	engine := &fakeUpdateEngine{state: updater.StateIdle, checkErr: errors.New("secret URL https://token@example.invalid")}
	runtimeAPI := &appRuntime{version: "0.2.0", updater: engine}
	response := httptest.NewRecorder()
	runtimeAPI.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/app/v1/updates/check", nil))
	if response.Code != http.StatusBadGateway {
		t.Fatalf("unexpected error status: %d", response.Code)
	}
	if strings.Contains(response.Body.String(), "token@example") {
		t.Fatalf("runtime leaked updater error: %s", response.Body.String())
	}

	statusResponse := httptest.NewRecorder()
	runtimeAPI.ServeHTTP(statusResponse, httptest.NewRequest(http.MethodGet, "/app/v1/updates/status", nil))
	var status updateStatus
	if err := json.NewDecoder(statusResponse.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if status.ErrorCode != "update_check_failed" {
		t.Fatalf("unexpected sanitized error state: %#v", status)
	}
}
