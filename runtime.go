package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	api "github.com/opensoha/soha-contracts/gen/go/sohaapi"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/opensoha/soha-app/internal/endpointservice"
	"github.com/wailsapp/wails/v3/pkg/updater"
)

var (
	appUpdateMode      = "disabled"
	appUpdatePublicKey = ""
)

type appInfo struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	Platform        string `json:"platform"`
	Arch            string `json:"arch"`
	UpdateSupported bool   `json:"updateSupported"`
	UpdateState     string `json:"updateState,omitempty"`
}

type updateStatus struct {
	Supported        bool   `json:"supported"`
	InstallMode      string `json:"installMode"`
	State            string `json:"state"`
	CurrentVersion   string `json:"currentVersion"`
	AvailableVersion string `json:"availableVersion,omitempty"`
	DownloadMode     string `json:"downloadMode,omitempty"`
	LastCheckedAt    string `json:"lastCheckedAt,omitempty"`
	ReleaseURL       string `json:"releaseURL,omitempty"`
	ErrorCode        string `json:"errorCode,omitempty"`
}

type updateEngine interface {
	State() updater.State
	Check(context.Context) (*updater.Release, error)
	CheckAndInstall(context.Context) error
}

type appRuntime struct {
	nativeScopeMu           sync.Mutex
	nativeScope             endpointservice.NativeUIScope
	nativeScopeKnown        bool
	nativeRetiredScopes     map[string]bool
	nativeKnownInterception bool
	networkUIScopeCall      func(context.Context, endpointservice.NativeUIScope) (endpointservice.InterceptionStatus, error)

	networkInterceptionCall func(context.Context, *endpointservice.InterceptionIntent) (endpointservice.InterceptionStatus, error)
	networkProxyCall        func(context.Context, string, *endpointservice.ProxyAction, *api.NetworkProxyRulesInput) (endpointservice.ProxyWorkbench, error)
	networkDisabled         bool
	version                 string
	updater                 updateEngine
	software                *softwareLibrary
	networkCall             func(context.Context, string, *endpointservice.ConnectInput) (endpointservice.Status, error)
	networkMihomoCall       func(context.Context, string, *endpointservice.MihomoAppInput) (endpointservice.MihomoAppStatus, error)
	networkAdmissionCall    func(context.Context, string, *endpointservice.AdmissionInput) (endpointservice.AdmissionStatus, error)
	openAdmissionProfile    func(context.Context, string) error
	networkLinkStatus       func() NetworkLinkStatus
	checkMu                 sync.Mutex
	statusMu                sync.RWMutex
	status                  updateStatus
}

var (
	errExternalUpdate = errors.New("update must be installed externally")
	errUpdateDisabled = errors.New("updates are disabled")
)

func (runtimeAPI *appRuntime) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	if runtimeAPI.networkDisabled && strings.HasPrefix(request.URL.Path, "/app/v1/network/") {
		writeError(writer, http.StatusServiceUnavailable, "network_control_disabled", "当前 App 实例已禁用本机网络控制")
		return
	}
	if runtimeAPI.software != nil && runtimeAPI.software.ServeHTTP(writer, request) {
		return
	}
	switch {
	case (request.Method == http.MethodGet || request.Method == http.MethodPost) && request.URL.Path == "/app/v1/network/proxy/interception":
		runtimeAPI.handleInterception(writer, request)
	case request.Method == http.MethodGet && request.URL.Path == "/app/v1/info":
		status := runtimeAPI.currentUpdateStatus()
		writeRuntimeJSON(writer, http.StatusOK, appInfo{
			Name:            "Soha",
			Version:         runtimeAPI.version,
			Platform:        runtime.GOOS,
			Arch:            runtime.GOARCH,
			UpdateSupported: status.Supported,
			UpdateState:     status.State,
		})
	case request.Method == http.MethodGet && request.URL.Path == "/app/v1/updates/status":
		writeRuntimeJSON(writer, http.StatusOK, runtimeAPI.currentUpdateStatus())
	case request.Method == http.MethodPost && request.URL.Path == "/app/v1/updates/check":
		if runtimeAPI.updater == nil {
			writeError(writer, http.StatusServiceUnavailable, "updates_unavailable", "当前构建未配置更新源")
			return
		}
		status, err := runtimeAPI.check(request.Context())
		if err != nil {
			writeError(writer, http.StatusBadGateway, "update_check_failed", "暂时无法检查更新，请稍后重试")
			return
		}
		writeRuntimeJSON(writer, http.StatusOK, status)
	case request.Method == http.MethodPost && request.URL.Path == "/app/v1/updates/install":
		if runtimeAPI.updater == nil {
			writeError(writer, http.StatusServiceUnavailable, "updates_unavailable", "当前构建未配置更新源")
			return
		}
		status, err := runtimeAPI.install(request.Context())
		switch {
		case errors.Is(err, errExternalUpdate):
			writeError(writer, http.StatusConflict, "update_external_only", "当前平台需要从发布页更新")
		case errors.Is(err, errUpdateDisabled):
			writeError(writer, http.StatusServiceUnavailable, "updates_unavailable", "当前构建未配置更新源")
		case err != nil:
			writeError(writer, http.StatusBadGateway, "update_install_failed", "更新失败，请稍后重试")
		default:
			writeRuntimeJSON(writer, http.StatusOK, status)
		}
	case request.Method == http.MethodGet && request.URL.Path == "/app/v1/network/status":
		runtimeAPI.handleNetwork(writer, request, "status")
	case request.Method == http.MethodGet && request.URL.Path == "/app/v1/network/link":
		if runtimeAPI.networkLinkStatus == nil {
			writeError(writer, http.StatusServiceUnavailable, "network_link_unavailable", "当前系统网络状态不可用")
			return
		}
		writeRuntimeJSON(writer, http.StatusOK, runtimeAPI.networkLinkStatus())
	case request.Method == http.MethodPost && request.URL.Path == "/app/v1/network/connect":
		runtimeAPI.handleNetwork(writer, request, "connect")
	case request.Method == http.MethodPost && request.URL.Path == "/app/v1/network/disconnect":
		runtimeAPI.handleNetwork(writer, request, "disconnect")
	case request.Method == http.MethodGet && request.URL.Path == "/app/v1/network/proxy":
		runtimeAPI.handleProxy(writer, request, "proxy_status")
	case request.Method == http.MethodPost && request.URL.Path == "/app/v1/network/proxy/actions":
		runtimeAPI.handleProxy(writer, request, "proxy_action")
	case request.Method == http.MethodPut && request.URL.Path == "/app/v1/network/proxy/rules":
		runtimeAPI.handleProxy(writer, request, "proxy_rules")
	case request.Method == http.MethodGet && request.URL.Path == "/app/v1/network/mihomo":
		runtimeAPI.handleNetworkMihomo(writer, request, "mihomo_status")
	case request.Method == http.MethodPut && request.URL.Path == "/app/v1/network/mihomo":
		runtimeAPI.handleNetworkMihomo(writer, request, "mihomo_configure")
	case request.Method == http.MethodDelete && request.URL.Path == "/app/v1/network/mihomo":
		runtimeAPI.handleNetworkMihomo(writer, request, "mihomo_clear")
	case request.Method == http.MethodPut && request.URL.Path == "/app/v1/network/mihomo/selection":
		runtimeAPI.handleNetworkMihomo(writer, request, "mihomo_select")
	case request.Method == http.MethodPost && request.URL.Path == "/app/v1/network/mihomo/refresh":
		runtimeAPI.handleNetworkMihomo(writer, request, "mihomo_refresh")
	case request.Method == http.MethodGet && request.URL.Path == "/app/v1/network/admission":
		runtimeAPI.handleAdmission(writer, request, "admission_status")
	case request.Method == http.MethodPost && request.URL.Path == "/app/v1/network/admission/prepare":
		runtimeAPI.handleAdmission(writer, request, "admission_prepare")
	case request.Method == http.MethodPost && request.URL.Path == "/app/v1/network/admission/check":
		runtimeAPI.handleAdmission(writer, request, "admission_check")
	case request.Method == http.MethodPost && request.URL.Path == "/app/v1/network/admission/connect":
		runtimeAPI.handleAdmission(writer, request, "admission_connect")
	case request.Method == http.MethodPost && request.URL.Path == "/app/v1/network/admission/open":
		runtimeAPI.handleAdmission(writer, request, "admission_open")
	case request.Method == http.MethodDelete && request.URL.Path == "/app/v1/network/admission":
		runtimeAPI.handleAdmission(writer, request, "admission_remove")
	default:
		writeError(writer, http.StatusNotFound, "runtime_not_found", "Runtime endpoint was not found")
	}
}

func (runtimeAPI *appRuntime) handleNetworkMihomo(writer http.ResponseWriter, request *http.Request, action string) {
	if runtimeAPI.networkMihomoCall == nil {
		writeError(writer, http.StatusServiceUnavailable, "network_service_unavailable", "Soha 网络服务不可用")
		return
	}
	var input *endpointservice.MihomoAppInput
	if action == "mihomo_configure" || action == "mihomo_select" {
		input = &endpointservice.MihomoAppInput{}
		if err := decodeRequestJSON(request, input); err != nil {
			writeError(writer, http.StatusBadRequest, "invalid_mihomo_request", "mihomo 参数无效")
			return
		}
	}
	ctx, cancel := context.WithTimeout(request.Context(), 50*time.Second)
	defer cancel()
	status, err := runtimeAPI.networkMihomoCall(ctx, action, input)
	if err != nil {
		appLog.Warn("endpoint mihomo request failed", "component", "network", "event", "app.network.mihomo.failed", "action", action, "error_type", logErrorType(err))
		httpStatus := http.StatusConflict
		if action == "mihomo_status" || errors.Is(err, endpointservice.ErrIPCUnsupported) {
			httpStatus = http.StatusServiceUnavailable
		}
		writeError(writer, httpStatus, "mihomo_operation_failed", "mihomo 操作未完成，请检查 Soha 网络服务")
		return
	}
	writeRuntimeJSON(writer, http.StatusOK, status)
}

func (runtimeAPI *appRuntime) handleNetwork(writer http.ResponseWriter, request *http.Request, action string) {
	if runtimeAPI.networkCall == nil {
		writeError(writer, http.StatusServiceUnavailable, "network_service_unavailable", "Soha 网络服务不可用")
		return
	}
	var input *endpointservice.ConnectInput
	switch action {
	case "connect":
		input = &endpointservice.ConnectInput{}
		if err := decodeRequestJSON(request, input); err != nil {
			writeError(writer, http.StatusBadRequest, "invalid_network_request", "网络连接参数无效")
			return
		}
	case "disconnect":
		if err := decodeRequestJSON(request, &struct{}{}); err != nil {
			writeError(writer, http.StatusBadRequest, "invalid_network_request", "网络断开参数无效")
			return
		}
	}
	ctx, cancel := context.WithTimeout(request.Context(), 130*time.Second)
	defer cancel()
	status, err := runtimeAPI.networkCall(ctx, action, input)
	if err != nil {
		appLog.Warn("endpoint network request failed", "component", "network", "event", "app.network.request.failed", "action", action, "error_type", logErrorType(err))
		httpStatus := http.StatusConflict
		if action == "status" || errors.Is(err, endpointservice.ErrIPCUnsupported) {
			httpStatus = http.StatusServiceUnavailable
		}
		writeError(writer, httpStatus, "network_operation_failed", "网络操作未完成，请检查 Soha 网络服务")
		return
	}
	writeRuntimeJSON(writer, http.StatusOK, status)
}

func writeRuntimeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func (runtimeAPI *appRuntime) currentUpdateStatus() updateStatus {
	runtimeAPI.statusMu.RLock()
	status := runtimeAPI.status
	runtimeAPI.statusMu.RUnlock()
	if status.CurrentVersion == "" {
		status.CurrentVersion = runtimeAPI.version
	}
	if runtimeAPI.updater == nil {
		status.Supported = false
		status.InstallMode = "disabled"
		status.State = string(updater.StateUnconfigured)
		return status
	}
	status.Supported = true
	if status.InstallMode == "" {
		status.InstallMode = defaultInstallMode(runtime.GOOS)
	}
	status.State = string(runtimeAPI.updater.State())
	return status
}

func (runtimeAPI *appRuntime) check(ctx context.Context) (updateStatus, error) {
	if !runtimeAPI.checkMu.TryLock() {
		return runtimeAPI.currentUpdateStatus(), nil
	}
	defer runtimeAPI.checkMu.Unlock()

	release, err := runtimeAPI.updater.Check(ctx)
	now := time.Now().UTC().Format(time.RFC3339)
	runtimeAPI.statusMu.Lock()
	status := runtimeAPI.status
	status.Supported = true
	status.CurrentVersion = runtimeAPI.version
	status.State = string(runtimeAPI.updater.State())
	status.LastCheckedAt = now
	if err != nil {
		status.ErrorCode = "update_check_failed"
		runtimeAPI.status = status
		runtimeAPI.statusMu.Unlock()
		return status, err
	}
	status.ErrorCode = ""
	if release == nil {
		status.AvailableVersion = ""
		status.DownloadMode = ""
		status.ReleaseURL = ""
		status.InstallMode = defaultInstallMode(runtime.GOOS)
	} else {
		status.AvailableVersion = release.Version
		status.InstallMode = releaseMetadataString(release, updateMetadataInstallMode, defaultInstallMode(runtime.GOOS))
		status.DownloadMode = releaseMetadataString(release, updateMetadataDownloadMode, "full")
		status.ReleaseURL = releaseMetadataString(release, updateMetadataReleaseURL, "")
	}
	runtimeAPI.status = status
	runtimeAPI.statusMu.Unlock()
	return status, nil
}

func (runtimeAPI *appRuntime) install(ctx context.Context) (updateStatus, error) {
	status := runtimeAPI.currentUpdateStatus()
	if status.InstallMode == "external" {
		return status, errExternalUpdate
	}
	if status.InstallMode != "self" {
		return status, errUpdateDisabled
	}
	if !runtimeAPI.checkMu.TryLock() {
		return status, nil
	}
	defer runtimeAPI.checkMu.Unlock()

	err := runtimeAPI.updater.CheckAndInstall(ctx)
	runtimeAPI.statusMu.Lock()
	status = runtimeAPI.status
	status.Supported = true
	status.CurrentVersion = runtimeAPI.version
	status.State = string(runtimeAPI.updater.State())
	status.LastCheckedAt = time.Now().UTC().Format(time.RFC3339)
	if err != nil {
		status.ErrorCode = "update_install_failed"
	} else {
		status.ErrorCode = ""
	}
	runtimeAPI.status = status
	runtimeAPI.statusMu.Unlock()
	return status, err
}

func releaseMetadataString(release *updater.Release, key, fallback string) string {
	if release == nil || release.Metadata == nil {
		return fallback
	}
	value, ok := release.Metadata[key].(string)
	if !ok || value == "" {
		return fallback
	}
	return value
}

func defaultInstallMode(platform string) string {
	switch platform {
	case "darwin":
		return "self"
	case "windows", "linux":
		return "external"
	default:
		return "disabled"
	}
}

func (runtimeAPI *appRuntime) startAutomaticChecks(ctx context.Context) {
	go func() {
		initial := time.NewTimer(30 * time.Second)
		defer initial.Stop()
		select {
		case <-ctx.Done():
			return
		case <-initial.C:
			runtimeAPI.checkSilently(ctx)
		}

		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runtimeAPI.checkSilently(ctx)
			}
		}
	}()
}

func (runtimeAPI *appRuntime) checkSilently(ctx context.Context) {
	_, _ = runtimeAPI.check(ctx)
}

func configureAppUpdater(ctx context.Context, runtimeAPI *appRuntime, target *updater.Updater) error {
	mode := updateBuildMode(strings.TrimSpace(appUpdateMode))
	if mode == "" || mode == updateModeDisabled {
		return nil
	}
	if mode != updateModeTest && mode != updateModeProduction {
		return fmt.Errorf("configure updater: unsupported build mode %q", mode)
	}
	publicKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(appUpdatePublicKey))
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("configure updater: Ed25519 public key is missing or invalid")
	}
	manifestURL := productionUpdateManifestURL
	if mode == updateModeTest {
		manifestURL = strings.TrimSpace(os.Getenv("SOHA_APP_UPDATE_MANIFEST_URL"))
		if err := validateTestUpdateURL(manifestURL); err != nil {
			return fmt.Errorf("configure updater: %w", err)
		}
	}
	executablePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("configure updater: resolve executable: %w", err)
	}
	provider, err := newSignedManifestProvider(signedManifestProviderConfig{
		Mode:           mode,
		ManifestURL:    manifestURL,
		PublicKey:      ed25519.PublicKey(publicKey),
		ExecutablePath: executablePath,
	})
	if err != nil {
		return fmt.Errorf("configure updater: %w", err)
	}
	if err := target.Init(updater.Config{
		CurrentVersion: runtimeAPI.version,
		Providers:      []updater.Provider{provider},
		Platform:       runtime.GOOS,
		Arch:           runtime.GOARCH,
		Channel:        map[updateBuildMode]string{updateModeTest: "test", updateModeProduction: "stable"}[mode],
		Window: &updater.BuiltinWindow{Options: updater.WindowOptions{
			Title: "Soha 更新",
		}},
	}); err != nil {
		return fmt.Errorf("configure updater: %w", err)
	}
	runtimeAPI.updater = target
	runtimeAPI.statusMu.Lock()
	runtimeAPI.status = updateStatus{
		Supported:      true,
		InstallMode:    defaultInstallMode(runtime.GOOS),
		State:          string(target.State()),
		CurrentVersion: runtimeAPI.version,
	}
	runtimeAPI.statusMu.Unlock()
	runtimeAPI.startAutomaticChecks(ctx)
	return nil
}

func validateTestUpdateURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("test update manifest URL is invalid")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme != "http" {
		return errors.New("test update manifest URL must use HTTPS or loopback HTTP")
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "localhost" {
		return nil
	}
	address := net.ParseIP(host)
	if address == nil || !address.IsLoopback() {
		return errors.New("test update manifest URL must use HTTPS or loopback HTTP")
	}
	return nil
}

func (runtimeAPI *appRuntime) proxyCall(ctx context.Context, action string, input *endpointservice.ProxyAction, rules *api.NetworkProxyRulesInput) (endpointservice.ProxyWorkbench, error) {
	if runtimeAPI.networkDisabled {
		return endpointservice.ProxyWorkbench{}, errors.New("network control disabled")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	call := runtimeAPI.networkProxyCall
	if call == nil {
		call = endpointservice.CallProxyIPC
	}
	return call(ctx, action, input, rules)
}
func (runtimeAPI *appRuntime) ProxyStatus(ctx context.Context) (endpointservice.ProxyWorkbench, error) {
	return runtimeAPI.proxyCall(ctx, "proxy_status", nil, nil)
}
func (runtimeAPI *appRuntime) ProxyAction(ctx context.Context, input endpointservice.ProxyAction) (endpointservice.ProxyWorkbench, error) {
	return runtimeAPI.proxyCall(ctx, "proxy_action", &input, nil)
}
func (runtimeAPI *appRuntime) ProxyRules(ctx context.Context, input api.NetworkProxyRulesInput) (endpointservice.ProxyWorkbench, error) {
	return runtimeAPI.proxyCall(ctx, "proxy_rules", nil, &input)
}
func (runtimeAPI *appRuntime) handleProxy(w http.ResponseWriter, r *http.Request, action string) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	var input *endpointservice.ProxyAction
	var rules *api.NetworkProxyRulesInput
	if action == "proxy_action" {
		input = &endpointservice.ProxyAction{}
		if decodeRequestJSON(r, input) != nil {
			writeError(w, http.StatusBadRequest, "invalid_proxy_request", "本机代理参数无效")
			return
		}
	}
	if action == "proxy_rules" {
		rules = &api.NetworkProxyRulesInput{}
		if decodeRequestJSON(r, rules) != nil {
			writeError(w, http.StatusBadRequest, "invalid_proxy_request", "个人规则参数无效")
			return
		}
	}
	view, err := runtimeAPI.proxyCall(ctx, action, input, rules)
	if err != nil {
		var ipcErr *endpointservice.IPCError
		if errors.As(err, &ipcErr) && ipcErr.Code == "rule_revision_conflict" {
			writeError(w, http.StatusConflict, ipcErr.Code, "规则版本已变化，请刷新后重新编辑")
			return
		}
		writeError(w, http.StatusConflict, "proxy_operation_failed", "本机代理操作未完成，请刷新状态后修复")
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (runtimeAPI *appRuntime) GetLocalProxyInterception() (endpointservice.InterceptionStatus, error) {
	return runtimeAPI.localInterception(context.Background(), nil)
}
func (runtimeAPI *appRuntime) SetLocalProxyInterception(intent endpointservice.InterceptionIntent) (endpointservice.InterceptionStatus, error) {
	return runtimeAPI.localInterception(context.Background(), &intent)
}
func (runtimeAPI *appRuntime) localInterception(ctx context.Context, intent *endpointservice.InterceptionIntent) (endpointservice.InterceptionStatus, error) {
	if runtimeAPI.networkDisabled {
		return endpointservice.InterceptionStatus{}, errors.New("network control disabled")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if intent != nil && (intent.SystemProxy || intent.TUN) {
		runtimeAPI.nativeScopeMu.Lock()
		scope, known := runtimeAPI.nativeScope, runtimeAPI.nativeScopeKnown
		runtimeAPI.nativeScopeMu.Unlock()
		if !known || !scope.Authenticated || scope.UserID == "" {
			return endpointservice.InterceptionStatus{}, errors.New("authenticated native UI scope required")
		}
		if _, err := runtimeAPI.syncNativeUIScope(ctx, scope); err != nil {
			return endpointservice.InterceptionStatus{}, err
		}
		runtimeAPI.nativeScopeMu.Lock()
		same := runtimeAPI.nativeScopeKnown && runtimeAPI.nativeScope == scope
		runtimeAPI.nativeScopeMu.Unlock()
		if !same {
			return endpointservice.InterceptionStatus{}, errors.New("native UI scope changed")
		}
	}
	call := runtimeAPI.networkInterceptionCall
	if call == nil {
		call = endpointservice.CallInterceptionIPC
	}
	status, err := call(ctx, intent)
	if err == nil {
		runtimeAPI.nativeScopeMu.Lock()
		runtimeAPI.nativeKnownInterception = status.SystemProxy || status.TUN || status.CleanupPending || status.DesiredSystemProxy || status.DesiredTUN
		runtimeAPI.nativeScopeMu.Unlock()
	}
	return status, err
}
func (runtimeAPI *appRuntime) handleInterception(w http.ResponseWriter, r *http.Request) {
	var intent *endpointservice.InterceptionIntent
	if r.Method == http.MethodPost {
		intent = &endpointservice.InterceptionIntent{}
		if decodeRequestJSON(r, intent) != nil {
			writeError(w, http.StatusBadRequest, "invalid_native_request", "本机接管参数无效")
			return
		}
	}
	status, err := runtimeAPI.localInterception(r.Context(), intent)
	if err != nil {
		writeError(w, http.StatusConflict, "native_operation_failed", "本机接管未完成，请刷新状态后恢复")
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// This private sink is invoked by appHost from actual authentication/server
// lifecycle events. No HTTP route or Wails method accepts identity fields.
func (runtimeAPI *appRuntime) setNativeUIScope(ctx context.Context, scope endpointservice.NativeUIScope) error {
	runtimeAPI.nativeScopeMu.Lock()
	if runtimeAPI.nativeRetiredScopes[scope.Epoch] {
		runtimeAPI.nativeScopeMu.Unlock()
		return errors.New("retired native host epoch")
	}
	if runtimeAPI.nativeScopeKnown && runtimeAPI.nativeScope.Epoch != scope.Epoch {
		if len(runtimeAPI.nativeRetiredScopes) >= 64 {
			runtimeAPI.nativeScopeMu.Unlock()
			return errors.New("native host epoch limit")
		}
		if runtimeAPI.nativeRetiredScopes == nil {
			runtimeAPI.nativeRetiredScopes = map[string]bool{}
		}
		runtimeAPI.nativeRetiredScopes[runtimeAPI.nativeScope.Epoch] = true
	}
	if runtimeAPI.nativeScopeKnown && runtimeAPI.nativeScope.Epoch == scope.Epoch {
		old := runtimeAPI.nativeScope
		if scope.Generation < old.Generation || scope.Generation == old.Generation && scope != old {
			runtimeAPI.nativeScopeMu.Unlock()
			return errors.New("stale native host scope")
		}
	}
	runtimeAPI.nativeScope = scope
	runtimeAPI.nativeScopeKnown = true
	wasNative := runtimeAPI.nativeKnownInterception
	runtimeAPI.nativeScopeMu.Unlock()
	if runtimeAPI.networkDisabled {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	status, err := runtimeAPI.syncNativeUIScope(ctx, scope)
	if err != nil {
		if !wasNative && (errors.Is(err, os.ErrNotExist) || errors.Is(err, endpointservice.ErrIPCUnsupported)) {
			return nil
		}
		return err
	}
	runtimeAPI.nativeScopeMu.Lock()
	if runtimeAPI.nativeScope == scope {
		runtimeAPI.nativeKnownInterception = status.SystemProxy || status.TUN || status.CleanupPending || status.DesiredSystemProxy || status.DesiredTUN
	}
	runtimeAPI.nativeScopeMu.Unlock()
	if status.CleanupPending {
		return errors.New("native scope cleanup pending")
	}
	return nil
}
func (runtimeAPI *appRuntime) syncNativeUIScope(ctx context.Context, scope endpointservice.NativeUIScope) (endpointservice.InterceptionStatus, error) {
	call := runtimeAPI.networkUIScopeCall
	if call == nil {
		call = endpointservice.CallInterceptionUIScopeIPC
	}
	return call(ctx, scope)
}
