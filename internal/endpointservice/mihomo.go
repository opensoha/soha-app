package endpointservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	mihomoProviderName    = "soha-managed"
	mihomoManualProxyName = "soha-manual"
)

type MihomoReadback struct {
	Mode            string `json:"mode,omitempty"`
	ProfileID       string `json:"profileId,omitempty"`
	ProfileRevision int    `json:"profileRevision,omitempty"`
	MixedPort       int    `json:"mixedPort,omitempty"`
	ControllerPort  int    `json:"controllerPort,omitempty"`
	DNSMode         string `json:"dnsMode,omitempty"`
	SelectedProxy   string `json:"selectedProxy,omitempty"`
}

type MihomoRuntime interface {
	Apply(context.Context, MihomoConfiguration) (MihomoReadback, error)
	Disable(context.Context) error
}

type MihomoAppRuntime interface {
	ApplySubscription(context.Context, MihomoConfiguration, string, string) (MihomoAppStatus, error)
}

type CoordinatedExecutor struct {
	mu             sync.Mutex
	wireGuard      ConfigurationExecutor
	mihomo         MihomoRuntime
	mihomoActive   bool
	previousMihomo *mihomoAppliedState
	appStatePath   string
	appDesired     *MihomoConfiguration
	appStatus      MihomoAppStatus
}

type mihomoAppliedState struct {
	Configuration MihomoConfiguration
	AppState      *mihomoAppState
	AppStatus     MihomoAppStatus
}

func NewCoordinatedExecutor(wireGuard ConfigurationExecutor, mihomo MihomoRuntime, appStatePath ...string) (*CoordinatedExecutor, error) {
	if wireGuard == nil || len(appStatePath) > 1 || len(appStatePath) == 1 && !filepath.IsAbs(appStatePath[0]) {
		return nil, errors.New("WireGuard executor is required")
	}
	path := ""
	if len(appStatePath) == 1 {
		path = appStatePath[0]
	}
	return &CoordinatedExecutor{wireGuard: wireGuard, mihomo: mihomo, appStatePath: path}, nil
}

func (executor *CoordinatedExecutor) Apply(ctx context.Context, desired ConfigurationDesired, now time.Time) ApplyOutcome {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	wireGuard := executor.wireGuard.Apply(ctx, desired, now)
	mihomo := executor.applyMihomo(ctx, desired)
	status, reason := "applied", ""
	if wireGuard.Status != "applied" {
		status, reason = "rejected", fallback(wireGuard.ReasonCode, "wireguard_apply_failed")
	}
	if mihomo.Status != "applied" {
		status, reason = "rejected", fallback(mihomo.ReasonCode, "mihomo_apply_failed")
	}
	return ApplyOutcome{Status: status, ReadbackHash: combinedReadbackHash(wireGuard.ReadbackHash, mihomo.ReadbackHash), ReasonCode: reason}
}

func (executor *CoordinatedExecutor) Disable(ctx context.Context) error {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	wireGuardErr := executor.wireGuard.Disable(ctx)
	var mihomoErr error
	if executor.mihomo != nil {
		mihomoErr = executor.mihomo.Disable(ctx)
	}
	if mihomoErr == nil {
		executor.mihomoActive, executor.previousMihomo = false, nil
		executor.appDesired, executor.appStatus = nil, MihomoAppStatus{}
	}
	return errors.Join(wireGuardErr, mihomoErr)
}

func (executor *CoordinatedExecutor) applyMihomo(ctx context.Context, desired ConfigurationDesired) ApplyOutcome {
	configuration := desired.Mihomo
	if configuration == nil {
		if executor.mihomoActive && executor.mihomo != nil {
			if err := executor.mihomo.Disable(ctx); err != nil {
				return executor.recoverMihomo(ctx, "mihomo_disable_failed")
			}
		}
		executor.mihomoActive, executor.previousMihomo = false, nil
		executor.appDesired, executor.appStatus = nil, MihomoAppStatus{}
		return ApplyOutcome{Status: "applied", ReadbackHash: mihomoReadbackHash(MihomoReadback{})}
	}
	includeSubscription := configuration.Mode == "managed_follow"
	if err := validateMihomoConfiguration(configuration, desired.WireGuard, includeSubscription); err != nil {
		return ApplyOutcome{Status: "rejected", ReadbackHash: executor.currentMihomoReadbackHash(), ReasonCode: "unsafe_mihomo_configuration"}
	}
	if executor.mihomo == nil {
		return ApplyOutcome{Status: "rejected", ReadbackHash: executor.currentMihomoReadbackHash(), ReasonCode: "mihomo_runtime_unavailable"}
	}
	if configuration.Mode == "app_subscription" {
		copied := cloneMihomoConfiguration(*configuration)
		executor.appDesired = &copied
		return executor.applyStoredMihomoApp(ctx, copied)
	}
	executor.appDesired, executor.appStatus = nil, MihomoAppStatus{}
	readback, err := executor.mihomo.Apply(ctx, *configuration)
	if err != nil || !reflect.DeepEqual(readback, expectedMihomoReadback(*configuration)) {
		return executor.recoverMihomo(ctx, "mihomo_apply_failed")
	}
	executor.rememberManagedMihomo(*configuration)
	return ApplyOutcome{Status: "applied", ReadbackHash: mihomoReadbackHash(readback)}
}

func (executor *CoordinatedExecutor) applyStoredMihomoApp(ctx context.Context, configuration MihomoConfiguration) ApplyOutcome {
	base := mihomoAppStatus(configuration, false, "", nil)
	if executor.appStatePath == "" {
		if executor.mihomoActive && executor.mihomo != nil {
			if err := executor.mihomo.Disable(ctx); err != nil {
				return executor.recoverMihomo(ctx, "mihomo_disable_failed")
			}
		}
		executor.mihomoActive, executor.previousMihomo, executor.appStatus = false, nil, base
		return ApplyOutcome{Status: "applied", ReadbackHash: mihomoReadbackHash(expectedMihomoReadback(configuration))}
	}
	state, err := loadMihomoAppState(executor.appStatePath)
	if errors.Is(err, os.ErrNotExist) || err == nil && (state.ProfileID != configuration.ProfileID || state.ProfileRevision != configuration.ProfileRevision) {
		if executor.mihomoActive && executor.mihomo != nil {
			if disableErr := executor.mihomo.Disable(ctx); disableErr != nil {
				return executor.recoverMihomo(ctx, "mihomo_disable_failed")
			}
		}
		executor.mihomoActive, executor.previousMihomo, executor.appStatus = false, nil, base
		return ApplyOutcome{Status: "applied", ReadbackHash: mihomoReadbackHash(expectedMihomoReadback(configuration))}
	}
	if err != nil {
		if executor.mihomoActive {
			if disableErr := executor.mihomo.Disable(ctx); disableErr != nil {
				return executor.recoverMihomo(ctx, "mihomo_state_invalid")
			}
		}
		executor.mihomoActive, executor.previousMihomo, executor.appStatus = false, nil, base
		return ApplyOutcome{Status: "rejected", ReadbackHash: mihomoReadbackHash(MihomoReadback{}), ReasonCode: "mihomo_state_invalid"}
	}
	status, err := executor.applyMihomoAppState(ctx, configuration, state)
	if err != nil {
		return ApplyOutcome{Status: "rejected", ReadbackHash: mihomoReadbackHash(MihomoReadback{}), ReasonCode: "mihomo_apply_failed"}
	}
	readback := expectedMihomoReadback(configuration)
	readback.SelectedProxy = status.SelectedProxy
	return ApplyOutcome{Status: "applied", ReadbackHash: mihomoReadbackHash(readback)}
}

func (executor *CoordinatedExecutor) ConfigureMihomoApp(ctx context.Context, input MihomoAppInput) (MihomoAppStatus, error) {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	configuration, err := executor.mihomoAppConfiguration()
	if err != nil || !validSubscriptionURL(input.SubscriptionURL) {
		return executor.currentMihomoAppStatus(), errors.New("mihomo app subscription is invalid or unavailable")
	}
	state := mihomoAppState{Version: mihomoAppStateVersion, ProfileID: configuration.ProfileID, ProfileRevision: configuration.ProfileRevision, SubscriptionURL: input.SubscriptionURL}
	return executor.applyMihomoAppState(ctx, configuration, state)
}

func (executor *CoordinatedExecutor) SelectMihomoApp(ctx context.Context, selectedProxy string) (MihomoAppStatus, error) {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	configuration, state, err := executor.loadedMihomoAppState()
	if err != nil || !validMihomoName(selectedProxy) {
		return executor.currentMihomoAppStatus(), errors.New("mihomo app subscription is not configured")
	}
	state.SelectedProxy = selectedProxy
	return executor.applyMihomoAppState(ctx, configuration, state)
}

func (executor *CoordinatedExecutor) RefreshMihomoApp(ctx context.Context) (MihomoAppStatus, error) {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	configuration, state, err := executor.loadedMihomoAppState()
	if err != nil {
		return executor.currentMihomoAppStatus(), errors.New("mihomo app subscription is not configured")
	}
	return executor.applyMihomoAppState(ctx, configuration, state)
}

func (executor *CoordinatedExecutor) ClearMihomoApp(ctx context.Context) (MihomoAppStatus, error) {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	configuration, err := executor.mihomoAppConfiguration()
	if err != nil {
		return executor.currentMihomoAppStatus(), err
	}
	if executor.mihomo != nil {
		if err := executor.mihomo.Disable(ctx); err != nil {
			return executor.currentMihomoAppStatus(), err
		}
	}
	executor.mihomoActive = false
	if err := os.Remove(executor.appStatePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return executor.currentMihomoAppStatus(), err
	}
	executor.appStatus = mihomoAppStatus(configuration, false, "", nil)
	return executor.currentMihomoAppStatus(), nil
}

func (executor *CoordinatedExecutor) MihomoAppStatus() (MihomoAppStatus, error) {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if _, err := executor.mihomoAppConfiguration(); err != nil {
		return MihomoAppStatus{}, err
	}
	return executor.currentMihomoAppStatus(), nil
}

func (executor *CoordinatedExecutor) loadedMihomoAppState() (MihomoConfiguration, mihomoAppState, error) {
	configuration, err := executor.mihomoAppConfiguration()
	if err != nil {
		return MihomoConfiguration{}, mihomoAppState{}, err
	}
	state, err := loadMihomoAppState(executor.appStatePath)
	if err != nil || state.ProfileID != configuration.ProfileID || state.ProfileRevision != configuration.ProfileRevision {
		return MihomoConfiguration{}, mihomoAppState{}, errors.New("mihomo app subscription is not configured")
	}
	return configuration, state, nil
}

func (executor *CoordinatedExecutor) mihomoAppConfiguration() (MihomoConfiguration, error) {
	if executor.appDesired == nil || executor.appDesired.Mode != "app_subscription" || executor.appStatePath == "" || executor.mihomo == nil {
		return MihomoConfiguration{}, errors.New("mihomo app subscription is unavailable")
	}
	if _, ok := executor.mihomo.(MihomoAppRuntime); !ok {
		return MihomoConfiguration{}, errors.New("mihomo app subscription is unavailable")
	}
	return *executor.appDesired, nil
}

func (executor *CoordinatedExecutor) applyMihomoAppState(ctx context.Context, configuration MihomoConfiguration, state mihomoAppState) (MihomoAppStatus, error) {
	runtime, ok := executor.mihomo.(MihomoAppRuntime)
	if !ok {
		return executor.currentMihomoAppStatus(), errors.New("mihomo app subscription runtime is unavailable")
	}
	status, err := runtime.ApplySubscription(ctx, configuration, state.SubscriptionURL, state.SelectedProxy)
	if err != nil || !validMihomoAppStatus(status, configuration) {
		executor.recoverMihomo(ctx, "mihomo_apply_failed")
		return executor.currentMihomoAppStatus(), errors.New("mihomo app subscription apply failed")
	}
	state.SelectedProxy = status.SelectedProxy
	if err := saveMihomoAppState(executor.appStatePath, state); err != nil {
		executor.recoverMihomo(ctx, "mihomo_state_save_failed")
		return executor.currentMihomoAppStatus(), err
	}
	executor.rememberAppMihomo(configuration, state, status)
	return executor.currentMihomoAppStatus(), nil
}

func (executor *CoordinatedExecutor) recoverMihomo(ctx context.Context, reason string) ApplyOutcome {
	previous := executor.previousMihomo
	if previous != nil {
		configuration := cloneMihomoConfiguration(previous.Configuration)
		if previous.AppState != nil {
			if runtime, ok := executor.mihomo.(MihomoAppRuntime); ok {
				state := *previous.AppState
				if status, err := runtime.ApplySubscription(ctx, configuration, state.SubscriptionURL, state.SelectedProxy); err == nil && validMihomoAppStatus(status, configuration) {
					executor.rememberAppMihomo(configuration, state, status)
					return ApplyOutcome{Status: "rolled-back", ReadbackHash: executor.currentMihomoReadbackHash(), ReasonCode: reason}
				}
			}
		} else if readback, err := executor.mihomo.Apply(ctx, configuration); err == nil && reflect.DeepEqual(readback, expectedMihomoReadback(configuration)) {
			executor.rememberManagedMihomo(configuration)
			return ApplyOutcome{Status: "rolled-back", ReadbackHash: mihomoReadbackHash(readback), ReasonCode: reason}
		}
		_ = executor.mihomo.Disable(ctx)
		executor.mihomoActive, executor.previousMihomo = false, nil
		if executor.appDesired != nil {
			executor.appStatus = mihomoAppStatus(*executor.appDesired, false, "", nil)
		} else {
			executor.appStatus = MihomoAppStatus{}
		}
		return ApplyOutcome{Status: "rejected", ReadbackHash: mihomoReadbackHash(MihomoReadback{}), ReasonCode: "mihomo_rollback_failed"}
	}
	_ = executor.mihomo.Disable(ctx)
	executor.mihomoActive = false
	if executor.appDesired != nil {
		executor.appStatus = mihomoAppStatus(*executor.appDesired, false, "", nil)
	}
	return ApplyOutcome{Status: "rejected", ReadbackHash: mihomoReadbackHash(MihomoReadback{}), ReasonCode: reason}
}

func (executor *CoordinatedExecutor) rememberManagedMihomo(configuration MihomoConfiguration) {
	executor.mihomoActive = true
	executor.previousMihomo = &mihomoAppliedState{Configuration: cloneMihomoConfiguration(configuration)}
	executor.appDesired, executor.appStatus = nil, MihomoAppStatus{}
}

func (executor *CoordinatedExecutor) rememberAppMihomo(configuration MihomoConfiguration, state mihomoAppState, status MihomoAppStatus) {
	configuration = cloneMihomoConfiguration(configuration)
	stateCopy := state
	executor.mihomoActive = true
	executor.previousMihomo = &mihomoAppliedState{Configuration: configuration, AppState: &stateCopy, AppStatus: cloneMihomoAppStatus(status)}
	executor.appDesired, executor.appStatus = &configuration, cloneMihomoAppStatus(status)
}

func (executor *CoordinatedExecutor) currentMihomoReadbackHash() string {
	if executor.previousMihomo == nil {
		return mihomoReadbackHash(MihomoReadback{})
	}
	readback := expectedMihomoReadback(executor.previousMihomo.Configuration)
	if executor.previousMihomo.AppState != nil {
		readback.SelectedProxy = executor.previousMihomo.AppStatus.SelectedProxy
	}
	return mihomoReadbackHash(readback)
}

func cloneMihomoConfiguration(configuration MihomoConfiguration) MihomoConfiguration {
	configuration.BypassCIDRs = slices.Clone(configuration.BypassCIDRs)
	configuration.BypassHosts = slices.Clone(configuration.BypassHosts)
	return configuration
}

func (executor *CoordinatedExecutor) currentMihomoAppStatus() MihomoAppStatus {
	return cloneMihomoAppStatus(executor.appStatus)
}

func mihomoAppStatus(configuration MihomoConfiguration, configured bool, selected string, proxies []string) MihomoAppStatus {
	return MihomoAppStatus{Mode: configuration.Mode, ProfileID: configuration.ProfileID, ProfileRevision: configuration.ProfileRevision, Configured: configured, SelectedProxy: selected, Proxies: slices.Clone(proxies)}
}

func validMihomoAppStatus(status MihomoAppStatus, configuration MihomoConfiguration) bool {
	if status.Mode != "app_subscription" || status.ProfileID != configuration.ProfileID || status.ProfileRevision != configuration.ProfileRevision || !status.Configured || !validMihomoName(status.SelectedProxy) || len(status.Proxies) == 0 || len(status.Proxies) > 2048 || !slices.Contains(status.Proxies, status.SelectedProxy) {
		return false
	}
	seen := map[string]struct{}{}
	for _, proxy := range status.Proxies {
		if !validMihomoName(proxy) {
			return false
		}
		if _, exists := seen[proxy]; exists {
			return false
		}
		seen[proxy] = struct{}{}
	}
	return true
}

func combinedReadbackHash(wireGuard, mihomo string) string {
	raw, _ := json.Marshal(struct {
		WireGuard string `json:"wireguard"`
		Mihomo    string `json:"mihomo"`
	}{wireGuard, mihomo})
	digest := sha256.Sum256(raw)
	return fmt.Sprintf("sha256:%x", digest)
}

func mihomoReadbackHash(readback MihomoReadback) string {
	raw, _ := json.Marshal(readback)
	digest := sha256.Sum256(raw)
	return fmt.Sprintf("sha256:%x", digest)
}

func expectedMihomoReadback(configuration MihomoConfiguration) MihomoReadback {
	return MihomoReadback{
		Mode: configuration.Mode, ProfileID: configuration.ProfileID, ProfileRevision: configuration.ProfileRevision,
		MixedPort: configuration.MixedPort, ControllerPort: configuration.ControllerPort, DNSMode: configuration.DNSMode,
		SelectedProxy: configuration.SelectedProxy,
	}
}

type MihomoController struct {
	mu        sync.Mutex
	origin    string
	address   string
	authority string
	port      int
	secret    string
	http      *http.Client
	applied   MihomoReadback
}

func NewMihomoController(origin, secret string) (*MihomoController, error) {
	normalized, port, err := mihomoOrigin(origin)
	if err != nil || len(secret) < 32 || len(secret) > 4096 || strings.TrimSpace(secret) != secret || strings.ContainsAny(secret, "\r\n\t ") {
		return nil, errors.New("mihomo controller configuration is invalid")
	}
	parsed, _ := url.Parse(normalized)
	client := *http.DefaultClient
	client.Timeout = requestTimeout
	client.CheckRedirect = rejectRedirect
	return &MihomoController{origin: normalized, address: parsed.Hostname(), authority: parsed.Host, port: port, secret: secret, http: &client}, nil
}

func (controller *MihomoController) Apply(ctx context.Context, configuration MihomoConfiguration) (MihomoReadback, error) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if configuration.Mode != "managed_follow" || configuration.ControllerPort != controller.port || validateMihomoConfiguration(&configuration, nil, true) != nil {
		return MihomoReadback{}, errors.New("mihomo configuration does not match the local controller")
	}
	selectedProxy := configuration.SelectedProxy
	if configuration.SourceType == "manual_node" {
		selectedProxy = mihomoManualProxyName
	}
	status, err := controller.applySource(ctx, configuration, configuration.SubscriptionURL, selectedProxy)
	if err != nil {
		return MihomoReadback{}, err
	}
	readback := expectedMihomoReadback(configuration)
	readback.SelectedProxy = status.SelectedProxy
	controller.applied = readback
	return readback, nil
}

func (controller *MihomoController) ApplySubscription(ctx context.Context, configuration MihomoConfiguration, subscriptionURL, selectedProxy string) (MihomoAppStatus, error) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if configuration.Mode != "app_subscription" || configuration.ControllerPort != controller.port || validateMihomoConfiguration(&configuration, nil, false) != nil || !validSubscriptionURL(subscriptionURL) || selectedProxy != "" && !validMihomoName(selectedProxy) {
		return MihomoAppStatus{}, errors.New("mihomo app subscription does not match the local controller")
	}
	status, err := controller.applySource(ctx, configuration, subscriptionURL, selectedProxy)
	if err == nil {
		controller.applied = MihomoReadback{Mode: status.Mode, ProfileID: status.ProfileID, ProfileRevision: status.ProfileRevision, MixedPort: configuration.MixedPort, ControllerPort: configuration.ControllerPort, DNSMode: configuration.DNSMode, SelectedProxy: status.SelectedProxy}
	}
	return status, err
}

func (controller *MihomoController) applySource(ctx context.Context, configuration MihomoConfiguration, subscriptionURL, selectedProxy string) (MihomoAppStatus, error) {
	payload, err := renderMihomoConfiguration(configuration, subscriptionURL, controller.address, controller.authority, controller.secret)
	if err == nil {
		raw, encodeErr := json.Marshal(struct {
			Payload string `json:"payload"`
		}{payload})
		if encodeErr != nil {
			err = encodeErr
		} else {
			err = controller.request(ctx, http.MethodPut, "/configs?force=true", raw, http.StatusNoContent, nil)
		}
	}
	if err == nil && configuration.SourceType != "manual_node" {
		err = controller.request(ctx, http.MethodPut, "/providers/proxies/"+url.PathEscape(mihomoProviderName), nil, http.StatusNoContent, nil)
	}
	var group struct {
		All []string `json:"all"`
		Now string   `json:"now"`
	}
	if err == nil {
		err = controller.request(ctx, http.MethodGet, "/proxies/"+url.PathEscape(configuration.SelectorGroup), nil, http.StatusOK, &group)
	}
	if err == nil {
		if len(group.All) == 0 || len(group.All) > 2048 {
			err = errors.New("mihomo proxy group is invalid")
		}
		seen := map[string]struct{}{}
		for _, proxy := range group.All {
			if !validMihomoName(proxy) {
				err = errors.New("mihomo proxy group is invalid")
				break
			}
			if _, exists := seen[proxy]; exists {
				err = errors.New("mihomo proxy group is invalid")
				break
			}
			seen[proxy] = struct{}{}
		}
		if err == nil && selectedProxy == "" {
			if slices.Contains(group.All, group.Now) {
				selectedProxy = group.Now
			} else {
				selectedProxy = group.All[0]
			}
		} else if err == nil && !slices.Contains(group.All, selectedProxy) {
			err = errors.New("mihomo selected proxy is unavailable")
		}
	}
	if err == nil {
		raw, _ := json.Marshal(struct {
			Name string `json:"name"`
		}{selectedProxy})
		err = controller.request(ctx, http.MethodPut, "/proxies/"+url.PathEscape(configuration.SelectorGroup), raw, http.StatusNoContent, nil)
	}
	var configs struct {
		MixedPort int    `json:"mixed-port"`
		Mode      string `json:"mode"`
	}
	if err == nil {
		err = controller.request(ctx, http.MethodGet, "/configs", nil, http.StatusOK, &configs)
	}
	if err == nil {
		group = struct {
			All []string `json:"all"`
			Now string   `json:"now"`
		}{}
		err = controller.request(ctx, http.MethodGet, "/proxies/"+url.PathEscape(configuration.SelectorGroup), nil, http.StatusOK, &group)
	}
	if err != nil || configs.MixedPort != configuration.MixedPort || configs.Mode != "rule" || group.Now != selectedProxy || !slices.Contains(group.All, selectedProxy) {
		disableErr := controller.disable(ctx)
		if err == nil {
			err = errors.New("mihomo controller readback did not match desired state")
		}
		return MihomoAppStatus{}, errors.Join(err, disableErr)
	}
	return mihomoAppStatus(configuration, true, selectedProxy, group.All), nil
}

func (controller *MihomoController) Disable(ctx context.Context) error {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.disable(ctx)
}

func (controller *MihomoController) disable(ctx context.Context) error {
	payload := fmt.Sprintf("mixed-port: 0\nallow-lan: false\nbind-address: %s\nmode: direct\nipv6: false\nexternal-controller: %s\nsecret: %s\ntun:\n  enable: false\ndns:\n  enable: false\nproxies: []\nproxy-groups: []\nrules: []\n", yamlString(controller.address), yamlString(controller.authority), yamlString(controller.secret))
	raw, _ := json.Marshal(struct {
		Payload string `json:"payload"`
	}{payload})
	if err := controller.request(ctx, http.MethodPut, "/configs?force=true", raw, http.StatusNoContent, nil); err != nil {
		return err
	}
	controller.applied = MihomoReadback{}
	return nil
}

func (controller *MihomoController) ProxyFlowSnapshot(ctx context.Context) (ProxyFlowSnapshot, error) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.applied.Mode == "" {
		return ProxyFlowSnapshot{}, nil
	}
	var connections struct {
		DownloadTotal int64      `json:"downloadTotal"`
		UploadTotal   int64      `json:"uploadTotal"`
		Connections   []struct{} `json:"connections"`
	}
	if err := controller.request(ctx, http.MethodGet, "/connections", nil, http.StatusOK, &connections); err != nil {
		return ProxyFlowSnapshot{}, err
	}
	if connections.DownloadTotal < 0 || connections.UploadTotal < 0 || len(connections.Connections) > 1_000_000 {
		return ProxyFlowSnapshot{}, errors.New("mihomo connection counters are invalid")
	}
	return ProxyFlowSnapshot{
		Active: true, Engine: "mihomo", Mode: controller.applied.Mode, ProfileID: controller.applied.ProfileID,
		ProfileRevision: controller.applied.ProfileRevision, SelectedProxy: controller.applied.SelectedProxy,
		UploadTotal: connections.UploadTotal, DownloadTotal: connections.DownloadTotal, ActiveConnections: int64(len(connections.Connections)),
	}, nil
}

func (controller *MihomoController) request(ctx context.Context, method, path string, body []byte, expectedStatus int, result any) error {
	request, err := http.NewRequestWithContext(ctx, method, controller.origin+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+controller.secret)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := controller.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != expectedStatus {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("mihomo controller returned HTTP %d", response.StatusCode)
	}
	if result == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("mihomo controller returned a non-JSON response")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxRuntimeResponseBytes+1))
	if err != nil || len(raw) > maxRuntimeResponseBytes || json.Unmarshal(raw, result) != nil {
		return errors.New("mihomo controller returned an invalid response")
	}
	return nil
}

func renderMihomoConfiguration(configuration MihomoConfiguration, subscriptionURL, controllerAddress, controllerAuthority, secret string) (string, error) {
	if validateMihomoConfiguration(&configuration, nil, false) != nil || configuration.SourceType == "manual_node" && !validMihomoManualNode(configuration.ManualNode) || configuration.SourceType != "manual_node" && !validSubscriptionURL(subscriptionURL) {
		return "", errors.New("unsafe mihomo configuration")
	}
	var output strings.Builder
	fmt.Fprintf(&output, "mixed-port: %d\nallow-lan: false\nbind-address: %s\nmode: rule\nlog-level: warning\nipv6: false\nexternal-controller: %s\nsecret: %s\ntun:\n  enable: false\n", configuration.MixedPort, yamlString(controllerAddress), yamlString(controllerAuthority), yamlString(secret))
	if configuration.DNSMode == "fake_ip" {
		fmt.Fprintf(&output, "dns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-range: %s\n  nameserver:\n    - system\n", yamlString(configuration.FakeIPRange))
	} else {
		output.WriteString("dns:\n  enable: false\n")
	}
	if configuration.SourceType == "manual_node" {
		node := configuration.ManualNode
		proxyType := node.Protocol
		if proxyType == "https" {
			proxyType = "http"
		}
		fmt.Fprintf(&output, "proxies:\n  - name: %s\n    type: %s\n    server: %s\n    port: %d\n", yamlString(mihomoManualProxyName), yamlString(proxyType), yamlString(node.Server), node.Port)
		if node.Protocol == "https" {
			output.WriteString("    tls: true\n")
		}
		if node.Username != "" {
			fmt.Fprintf(&output, "    username: %s\n    password: %s\n", yamlString(node.Username), yamlString(node.Password))
		}
		fmt.Fprintf(&output, "proxy-groups:\n  - name: %s\n    type: select\n    proxies:\n      - %s\nrules:\n", yamlString(configuration.SelectorGroup), yamlString(mihomoManualProxyName))
	} else {
		fmt.Fprintf(&output, "proxy-providers:\n  %s:\n    type: http\n    url: %s\n    path: ./providers/%s.yaml\n    proxy: DIRECT\n    interval: 3600\nproxy-groups:\n  - name: %s\n    type: select\n    use:\n      - %s\nrules:\n", mihomoProviderName, yamlString(subscriptionURL), mihomoProviderName, yamlString(configuration.SelectorGroup), mihomoProviderName)
	}
	for _, cidr := range configuration.BypassCIDRs {
		fmt.Fprintf(&output, "  - %s\n", yamlString("IP-CIDR,"+cidr+",DIRECT,no-resolve"))
	}
	for _, host := range configuration.BypassHosts {
		if address, err := netip.ParseAddr(host); err == nil {
			fmt.Fprintf(&output, "  - %s\n", yamlString("IP-CIDR,"+netip.PrefixFrom(address, 32).String()+",DIRECT,no-resolve"))
		} else {
			fmt.Fprintf(&output, "  - %s\n", yamlString("DOMAIN,"+host+",DIRECT"))
		}
	}
	fmt.Fprintf(&output, "  - %s\n", yamlString("MATCH,"+configuration.SelectorGroup))
	return output.String(), nil
}

func yamlString(value string) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

func validateMihomoConfiguration(configuration *MihomoConfiguration, wireGuard *WireGuardConfiguration, requireSource bool) error {
	if configuration == nil {
		return nil
	}
	if !identifierPattern.MatchString(configuration.ProfileID) || configuration.ProfileRevision < 1 || configuration.MixedPort < 1 || configuration.MixedPort > 65535 || configuration.ControllerPort < 1 || configuration.ControllerPort > 65535 || configuration.MixedPort == configuration.ControllerPort || !validMihomoName(configuration.SelectorGroup) {
		return errors.New("invalid mihomo profile")
	}
	switch configuration.Mode {
	case "managed_follow":
		if !configuration.FailClosed {
			return errors.New("invalid managed mihomo profile")
		}
		switch configuration.SourceType {
		case "", "managed_subscription":
			if !validMihomoName(configuration.SelectedProxy) || configuration.ManualNode != nil || requireSource && !validSubscriptionURL(configuration.SubscriptionURL) {
				return errors.New("invalid managed mihomo subscription")
			}
		case "manual_node":
			if configuration.SelectedProxy != "" || configuration.SubscriptionURL != "" || requireSource && !validMihomoManualNode(configuration.ManualNode) {
				return errors.New("invalid managed mihomo manual node")
			}
		default:
			return errors.New("invalid managed mihomo source")
		}
	case "app_subscription":
		if configuration.SourceType != "" || configuration.SelectedProxy != "" || configuration.SubscriptionURL != "" || configuration.ManualNode != nil {
			return errors.New("app subscription cannot contain managed state")
		}
	default:
		return errors.New("invalid mihomo mode")
	}
	var fakeIP netip.Prefix
	switch configuration.DNSMode {
	case "disabled":
		if configuration.FakeIPRange != "" {
			return errors.New("disabled mihomo DNS contains a fake-IP range")
		}
	case "fake_ip":
		var err error
		fakeIP, err = canonicalMihomoPrefix(configuration.FakeIPRange)
		if err != nil {
			return err
		}
	default:
		return errors.New("invalid mihomo DNS mode")
	}
	if len(configuration.BypassCIDRs) > 256 || len(configuration.BypassHosts) > 128 {
		return errors.New("mihomo bypass limit exceeded")
	}
	bypasses := make([]netip.Prefix, 0, len(configuration.BypassCIDRs))
	seen := map[string]struct{}{}
	for _, raw := range configuration.BypassCIDRs {
		prefix, err := canonicalMihomoPrefix(raw)
		if err != nil {
			return err
		}
		if _, exists := seen[raw]; exists || fakeIP.IsValid() && fakeIP.Overlaps(prefix) {
			return errors.New("invalid mihomo bypass CIDR")
		}
		seen[raw] = struct{}{}
		bypasses = append(bypasses, prefix)
	}
	seen = map[string]struct{}{}
	for _, host := range configuration.BypassHosts {
		if !validEndpointHost(host) {
			return errors.New("invalid mihomo bypass host")
		}
		if _, exists := seen[host]; exists {
			return errors.New("duplicate mihomo bypass host")
		}
		seen[host] = struct{}{}
	}
	if wireGuard != nil {
		if fakeIP.IsValid() && len(wireGuard.DNSServers) != 0 {
			return errors.New("mihomo fake-IP DNS conflicts with WireGuard DNS")
		}
		for _, raw := range wireGuard.Routes {
			route, err := canonicalMihomoPrefix(raw)
			if err != nil || fakeIP.IsValid() && fakeIP.Overlaps(route) || !prefixCoveredBy(route, bypasses) {
				return errors.New("mihomo bypass does not cover WireGuard route")
			}
		}
	}
	return nil
}

func validMihomoName(value string) bool {
	return len(value) > 0 && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, ",\r\n\t")
}

func canonicalMihomoPrefix(raw string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() == 0 || prefix.String() != raw {
		return netip.Prefix{}, errors.New("invalid mihomo IPv4 prefix")
	}
	return prefix, nil
}

func prefixCoveredBy(prefix netip.Prefix, covers []netip.Prefix) bool {
	return slices.ContainsFunc(covers, func(cover netip.Prefix) bool {
		return cover.Bits() <= prefix.Bits() && cover.Contains(prefix.Addr())
	})
}
