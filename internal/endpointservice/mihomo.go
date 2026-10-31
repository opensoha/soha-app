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
	mihomoVPNProxyName    = "soha-vpn"
)

type MihomoReadback struct {
	Mode            string `json:"mode,omitempty"`
	ProfileID       string `json:"profileId,omitempty"`
	ProfileRevision int    `json:"profileRevision,omitempty"`
	MixedPort       int    `json:"mixedPort,omitempty"`
	ControllerPort  int    `json:"controllerPort,omitempty"`
	DNSMode         string `json:"dnsMode,omitempty"`
	SelectedProxy   string `json:"selectedProxy,omitempty"`
	ProtectionHash  string `json:"protectionHash,omitempty"`
}

type MihomoRuntime interface {
	Apply(context.Context, MihomoConfiguration) (MihomoReadback, error)
	Disable(context.Context) error
}

type MihomoAppRuntime interface {
	ApplySubscription(context.Context, MihomoConfiguration, string, string) (MihomoAppStatus, error)
}

type CoordinatedExecutor struct {
	mu              sync.Mutex
	wireGuard       ConfigurationExecutor
	mihomo          MihomoRuntime
	mihomoActive    bool
	previousMihomo  *mihomoAppliedState
	appStatePath    string
	appClearPending bool
	appDesired      *MihomoConfiguration
	appStatus       MihomoAppStatus
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
	// No live DIRECT connections may survive removal/replacement of VPN routes.
	if err := executor.quiesceMihomo(ctx); err != nil {
		return ApplyOutcome{Status: "rejected", ReadbackHash: executor.currentMihomoReadbackHash(), ReasonCode: "mihomo_disable_failed"}
	}
	executor.appDesired, executor.appStatus = nil, MihomoAppStatus{}
	wireGuard := executor.wireGuard.Apply(ctx, desired, now)
	if wireGuard.Status != "applied" {
		return ApplyOutcome{Status: "rejected", ReadbackHash: combinedReadbackHash(wireGuard.ReadbackHash, mihomoReadbackHash(MihomoReadback{})), ReasonCode: fallback(wireGuard.ReasonCode, "wireguard_apply_failed")}
	}
	if desired.Mihomo != nil {
		configuration := cloneMihomoConfiguration(*desired.Mihomo)
		configuration.EnforcementUntil = desired.ValidUntil
		if desired.WireGuard != nil {
			configuration.DNSRecords = desired.WireGuard.DNSRecords
			configuration.VPNRoutes = slices.Clone(desired.WireGuard.Routes)
			if err := executor.bindMihomoVPN(ctx, &configuration); err != nil {
				return ApplyOutcome{Status: "rejected", ReadbackHash: combinedReadbackHash(wireGuard.ReadbackHash, mihomoReadbackHash(MihomoReadback{})), ReasonCode: "mihomo_vpn_binding_unavailable"}
			}
		}
		desired.Mihomo = &configuration
	}

	if desired.Mihomo != nil && (desired.Mihomo.Protection == nil || desired.Mihomo.Protection.PolicyVersion != desired.PolicyVersion) {
		return executor.recoverMihomo(ctx, "mihomo_policy_version_mismatch")
	}
	mihomo := executor.applyMihomo(ctx, desired)
	return ApplyOutcome{Status: mihomo.Status, ReadbackHash: combinedReadbackHash(wireGuard.ReadbackHash, mihomo.ReadbackHash), ReasonCode: mihomo.ReasonCode}
}

func (executor *CoordinatedExecutor) Verify(ctx context.Context, desired ConfigurationDesired, now time.Time) ApplyOutcome {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	verifier, ok := executor.wireGuard.(interface {
		Verify(context.Context, ConfigurationDesired, time.Time) ApplyOutcome
	})
	if !ok {
		return executor.recoverMihomo(ctx, "endpoint_readback_unavailable")
	}
	wireGuard := verifier.Verify(ctx, desired, now)
	if wireGuard.Status != "applied" {
		return executor.recoverMihomo(ctx, fallback(wireGuard.ReasonCode, "endpoint_readback_mismatch"))
	}
	if executor.mihomo == nil {
		if desired.Mihomo == nil {
			return wireGuard
		}
		return executor.recoverMihomo(ctx, "mihomo_runtime_unavailable")
	}
	mihomo, ok := executor.mihomo.(interface {
		Verify(context.Context, *MihomoConfiguration) error
	})
	if !ok {
		return executor.recoverMihomo(ctx, "mihomo_readback_unavailable")
	}
	var configuration *MihomoConfiguration
	if executor.previousMihomo != nil {
		current := cloneMihomoConfiguration(executor.previousMihomo.Configuration)
		if err := executor.bindMihomoVPN(ctx, &current); err != nil {
			return executor.recoverMihomo(ctx, "mihomo_vpn_binding_unavailable")
		}
		configuration = &current
	}
	if err := mihomo.Verify(ctx, configuration); err != nil {
		return executor.recoverMihomo(ctx, "mihomo_readback_mismatch")
	}
	return ApplyOutcome{Status: "applied", ReadbackHash: combinedReadbackHash(wireGuard.ReadbackHash, executor.currentMihomoReadbackHash())}
}

func (executor *CoordinatedExecutor) Disable(ctx context.Context) error {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if err := executor.quiesceMihomo(ctx); err != nil {
		return err
	}
	executor.appDesired, executor.appStatus = nil, MihomoAppStatus{}
	return executor.wireGuard.Disable(ctx)
}

func (executor *CoordinatedExecutor) quiesceMihomo(ctx context.Context) error {
	if executor.mihomo != nil {
		if err := executor.mihomo.Disable(ctx); err != nil {
			return err
		}
	}
	executor.mihomoActive, executor.previousMihomo = false, nil
	return nil
}

func (executor *CoordinatedExecutor) bindMihomoVPN(ctx context.Context, configuration *MihomoConfiguration) error {
	if len(configuration.VPNRoutes) == 0 {
		if configuration.VPNInterface != "" {
			return errors.New("VPN binding without routes")
		}
		return nil
	}
	binder, ok := executor.wireGuard.(interface {
		VPNBinding(context.Context) (string, []string, error)
	})
	if !ok {
		return errors.New("VPN binding readback is unavailable")
	}
	name, routes, err := binder.VPNBinding(ctx)
	if err != nil || !slices.Equal(routes, configuration.VPNRoutes) {
		return errors.New("VPN binding does not match authorized routes")
	}
	configuration.VPNInterface = name
	return nil
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
		return executor.recoverMihomo(ctx, "unsafe_mihomo_configuration")
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
	if executor.appClearPending || errors.Is(err, os.ErrNotExist) || err == nil && (state.Cleared || state.ProfileID != configuration.ProfileID || state.ProfileRevision != configuration.ProfileRevision) {
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
	cleared := mihomoAppState{Version: mihomoAppStateVersion, ProfileID: configuration.ProfileID, ProfileRevision: configuration.ProfileRevision, Cleared: true}
	executor.appClearPending = true
	if err := saveMihomoAppState(executor.appStatePath, cleared); err != nil {
		removeErr := os.Remove(executor.appStatePath)
		if errors.Is(removeErr, os.ErrNotExist) {
			removeErr = nil
		}
		disableErr := executor.mihomo.Disable(ctx)
		if disableErr == nil {
			executor.mihomoActive, executor.previousMihomo = false, nil
			executor.appStatus = mihomoAppStatus(configuration, false, "", nil)
		}
		return executor.currentMihomoAppStatus(), errors.Join(err, removeErr, disableErr)
	}
	if executor.mihomo != nil {
		if err := executor.mihomo.Disable(ctx); err != nil {
			return executor.currentMihomoAppStatus(), err
		}
	}
	executor.mihomoActive, executor.previousMihomo = false, nil
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
	if err != nil || executor.appClearPending || state.Cleared || state.ProfileID != configuration.ProfileID || state.ProfileRevision != configuration.ProfileRevision {
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
	if err := executor.quiesceMihomo(ctx); err != nil {
		return executor.currentMihomoAppStatus(), err
	}
	if err := executor.bindMihomoVPN(ctx, &configuration); err != nil {
		executor.recoverMihomo(ctx, "mihomo_vpn_binding_unavailable")
		return executor.currentMihomoAppStatus(), err
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
	executor.appClearPending = false
	return executor.currentMihomoAppStatus(), nil
}

func (executor *CoordinatedExecutor) recoverMihomo(ctx context.Context, reason string) ApplyOutcome {
	// Old files may be retained for repair, but old policy must never be restarted.
	if err := executor.quiesceMihomo(ctx); err != nil {
		reason = "mihomo_disable_failed"
	}
	executor.appDesired, executor.appStatus = nil, MihomoAppStatus{}
	return ApplyOutcome{Status: "rejected", ReadbackHash: executor.currentMihomoReadbackHash(), ReasonCode: reason}
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
	configuration.VPNRoutes = slices.Clone(configuration.VPNRoutes)
	if configuration.Protection != nil {
		protection := *configuration.Protection
		protection.CIDRs = slices.Clone(protection.CIDRs)
		protection.Hosts = slices.Clone(protection.Hosts)
		configuration.Protection = &protection
	}
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
	if configuration.SourceType == "manual_node" {
		configuration.SelectedProxy = mihomoManualProxyName
	}
	return MihomoReadback{
		Mode: configuration.Mode, ProfileID: configuration.ProfileID, ProfileRevision: configuration.ProfileRevision,
		MixedPort: configuration.MixedPort, ControllerPort: configuration.ControllerPort, DNSMode: configuration.DNSMode,
		SelectedProxy:  configuration.SelectedProxy,
		ProtectionHash: mihomoProtectionHash(configuration),
	}
}

type MihomoController struct {
	egress    *mihomoEgress
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
		controller.applied = expectedMihomoReadback(configuration)
		controller.applied.SelectedProxy = status.SelectedProxy
	}
	return status, err
}

func (controller *MihomoController) applySource(ctx context.Context, configuration MihomoConfiguration, subscriptionURL, selectedProxy string) (status MihomoAppStatus, result error) {
	defer func() {
		if result != nil {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), requestTimeout)
			defer cancel()
			result = errors.Join(result, controller.disable(cleanupCtx))
		}
	}()
	if err := controller.disable(ctx); err != nil {
		return MihomoAppStatus{}, err
	}
	if err := prepareMihomoBootstrap(ctx, &configuration, subscriptionURL); err != nil {
		return MihomoAppStatus{}, err
	}
	release, err := controller.prepareEgress(&configuration)
	if err != nil {
		return MihomoAppStatus{}, err
	}
	defer release()
	payload, err := renderMihomoConfiguration(configuration, subscriptionURL, controller.address, controller.authority, controller.secret)
	if err != nil {
		return MihomoAppStatus{}, err
	}
	raw, _ := json.Marshal(struct {
		Payload string `json:"payload"`
	}{payload})
	release()
	if err := controller.request(ctx, http.MethodPut, "/configs?force=true", raw, http.StatusNoContent, nil); err != nil {
		return MihomoAppStatus{}, err
	}
	group, err := controller.proxyGroup(ctx, configuration)
	if err != nil {
		return MihomoAppStatus{}, err
	}
	if selectedProxy == "" {
		if slices.Contains(group.All, group.Now) {
			selectedProxy = group.Now
		} else {
			selectedProxy = group.All[0]
		}
	}
	if !slices.Contains(group.All, selectedProxy) {
		return MihomoAppStatus{}, errors.New("mihomo selected proxy is unavailable")
	}
	raw, _ = json.Marshal(struct {
		Name string `json:"name"`
	}{selectedProxy})
	if err := controller.request(ctx, http.MethodPut, "/proxies/"+url.PathEscape(configuration.SelectorGroup), raw, http.StatusNoContent, nil); err != nil {
		return MihomoAppStatus{}, err
	}
	if err := controller.verifyRules(ctx, mihomoRules(configuration)); err != nil {
		return MihomoAppStatus{}, err
	}
	if err := controller.verifyListener(ctx, 0, mihomoIPv6(configuration)); err != nil {
		return MihomoAppStatus{}, err
	}
	if err := controller.verifyEgress(ctx); err != nil {
		return MihomoAppStatus{}, err
	}
	// Open the only ingress after inspecting the staged rules and actual nodes.
	raw, _ = json.Marshal(map[string]int{"mixed-port": configuration.MixedPort})
	if err := controller.request(ctx, http.MethodPatch, "/configs", raw, http.StatusNoContent, nil); err != nil {
		return MihomoAppStatus{}, err
	}
	if err := controller.verifyListener(ctx, configuration.MixedPort, mihomoIPv6(configuration)); err != nil {
		return MihomoAppStatus{}, err
	}
	if err := controller.verifyRules(ctx, mihomoRules(configuration)); err != nil {
		return MihomoAppStatus{}, err
	}
	group, err = controller.proxyGroup(ctx, configuration)
	if err != nil || group.Now != selectedProxy {
		return MihomoAppStatus{}, errors.New("mihomo selector readback changed")
	}
	return mihomoAppStatus(configuration, true, selectedProxy, group.All), nil
}

func (controller *MihomoController) Disable(ctx context.Context) error {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.disable(ctx)
}

func (controller *MihomoController) disable(ctx context.Context) error {
	gateErr := controller.egress.close()
	controller.egress = nil
	payload := fmt.Sprintf("mixed-port: 0\nport: 0\nsocks-port: 0\nredir-port: 0\ntproxy-port: 0\nallow-lan: false\nbind-address: %s\nmode: rule\nipv6: false\nexternal-controller: %s\nsecret: %s\ntun:\n  enable: false\ndns:\n  enable: false\nproxies: []\nproxy-groups: []\nrules:\n  - MATCH,REJECT\n", yamlString(controller.address), yamlString(controller.authority), yamlString(controller.secret))
	raw, _ := json.Marshal(struct {
		Payload string `json:"payload"`
	}{payload})
	putErr := controller.request(ctx, http.MethodPut, "/configs?force=true", raw, http.StatusNoContent, nil)
	closeErr := controller.closeConnections(ctx)
	listenerErr := controller.verifyListener(ctx, 0)
	rulesErr := controller.verifyRules(ctx, []mihomoRule{{Type: "Match", Proxy: "REJECT"}})
	if err := errors.Join(gateErr, putErr, closeErr, listenerErr, rulesErr); err != nil {
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
	output.WriteString("mixed-port: 0\nport: 0\nsocks-port: 0\nredir-port: 0\ntproxy-port: 0\n")
	fmt.Fprintf(&output, "allow-lan: false\nbind-address: %s\nmode: rule\nlog-level: warning\nipv6: %t\nexternal-controller: %s\nsecret: %s\ntun:\n  enable: false\n", yamlString(controllerAddress), mihomoIPv6(configuration), yamlString(controllerAuthority), yamlString(secret))
	if len(configuration.DNSRecords) > 0 {
		output.WriteString("hosts:\n")
		for _, record := range configuration.DNSRecords {
			if !record.ExpiresAt.After(time.Now()) || !record.ExpiresAt.After(configuration.EnforcementUntil.Add(-time.Second)) || len(record.Addresses) == 0 {
				return "", errors.New("site DNS record expired")
			}
			raw, _ := json.Marshal(record.Addresses)
			fmt.Fprintf(&output, "  %s: %s\n", yamlString(record.Hostname), raw)
		}
	}
	if configuration.DNSMode == "fake_ip" {
		fmt.Fprintf(&output, "dns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-range: %s\n  nameserver:\n    - system\n", yamlString(configuration.FakeIPRange))
	} else {
		output.WriteString("dns:\n  enable: false\n")
	}
	if configuration.GuardPort < 1 || configuration.GuardProxyPort < 1 || configuration.GuardDirectPort < 1 || len(configuration.GuardProxySecret) < 32 || len(configuration.GuardDirectSecret) < 32 {
		return "", errors.New("mihomo egress guard is missing")
	}
	fmt.Fprintf(&output, "listeners:\n  - name: soha-backend-proxy\n    type: socks\n    listen: 127.0.0.1\n    port: %d\n    udp: false\n    proxy: %s\n    users:\n      - username: proxy\n        password: %s\n  - name: soha-backend-direct\n    type: socks\n    listen: 127.0.0.1\n    port: %d\n    udp: false\n    proxy: DIRECT\n    users:\n      - username: direct\n        password: %s\n", configuration.GuardProxyPort, yamlString(configuration.SelectorGroup), yamlString(configuration.GuardProxySecret), configuration.GuardDirectPort, yamlString(configuration.GuardDirectSecret))
	output.WriteString("proxies:\n")
	for _, guard := range []struct{ name, user, secret string }{{mihomoGuardProxyName, "proxy", configuration.GuardProxySecret}, {mihomoGuardDirectName, "direct", configuration.GuardDirectSecret}} {
		fmt.Fprintf(&output, "  - name: %s\n    type: http\n    server: 127.0.0.1\n    port: %d\n    username: %s\n    password: %s\n", yamlString(guard.name), configuration.GuardPort, yamlString(guard.user), yamlString(guard.secret))
	}

	if len(configuration.VPNRoutes) > 0 {
		fmt.Fprintf(&output, "  - name: %s\n    type: direct\n    interface-name: %s\n    ip-version: dual\n", yamlString(mihomoVPNProxyName), yamlString(configuration.VPNInterface))
	}
	if len(configuration.BootstrapNodes) == 0 {
		return "", errors.New("proxy transport nodes were not validated")
	}
	for _, node := range configuration.BootstrapNodes {
		raw, err := json.Marshal(node)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&output, "  - %s\n", raw)
	}
	fmt.Fprintf(&output, "proxy-groups:\n  - name: %s\n    type: select\n    proxies:\n", yamlString(configuration.SelectorGroup))
	for _, node := range configuration.BootstrapNodes {
		fmt.Fprintf(&output, "      - %s\n", yamlString(fmt.Sprint(node["name"])))
	}
	output.WriteString("rules:\n")

	for _, rule := range mihomoRules(configuration) {
		fmt.Fprintf(&output, "  - %s\n", yamlString(rule.configurationLine()))
	}
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
		if err != nil || !fakeIP.Addr().Is4() {
			return errors.New("fake-IP range must be IPv4")
		}
	default:
		return errors.New("invalid mihomo DNS mode")
	}
	if err := validateMihomoProtection(configuration, fakeIP); err != nil {
		return err
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
	if err != nil || prefix.Addr().Is4In6() || !prefix.Addr().IsGlobalUnicast() || prefix != prefix.Masked() || prefix.Bits() == 0 || prefix.String() != raw {
		return netip.Prefix{}, errors.New("invalid mihomo IP prefix")
	}
	return prefix, nil
}

func prefixCoveredBy(prefix netip.Prefix, covers []netip.Prefix) bool {
	return slices.ContainsFunc(covers, func(cover netip.Prefix) bool {
		return cover.Bits() <= prefix.Bits() && cover.Contains(prefix.Addr())
	})
}
