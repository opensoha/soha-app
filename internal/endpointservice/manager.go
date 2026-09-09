package endpointservice

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	randv2 "math/rand/v2"
	"slices"
	"sync"
	"time"
)

const (
	StateDisconnected = "disconnected"
	StateConnecting   = "connecting"
	StateConnected    = "connected"
	StateDegraded     = "degraded"
	shutdownTimeout   = 10 * time.Second
	heartbeatRetryMax = 30 * time.Second
)

type RuntimeControl interface {
	Connect(context.Context, VPNConnectRequest) (VPNConnectResult, error)
	Configuration(context.Context) (RuntimeMessage, error)
	MihomoSource(context.Context, string) (MihomoSource, error)
	Report(context.Context, ConfigurationApplied) error
	Renew(context.Context, LeaseRenewRequest) (LeaseRenewResult, error)
	Revoke(context.Context, LeaseRevoke) error
}

type ConfigurationExecutor interface {
	Apply(context.Context, ConfigurationDesired, time.Time) ApplyOutcome
	Disable(context.Context) error
}

type MihomoAppCoordinator interface {
	MihomoAppStatus() (MihomoAppStatus, error)
	ConfigureMihomoApp(context.Context, MihomoAppInput) (MihomoAppStatus, error)
	SelectMihomoApp(context.Context, string) (MihomoAppStatus, error)
	RefreshMihomoApp(context.Context) (MihomoAppStatus, error)
	ClearMihomoApp(context.Context) (MihomoAppStatus, error)
}

type Telemetry interface {
	Heartbeat(context.Context, Status) error
}

type ManagerOptions struct {
	RuntimeID         string
	DeviceID          string
	PollInterval      time.Duration
	HeartbeatInterval time.Duration
	RenewBefore       time.Duration
	MaxClockSkew      time.Duration
}

type ConnectInput struct {
	SiteID           string   `json:"siteId"`
	NetworkSpaceID   string   `json:"networkSpaceId"`
	GatewayID        string   `json:"gatewayId,omitempty"`
	Mode             string   `json:"mode"`
	ResourceIDs      []string `json:"resourceIds"`
	AccessGrantID    string   `json:"accessGrantId,omitempty"`
	AccessGrantToken string   `json:"accessGrantToken,omitempty"`
}

type Status struct {
	State                 string    `json:"state"`
	RuntimeID             string    `json:"runtimeId"`
	DeviceID              string    `json:"deviceId"`
	SiteID                string    `json:"siteId,omitempty"`
	NetworkSpaceID        string    `json:"networkSpaceId,omitempty"`
	Mode                  string    `json:"mode,omitempty"`
	ResourceIDs           []string  `json:"resourceIds,omitempty"`
	SessionID             string    `json:"sessionId,omitempty"`
	GatewayID             string    `json:"gatewayId,omitempty"`
	ConfigurationVersion  int       `json:"configurationVersion"`
	PolicyVersion         int       `json:"policyVersion"`
	ValidUntil            time.Time `json:"validUntil,omitempty"`
	MihomoMode            string    `json:"mihomoMode,omitempty"`
	MihomoProfileID       string    `json:"mihomoProfileId,omitempty"`
	MihomoProfileRevision int       `json:"mihomoProfileRevision,omitempty"`
	UptimeSeconds         int64     `json:"uptimeSeconds"`
	Diagnostic            string    `json:"diagnostic,omitempty"`
}

type Manager struct {
	options   ManagerOptions
	control   RuntimeControl
	executor  ConfigurationExecutor
	telemetry Telemetry
	logger    *slog.Logger
	startedAt time.Time
	now       func() time.Time

	intervalJitter func(time.Duration) time.Duration
	heartbeatWait  func(context.Context, time.Duration) bool

	operationMu       sync.Mutex
	stateMu           sync.RWMutex
	pollInterval      time.Duration
	heartbeatInterval time.Duration
	status            Status
	leaseIDs          []string
	sessionUntil      time.Time
	nextRenewAt       time.Time
	appliedVersion    int
	disabled          bool
	cleanupReason     string
}

func NewManager(options ManagerOptions, control RuntimeControl, executor ConfigurationExecutor, telemetry Telemetry, logger *slog.Logger) (*Manager, error) {
	if !identifierPattern.MatchString(options.RuntimeID) || !identifierPattern.MatchString(options.DeviceID) || control == nil || executor == nil || logger == nil || options.PollInterval <= 0 || options.PollInterval > 5*time.Minute || options.HeartbeatInterval <= 0 || options.HeartbeatInterval > 5*time.Minute || options.RenewBefore <= 0 || options.RenewBefore > 2*time.Minute || options.MaxClockSkew <= 0 || options.MaxClockSkew > 5*time.Minute {
		return nil, errors.New("endpoint manager dependencies and intervals are invalid")
	}
	now := time.Now
	return &Manager{options: options, control: control, executor: executor, telemetry: telemetry, logger: logger, now: now, startedAt: now().UTC(), intervalJitter: runtimeIntervalJitter, heartbeatWait: waitFor, pollInterval: options.PollInterval, heartbeatInterval: options.HeartbeatInterval, disabled: true, status: Status{State: StateDisconnected, RuntimeID: options.RuntimeID, DeviceID: options.DeviceID}}, nil
}

func (manager *Manager) Connect(ctx context.Context, input ConnectInput) (Status, error) {
	manager.operationMu.Lock()
	defer manager.operationMu.Unlock()
	if input.Mode == "" {
		input.Mode = "external_vpn"
	}
	if !identifierPattern.MatchString(input.SiteID) || !identifierPattern.MatchString(input.NetworkSpaceID) || (input.GatewayID != "" && !identifierPattern.MatchString(input.GatewayID)) || !validConnectScope(input.Mode, input.ResourceIDs, input.AccessGrantID, input.AccessGrantToken) {
		return manager.Status(), errors.New("VPN connection scope is invalid")
	}
	input.ResourceIDs = slices.Clone(input.ResourceIDs)
	slices.Sort(input.ResourceIDs)
	manager.stateMu.RLock()
	active := manager.status.SessionID != "" || manager.cleanupReason != ""
	manager.stateMu.RUnlock()
	if active {
		return manager.Status(), errors.New("endpoint session must be disconnected before reconnecting")
	}
	manager.update(func(status *Status) {
		status.State, status.Diagnostic = StateConnecting, ""
		status.SiteID, status.NetworkSpaceID = input.SiteID, input.NetworkSpaceID
		status.Mode, status.ResourceIDs = input.Mode, slices.Clone(input.ResourceIDs)
	})
	result, err := manager.control.Connect(ctx, VPNConnectRequest{RequestID: randomID(), SiteID: input.SiteID, NetworkSpaceID: input.NetworkSpaceID, GatewayID: input.GatewayID, Mode: input.Mode, ResourceIDs: slices.Clone(input.ResourceIDs), AccessGrantID: input.AccessGrantID, AccessGrantToken: input.AccessGrantToken})
	if err != nil {
		manager.degrade("vpn_connect_failed")
		return manager.Status(), fmt.Errorf("request VPN connection: %w", err)
	}
	if result.Decision != "allow" || !identifierPattern.MatchString(result.SessionID) || !identifierPattern.MatchString(result.GatewayID) || result.ConfigurationVersion < 1 || result.PolicyVersion < 1 || !validLeaseShape(input.Mode, len(result.NetworkLeases), len(result.ResourceLeases)) || !result.ValidUntil.After(manager.now().UTC()) {
		manager.update(func(status *Status) {
			status.State, status.Diagnostic = StateDisconnected, fallback(result.ReasonCode, "authorization_denied")
		})
		return manager.Status(), fmt.Errorf("VPN connection denied: %s", fallback(result.ReasonCode, "authorization_denied"))
	}
	leaseIDs := leaseIDs(result.NetworkLeases, result.ResourceLeases)
	if len(leaseIDs) != len(result.NetworkLeases)+len(result.ResourceLeases) {
		manager.update(func(status *Status) { status.State, status.Diagnostic = StateDisconnected, "invalid_leases" })
		return manager.Status(), errors.New("network control returned invalid lease IDs")
	}
	manager.stateMu.Lock()
	manager.status.SessionID, manager.status.GatewayID = result.SessionID, result.GatewayID
	manager.status.ConfigurationVersion, manager.status.PolicyVersion = result.ConfigurationVersion, result.PolicyVersion
	manager.sessionUntil = result.ValidUntil.UTC()
	manager.leaseIDs = leaseIDs
	manager.nextRenewAt = renewalTime(manager.now().UTC(), manager.sessionUntil, manager.options.RenewBefore)
	manager.stateMu.Unlock()
	if err := manager.syncConfiguration(ctx); err != nil {
		_, cleanupErr := manager.disconnectLocked(ctx, "connect_failed")
		return manager.Status(), errors.Join(err, cleanupErr)
	}
	return manager.Status(), nil
}

func (manager *Manager) Disconnect(ctx context.Context) (Status, error) {
	manager.operationMu.Lock()
	defer manager.operationMu.Unlock()
	return manager.disconnectLocked(ctx, "user_disconnected")
}

func (manager *Manager) MihomoAppStatus() (MihomoAppStatus, error) {
	coordinator, ok := manager.executor.(MihomoAppCoordinator)
	if !ok {
		return MihomoAppStatus{}, errors.New("mihomo app subscription is unavailable")
	}
	return coordinator.MihomoAppStatus()
}

func (manager *Manager) ConfigureMihomoApp(ctx context.Context, input MihomoAppInput) (MihomoAppStatus, error) {
	manager.operationMu.Lock()
	defer manager.operationMu.Unlock()
	coordinator, ok := manager.executor.(MihomoAppCoordinator)
	if !ok {
		return MihomoAppStatus{}, errors.New("mihomo app subscription is unavailable")
	}
	return coordinator.ConfigureMihomoApp(ctx, input)
}

func (manager *Manager) SelectMihomoApp(ctx context.Context, selectedProxy string) (MihomoAppStatus, error) {
	manager.operationMu.Lock()
	defer manager.operationMu.Unlock()
	coordinator, ok := manager.executor.(MihomoAppCoordinator)
	if !ok {
		return MihomoAppStatus{}, errors.New("mihomo app subscription is unavailable")
	}
	return coordinator.SelectMihomoApp(ctx, selectedProxy)
}

func (manager *Manager) RefreshMihomoApp(ctx context.Context) (MihomoAppStatus, error) {
	manager.operationMu.Lock()
	defer manager.operationMu.Unlock()
	coordinator, ok := manager.executor.(MihomoAppCoordinator)
	if !ok {
		return MihomoAppStatus{}, errors.New("mihomo app subscription is unavailable")
	}
	return coordinator.RefreshMihomoApp(ctx)
}

func (manager *Manager) ClearMihomoApp(ctx context.Context) (MihomoAppStatus, error) {
	manager.operationMu.Lock()
	defer manager.operationMu.Unlock()
	coordinator, ok := manager.executor.(MihomoAppCoordinator)
	if !ok {
		return MihomoAppStatus{}, errors.New("mihomo app subscription is unavailable")
	}
	return coordinator.ClearMihomoApp(ctx)
}

func (manager *Manager) disconnectLocked(ctx context.Context, reason string) (Status, error) {
	manager.stateMu.RLock()
	sessionID, leaseIDs := manager.status.SessionID, slices.Clone(manager.leaseIDs)
	manager.stateMu.RUnlock()
	localErr := manager.executor.Disable(ctx)
	var remoteErr error
	if sessionID != "" && len(leaseIDs) != 0 {
		remoteErr = manager.control.Revoke(ctx, LeaseRevoke{SessionID: sessionID, LeaseIDs: leaseIDs, ReasonCode: reason, EffectiveAt: manager.now().UTC()})
	}
	manager.stateMu.Lock()
	manager.disabled = localErr == nil
	if localErr != nil || remoteErr != nil {
		manager.status.State, manager.status.Diagnostic = StateDegraded, "disconnect_incomplete"
		manager.cleanupReason = reason
	} else {
		manager.cleanupReason = ""
		manager.leaseIDs = nil
		manager.sessionUntil, manager.nextRenewAt = time.Time{}, time.Time{}
		manager.appliedVersion = 0
		manager.status = Status{State: StateDisconnected, RuntimeID: manager.options.RuntimeID, DeviceID: manager.options.DeviceID}
	}
	status := manager.status
	manager.stateMu.Unlock()
	return status, errors.Join(localErr, remoteErr)
}

func (manager *Manager) Cycle(ctx context.Context) error {
	manager.operationMu.Lock()
	defer manager.operationMu.Unlock()
	now := manager.now().UTC()
	manager.stateMu.RLock()
	cleanupReason := manager.cleanupReason
	active := manager.status.SessionID != ""
	expired := (active || !manager.disabled) && !manager.status.ValidUntil.IsZero() && !manager.status.ValidUntil.After(now)
	renew := active && !manager.nextRenewAt.IsZero() && !manager.nextRenewAt.After(now)
	manager.stateMu.RUnlock()
	if cleanupReason != "" {
		_, err := manager.disconnectLocked(ctx, cleanupReason)
		return err
	}
	if expired {
		_, err := manager.disconnectLocked(ctx, "configuration_expired")
		return err
	}
	if active && renew {
		if err := manager.renew(ctx, now); err != nil {
			manager.degrade("lease_renewal_failed")
			return err
		}
	}
	return manager.syncConfiguration(ctx)
}

func (manager *Manager) Run(ctx context.Context) error {
	poll := time.NewTimer(0)
	defer poll.Stop()
	var heartbeatDone <-chan struct{}
	if manager.telemetry != nil {
		done := make(chan struct{})
		heartbeatDone = done
		go func() {
			defer close(done)
			manager.runHeartbeats(ctx)
		}()
	}
	defer func() {
		if heartbeatDone != nil {
			<-heartbeatDone
		}
	}()
	for {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
			_, err := manager.Disconnect(shutdownCtx)
			cancel()
			return err
		case <-poll.C:
			if err := manager.Cycle(ctx); err != nil && ctx.Err() == nil {
				manager.logger.Warn("endpoint network cycle failed", "event", "endpoint_network.cycle.failed", "error", err.Error())
			}
			poll.Reset(manager.nextPollDelay(manager.now().UTC()))
		}
	}
}

func (manager *Manager) runHeartbeats(ctx context.Context) {
	delay, retry := time.Duration(0), time.Second
	for {
		if delay > 0 && !manager.heartbeatWait(ctx, manager.intervalJitter(delay)) {
			return
		}
		if ctx.Err() != nil {
			return
		}
		if err := manager.telemetry.Heartbeat(ctx, manager.Status()); err != nil {
			if ctx.Err() != nil {
				return
			}
			manager.logger.Warn("endpoint heartbeat failed", "event", "endpoint_network.heartbeat.failed", "error", err.Error())
			delay, retry = retry, min(retry*2, heartbeatRetryMax)
			continue
		}
		_, delay = manager.intervals()
		retry = time.Second
	}
}

func (manager *Manager) nextPollDelay(now time.Time) time.Duration {
	poll, _ := manager.intervals()
	delay := manager.intervalJitter(poll)
	manager.stateMu.RLock()
	validUntil := manager.status.ValidUntil
	manager.stateMu.RUnlock()
	if untilExpiry := validUntil.Sub(now); !validUntil.IsZero() && untilExpiry > 0 && untilExpiry < delay {
		return untilExpiry
	}
	return delay
}

func (manager *Manager) applyRuntimeIntervals(intervals *RuntimeIntervals) {
	if intervals == nil || !validRuntimeInterval(intervals.HeartbeatIntervalSeconds) || !validRuntimeInterval(intervals.ConfigurationPollIntervalSeconds) {
		return
	}
	manager.stateMu.Lock()
	manager.heartbeatInterval = time.Duration(intervals.HeartbeatIntervalSeconds) * time.Second
	manager.pollInterval = time.Duration(intervals.ConfigurationPollIntervalSeconds) * time.Second
	manager.stateMu.Unlock()
}

func (manager *Manager) intervals() (time.Duration, time.Duration) {
	manager.stateMu.RLock()
	poll, heartbeat := manager.pollInterval, manager.heartbeatInterval
	manager.stateMu.RUnlock()
	if poll <= 0 {
		poll = manager.options.PollInterval
	}
	if heartbeat <= 0 {
		heartbeat = manager.options.HeartbeatInterval
	}
	return poll, heartbeat
}

func validRuntimeInterval(seconds int) bool {
	return seconds >= minRuntimeIntervalSeconds && seconds <= maxRuntimeIntervalSeconds
}

func runtimeIntervalJitter(delay time.Duration) time.Duration {
	span := delay / 5
	if span == 0 {
		return delay
	}
	return delay - span + time.Duration(randv2.Int64N(int64(2*span)+1))
}

func waitFor(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (manager *Manager) Status() Status {
	manager.stateMu.RLock()
	status := manager.status
	manager.stateMu.RUnlock()
	status.ResourceIDs = slices.Clone(status.ResourceIDs)
	status.UptimeSeconds = max(0, int64(manager.now().UTC().Sub(manager.startedAt)/time.Second))
	return status
}

func (manager *Manager) syncConfiguration(ctx context.Context) error {
	message, err := manager.control.Configuration(ctx)
	if err != nil {
		manager.degrade("control_unavailable")
		return fmt.Errorf("poll endpoint configuration: %w", err)
	}
	now := manager.now().UTC()
	if message.SchemaVersion != RuntimeSchemaVersion || message.MessageType != MessageConfiguration || message.ProducerID != "network-control" || message.RuntimeID != manager.options.RuntimeID || message.RuntimeKind != "endpoint" || message.OccurredAt.After(now.Add(manager.options.MaxClockSkew)) || !message.ExpiresAt.After(now) || !message.ExpiresAt.After(message.OccurredAt) {
		manager.degrade("invalid_configuration_message")
		return errors.New("network control returned an invalid endpoint configuration message")
	}
	var desired ConfigurationDesired
	if err := decodeStrict(message.Payload, &desired); err != nil || !message.ExpiresAt.Equal(desired.ValidUntil) {
		manager.degrade("invalid_configuration_payload")
		return errors.New("network control returned an invalid endpoint configuration payload")
	}
	if err := validateMihomoConfiguration(desired.Mihomo, desired.WireGuard, false); err != nil {
		manager.degrade("unsafe_mihomo_configuration")
		return errors.New("network control returned an unsafe mihomo configuration")
	}
	if desired.Mihomo != nil && desired.Mihomo.Mode == "managed_follow" {
		source, sourceErr := manager.control.MihomoSource(ctx, desired.Mihomo.ProfileID)
		if sourceErr != nil || source.ProfileID != desired.Mihomo.ProfileID || source.ProfileRevision != desired.Mihomo.ProfileRevision || desired.Mihomo.SourceType != "" && source.SourceType != desired.Mihomo.SourceType {
			manager.degrade("mihomo_source_unavailable")
			return errors.New("network control returned an invalid mihomo source")
		}
		desired.Mihomo.SourceType = source.SourceType
		desired.Mihomo.SubscriptionURL = source.SubscriptionURL
		desired.Mihomo.ManualNode = source.ManualNode
	}
	manager.applyRuntimeIntervals(desired.RuntimeIntervals)
	manager.stateMu.RLock()
	currentVersion, appliedVersion := manager.status.ConfigurationVersion, manager.appliedVersion
	manager.stateMu.RUnlock()
	if desired.ConfigurationVersion < currentVersion {
		manager.degrade("stale_configuration")
		return errors.New("network control returned a stale endpoint configuration")
	}
	if desired.ConfigurationVersion == appliedVersion {
		manager.update(func(status *Status) { applyDesiredStatus(status, desired) })
		return nil
	}
	outcome := manager.executor.Apply(ctx, desired, now)
	report := ConfigurationApplied{ConfigurationVersion: desired.ConfigurationVersion, PolicyVersion: desired.PolicyVersion, Status: outcome.Status, ReadbackHash: outcome.ReadbackHash, ReasonCode: outcome.ReasonCode}
	reportErr := manager.control.Report(ctx, report)
	if outcome.Status != "applied" {
		manager.degrade(fallback(outcome.ReasonCode, "endpoint_apply_failed"))
		return errors.Join(fmt.Errorf("endpoint configuration was %s", outcome.Status), reportErr)
	}
	manager.stateMu.Lock()
	applyDesiredStatus(&manager.status, desired)
	manager.appliedVersion = desired.ConfigurationVersion
	manager.disabled = desired.WireGuard == nil && desired.Mihomo == nil
	manager.leaseIDs = leaseIDs(desired.NetworkLeases, desired.ResourceLeases)
	manager.stateMu.Unlock()
	if reportErr != nil {
		manager.degrade("configuration_report_failed")
		return fmt.Errorf("report endpoint configuration: %w", reportErr)
	}
	return nil
}

func (manager *Manager) renew(ctx context.Context, now time.Time) error {
	manager.stateMu.RLock()
	request := LeaseRenewRequest{SessionID: manager.status.SessionID, LeaseIDs: slices.Clone(manager.leaseIDs), ObservedConfigurationVersion: manager.status.ConfigurationVersion}
	manager.stateMu.RUnlock()
	if request.SessionID == "" || request.ObservedConfigurationVersion < 1 || len(request.LeaseIDs) == 0 {
		return errors.New("endpoint session cannot be renewed before a configuration is applied")
	}
	result, err := manager.control.Renew(ctx, request)
	if err != nil {
		return fmt.Errorf("renew endpoint leases: %w", err)
	}
	leaseIDs := leaseIDs(result.NetworkLeases, result.ResourceLeases)
	if result.PolicyVersion < 1 || !result.ValidUntil.After(now) || intersects(request.LeaseIDs, result.RevokedLeaseIDs) || len(leaseIDs) != len(result.NetworkLeases)+len(result.ResourceLeases) || len(leaseIDs) == 0 {
		_ = manager.executor.Disable(ctx)
		manager.stateMu.Lock()
		manager.disabled = true
		manager.appliedVersion = 0
		manager.status.State, manager.status.Diagnostic = StateDegraded, "lease_revoked"
		manager.stateMu.Unlock()
		return errors.New("endpoint network lease was revoked")
	}
	manager.stateMu.Lock()
	manager.sessionUntil = result.ValidUntil.UTC()
	manager.nextRenewAt = renewalTime(now, manager.sessionUntil, manager.options.RenewBefore)
	manager.leaseIDs = leaseIDs
	manager.status.PolicyVersion = result.PolicyVersion
	manager.stateMu.Unlock()
	return nil
}

func applyDesiredStatus(status *Status, desired ConfigurationDesired) {
	status.ConfigurationVersion, status.PolicyVersion, status.ValidUntil = desired.ConfigurationVersion, desired.PolicyVersion, desired.ValidUntil.UTC()
	status.State, status.Diagnostic = StateDisconnected, ""
	status.MihomoMode, status.MihomoProfileID, status.MihomoProfileRevision = "", "", 0
	if desired.Mihomo != nil {
		status.MihomoMode, status.MihomoProfileID, status.MihomoProfileRevision = desired.Mihomo.Mode, desired.Mihomo.ProfileID, desired.Mihomo.ProfileRevision
	}
	if desired.WireGuard != nil || desired.Mihomo != nil {
		status.State = StateConnected
	}
}

func (manager *Manager) update(change func(*Status)) {
	manager.stateMu.Lock()
	change(&manager.status)
	manager.stateMu.Unlock()
}

func (manager *Manager) degrade(reason string) {
	manager.update(func(status *Status) { status.State, status.Diagnostic = StateDegraded, reason })
}

func renewalTime(now, validUntil time.Time, before time.Duration) time.Time {
	remaining := validUntil.Sub(now)
	if remaining <= 0 {
		return now
	}
	lead := min(before, remaining/3)
	return validUntil.Add(-lead)
}

func leaseIDs(networkLeases []NetworkLease, resourceLeases []ResourceLease) []string {
	ids := make([]string, 0, len(networkLeases)+len(resourceLeases))
	for _, lease := range networkLeases {
		if identifierPattern.MatchString(lease.ID) {
			ids = append(ids, lease.ID)
		}
	}
	for _, lease := range resourceLeases {
		if identifierPattern.MatchString(lease.ID) {
			ids = append(ids, lease.ID)
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

func validConnectScope(mode string, resourceIDs []string, accessGrantID, accessGrantToken string) bool {
	if len(resourceIDs) > 256 || !allIdentifiers(resourceIDs) {
		return false
	}
	switch mode {
	case "external_vpn":
		return len(resourceIDs) == 0 && accessGrantID == "" && accessGrantToken == ""
	case "internal_ztna", "external_vpn_ztna", "external_direct_ztna":
		decoded, err := base64.RawURLEncoding.DecodeString(accessGrantToken)
		return len(resourceIDs) > 0 && identifierPattern.MatchString(accessGrantID) && err == nil && len(decoded) == 32
	default:
		return false
	}
}

func validLeaseShape(mode string, networkLeases, resourceLeases int) bool {
	if networkLeases > 256 || resourceLeases > 512 {
		return false
	}
	switch mode {
	case "external_vpn":
		return networkLeases > 0 && resourceLeases == 0
	case "external_vpn_ztna":
		return networkLeases > 0 && resourceLeases > 0
	case "internal_ztna", "external_direct_ztna":
		return networkLeases == 0 && resourceLeases > 0
	default:
		return false
	}
}

func intersects(left, right []string) bool {
	for _, item := range left {
		if slices.Contains(right, item) {
			return true
		}
	}
	return false
}

func decodeStrict(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contains trailing data")
		}
		return err
	}
	return nil
}

func randomID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}

func fallback(value, fallbackValue string) string {
	if value == "" {
		return fallbackValue
	}
	return value
}
