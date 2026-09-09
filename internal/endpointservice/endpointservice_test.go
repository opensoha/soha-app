package endpointservice

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestExecutorApplyRollbackAndFailClosed(t *testing.T) {
	t.Parallel()
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	first := desiredConfiguration(privateKey.PublicKey(), peerKey.PublicKey(), 1, now.Add(5*time.Minute))
	second := desiredConfiguration(privateKey.PublicKey(), peerKey.PublicKey(), 2, now.Add(10*time.Minute))
	second.WireGuard.Routes = []string{"10.40.0.0/24"}
	second.WireGuard.Peers[0].AllowedIPs = []string{"10.40.0.0/24"}
	second.NetworkLeases[0].CIDRs = []string{"10.40.0.0/24"}
	second.WireGuard.FirewallRules[0].DestinationCIDR = "10.40.0.0/24"
	second.WireGuard.DNSServers = []string{"10.40.0.53"}

	system := &fakeSystem{}
	executor, err := NewExecutor(privateKey, system)
	if err != nil {
		t.Fatal(err)
	}
	if outcome := executor.Apply(context.Background(), first, now); outcome.Status != "applied" {
		t.Fatalf("first Apply() = %#v", outcome)
	}
	system.applyErrAt = 2
	if outcome := executor.Apply(context.Background(), second, now); outcome.Status != "rolled-back" {
		t.Fatalf("second Apply() = %#v, want rolled-back", outcome)
	}
	if system.current.Routes[0] != "10.20.0.0/24" {
		t.Fatalf("rollback routes = %v", system.current.Routes)
	}

	freshSystem := &fakeSystem{applyErrAt: 1}
	fresh, err := NewExecutor(privateKey, freshSystem)
	if err != nil {
		t.Fatal(err)
	}
	if outcome := fresh.Apply(context.Background(), first, now); outcome.Status != "rejected" || freshSystem.disableCalls == 0 {
		t.Fatalf("first failed Apply() = %#v disableCalls=%d", outcome, freshSystem.disableCalls)
	}
}

func TestExecutorRejectsUnsafeEndpointConfiguration(t *testing.T) {
	t.Parallel()
	privateKey, _ := wgtypes.GeneratePrivateKey()
	peerKey, _ := wgtypes.GeneratePrivateKey()
	now := time.Now().UTC()
	desired := desiredConfiguration(privateKey.PublicKey(), peerKey.PublicKey(), 1, now.Add(time.Minute))
	desired.WireGuard.Routes = []string{"0.0.0.0/0"}
	desired.WireGuard.Peers[0].AllowedIPs = []string{"0.0.0.0/0"}
	desired.NetworkLeases[0].CIDRs = []string{"0.0.0.0/0"}

	executor, err := NewExecutor(privateKey, &fakeSystem{})
	if err != nil {
		t.Fatal(err)
	}
	outcome := executor.Apply(context.Background(), desired, now)
	if outcome.Status != "rejected" || outcome.ReasonCode != "unsafe_endpoint_configuration" {
		t.Fatalf("Apply() = %#v", outcome)
	}
}

func TestExecutorRejectsInvalidFirewallPort(t *testing.T) {
	t.Parallel()
	privateKey, _ := wgtypes.GeneratePrivateKey()
	peerKey, _ := wgtypes.GeneratePrivateKey()
	now := time.Now().UTC()
	desired := desiredConfiguration(privateKey.PublicKey(), peerKey.PublicKey(), 1, now.Add(time.Minute))
	desired.WireGuard.FirewallRules[0].Protocol = "tcp"
	desired.WireGuard.FirewallRules[0].Ports = []int{443, 443}

	executor, _ := NewExecutor(privateKey, &fakeSystem{})
	if outcome := executor.Apply(context.Background(), desired, now); outcome.Status != "rejected" {
		t.Fatalf("Apply() = %#v", outcome)
	}
}

func TestExecutorRejectsDNSOutsideAuthorizedRoutes(t *testing.T) {
	t.Parallel()
	privateKey, _ := wgtypes.GeneratePrivateKey()
	peerKey, _ := wgtypes.GeneratePrivateKey()
	now := time.Now().UTC()
	desired := desiredConfiguration(privateKey.PublicKey(), peerKey.PublicKey(), 1, now.Add(time.Minute))
	desired.WireGuard.DNSServers = []string{"1.1.1.1"}
	executor, _ := NewExecutor(privateKey, &fakeSystem{})
	if outcome := executor.Apply(context.Background(), desired, now); outcome.Status != "rejected" {
		t.Fatalf("Apply() = %#v", outcome)
	}
}

func TestExecutorAcceptsDirectZTNAResourceLease(t *testing.T) {
	t.Parallel()
	privateKey, _ := wgtypes.GeneratePrivateKey()
	peerKey, _ := wgtypes.GeneratePrivateKey()
	now := time.Now().UTC()
	desired := directZTNAConfiguration(privateKey.PublicKey(), peerKey.PublicKey(), 1, now.Add(time.Minute))
	executor, _ := NewExecutor(privateKey, &fakeSystem{})
	if outcome := executor.Apply(context.Background(), desired, now); outcome.Status != "applied" {
		t.Fatalf("Apply(direct ZTNA) = %#v", outcome)
	}

	desired.WireGuard.Routes = []string{"10.20.8.0/24"}
	desired.WireGuard.Peers[0].AllowedIPs = []string{"10.20.8.0/24"}
	if outcome := executor.Apply(context.Background(), desired, now); outcome.Status != "rejected" {
		t.Fatalf("Apply(overbroad direct ZTNA) = %#v", outcome)
	}
}

func TestManagerConnectRenewDisconnect(t *testing.T) {
	t.Parallel()
	privateKey, _ := wgtypes.GeneratePrivateKey()
	peerKey, _ := wgtypes.GeneratePrivateKey()
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	desired := desiredConfiguration(privateKey.PublicKey(), peerKey.PublicKey(), 7, now.Add(2*time.Minute))
	raw, _ := json.Marshal(desired)
	control := &fakeControl{
		connectResult: VPNConnectResult{RequestID: "request-1", Decision: "allow", ReasonCode: "policy_allowed", SessionID: "session-1", GatewayID: "gateway-1", ConfigurationVersion: 7, PolicyVersion: 3, ValidUntil: now.Add(2 * time.Minute), NetworkLeases: desired.NetworkLeases},
		configuration: RuntimeMessage{SchemaVersion: RuntimeSchemaVersion, MessageID: "message-1", MessageType: MessageConfiguration, ProducerID: "network-control", RuntimeID: "endpoint-1", RuntimeKind: "endpoint", OccurredAt: now, ExpiresAt: desired.ValidUntil, Payload: raw},
		renewResult:   LeaseRenewResult{PolicyVersion: 3, ValidUntil: now.Add(7 * time.Minute), NetworkLeases: desired.NetworkLeases, ResourceLeases: []ResourceLease{}, RevokedLeaseIDs: []string{}},
	}
	system := &fakeSystem{}
	executor, _ := NewExecutor(privateKey, system)
	manager, err := NewManager(ManagerOptions{RuntimeID: "endpoint-1", DeviceID: "device-1", PollInterval: time.Second, HeartbeatInterval: time.Minute, RenewBefore: 30 * time.Second, MaxClockSkew: time.Minute}, control, executor, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return now }

	status, err := manager.Connect(context.Background(), ConnectInput{SiteID: "site-1", NetworkSpaceID: "space-1", GatewayID: "gateway-b"})
	if err != nil || status.State != StateConnected || status.ConfigurationVersion != 7 || control.lastConnect.GatewayID != "gateway-b" {
		t.Fatalf("Connect() status=%#v err=%v", status, err)
	}
	manager.now = func() time.Time { return now.Add(100 * time.Second) }
	if err := manager.Cycle(context.Background()); err != nil {
		t.Fatalf("Cycle() = %v", err)
	}
	if control.renewCalls != 1 {
		t.Fatalf("renew calls = %d", control.renewCalls)
	}
	if _, err := manager.Disconnect(context.Background()); err != nil {
		t.Fatalf("Disconnect() = %v", err)
	}
	if control.revokeCalls != 1 || system.disableCalls == 0 || manager.Status().State != StateDisconnected {
		t.Fatalf("disconnect revoke=%d disable=%d status=%#v", control.revokeCalls, system.disableCalls, manager.Status())
	}
}

func TestManagerConnectsDirectZTNAAndRenewsResourceLease(t *testing.T) {
	t.Parallel()
	privateKey, _ := wgtypes.GeneratePrivateKey()
	peerKey, _ := wgtypes.GeneratePrivateKey()
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	desired := directZTNAConfiguration(privateKey.PublicKey(), peerKey.PublicKey(), 4, now.Add(2*time.Minute))
	raw, _ := json.Marshal(desired)
	control := &fakeControl{
		connectResult: VPNConnectResult{RequestID: "request-1", Decision: "allow", ReasonCode: "policy_allowed", SessionID: "session-1", GatewayID: "gateway-1", ConfigurationVersion: 4, PolicyVersion: 3, ValidUntil: desired.ValidUntil, NetworkLeases: []NetworkLease{}, ResourceLeases: desired.ResourceLeases},
		configuration: RuntimeMessage{SchemaVersion: RuntimeSchemaVersion, MessageID: "message-1", MessageType: MessageConfiguration, ProducerID: "network-control", RuntimeID: "endpoint-1", RuntimeKind: "endpoint", OccurredAt: now, ExpiresAt: desired.ValidUntil, Payload: raw},
		renewResult:   LeaseRenewResult{PolicyVersion: 3, ValidUntil: now.Add(7 * time.Minute), NetworkLeases: []NetworkLease{}, ResourceLeases: desired.ResourceLeases, RevokedLeaseIDs: []string{}},
	}
	executor, _ := NewExecutor(privateKey, &fakeSystem{})
	manager, _ := NewManager(ManagerOptions{RuntimeID: "endpoint-1", DeviceID: "device-1", PollInterval: time.Second, HeartbeatInterval: time.Minute, RenewBefore: 30 * time.Second, MaxClockSkew: time.Minute}, control, executor, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	manager.now = func() time.Time { return now }
	status, err := manager.Connect(context.Background(), ConnectInput{SiteID: "site-1", NetworkSpaceID: "space-1", Mode: "external_direct_ztna", ResourceIDs: []string{"resource-db"}, AccessGrantID: "grant-1", AccessGrantToken: testAccessGrantToken})
	if err != nil || status.State != StateConnected || status.Mode != "external_direct_ztna" || len(status.ResourceIDs) != 1 || control.lastConnect.Mode != "external_direct_ztna" || len(control.lastConnect.ResourceIDs) != 1 || control.lastConnect.AccessGrantID != "grant-1" || control.lastConnect.AccessGrantToken != testAccessGrantToken {
		t.Fatalf("Connect(direct ZTNA) status=%#v request=%#v err=%v", status, control.lastConnect, err)
	}
	manager.now = func() time.Time { return now.Add(100 * time.Second) }
	if err := manager.Cycle(context.Background()); err != nil || control.renewCalls != 1 {
		t.Fatalf("Cycle(direct ZTNA) renew=%d err=%v", control.renewCalls, err)
	}
	if _, err := manager.Disconnect(context.Background()); err != nil || len(control.lastRevoke.LeaseIDs) != 1 || control.lastRevoke.LeaseIDs[0] != "resource-lease" {
		t.Fatalf("Disconnect(direct ZTNA) revoke=%#v err=%v", control.lastRevoke, err)
	}
}

func TestManagerAppliesManagedMihomoWithoutVPNSession(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	desired := ConfigurationDesired{ConfigurationVersion: 5, PolicyVersion: 3, ValidUntil: now.Add(2 * time.Minute), AccessProfile: "full", ProtectedResourceIDs: []string{}, NetworkLeases: []NetworkLease{}, ResourceLeases: []ResourceLease{}, Mihomo: ptrMihomo(managedMihomoConfiguration(9090))}
	desired.Mihomo.SubscriptionURL = ""
	raw, _ := json.Marshal(desired)
	control := &fakeControl{
		configuration: RuntimeMessage{SchemaVersion: RuntimeSchemaVersion, MessageID: "message-1", MessageType: MessageConfiguration, ProducerID: "network-control", RuntimeID: "endpoint-1", RuntimeKind: "endpoint", OccurredAt: now, ExpiresAt: desired.ValidUntil, Payload: raw},
		source:        MihomoSource{ProfileID: desired.Mihomo.ProfileID, ProfileRevision: desired.Mihomo.ProfileRevision, SourceType: "managed_subscription", SubscriptionURL: "https://subscriptions.example.test/private?id=secret"},
	}
	executor := &fakeConfigurationExecutor{outcome: ApplyOutcome{Status: "applied", ReadbackHash: emptyReadbackHash()}}
	manager, err := NewManager(ManagerOptions{RuntimeID: "endpoint-1", DeviceID: "device-1", PollInterval: time.Second, HeartbeatInterval: time.Minute, RenewBefore: 30 * time.Second, MaxClockSkew: time.Minute}, control, executor, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return now }
	if err := manager.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	status := manager.Status()
	encoded, _ := json.Marshal(status)
	if status.State != StateConnected || status.MihomoMode != "managed_follow" || status.MihomoProfileID != desired.Mihomo.ProfileID || status.MihomoProfileRevision != 1 || control.sourceCalls != 1 || executor.applyCalls != 1 || executor.lastDesired.Mihomo == nil || executor.lastDesired.Mihomo.SubscriptionURL != control.source.SubscriptionURL || strings.Contains(string(encoded), "subscriptions.example.test") {
		t.Fatalf("status=%#v sourceCalls=%d apply=%#v JSON=%s", status, control.sourceCalls, executor.lastDesired, encoded)
	}
	if err := manager.Cycle(context.Background()); err != nil || executor.applyCalls != 1 {
		t.Fatalf("stable Cycle() applyCalls=%d err=%v", executor.applyCalls, err)
	}
}

func TestManagerUpdatesUnifiedIntervalsWithoutReapplyingConfiguration(t *testing.T) {
	now := time.Date(2026, 9, 4, 8, 0, 0, 0, time.UTC)
	desired := ConfigurationDesired{
		ConfigurationVersion: 5, PolicyVersion: 3, ValidUntil: now.Add(2 * time.Minute), AccessProfile: "full",
		ProtectedResourceIDs: []string{}, NetworkLeases: []NetworkLease{}, ResourceLeases: []ResourceLease{},
		RuntimeIntervals: &RuntimeIntervals{HeartbeatIntervalSeconds: 90, ConfigurationPollIntervalSeconds: 120},
	}
	raw, _ := json.Marshal(desired)
	control := &fakeControl{configuration: RuntimeMessage{
		SchemaVersion: RuntimeSchemaVersion, MessageID: "message-1", MessageType: MessageConfiguration,
		ProducerID: "network-control", RuntimeID: "endpoint-1", RuntimeKind: "endpoint", OccurredAt: now, ExpiresAt: desired.ValidUntil, Payload: raw,
	}}
	executor := &fakeConfigurationExecutor{outcome: ApplyOutcome{Status: "applied", ReadbackHash: emptyReadbackHash()}}
	manager, err := NewManager(ManagerOptions{RuntimeID: "endpoint-1", DeviceID: "device-1", PollInterval: time.Minute, HeartbeatInterval: time.Minute, RenewBefore: 30 * time.Second, MaxClockSkew: time.Minute}, control, executor, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return now }
	manager.intervalJitter = func(delay time.Duration) time.Duration { return delay }
	if err := manager.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if poll, heartbeat := manager.intervals(); poll != 120*time.Second || heartbeat != 90*time.Second || manager.nextPollDelay(now) != 120*time.Second {
		t.Fatalf("intervals = %s/%s, next poll = %s", poll, heartbeat, manager.nextPollDelay(now))
	}

	desired.RuntimeIntervals = &RuntimeIntervals{HeartbeatIntervalSeconds: 75, ConfigurationPollIntervalSeconds: 80}
	control.configuration.Payload, _ = json.Marshal(desired)
	if err := manager.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if poll, heartbeat := manager.intervals(); poll != 80*time.Second || heartbeat != 75*time.Second || executor.applyCalls != 1 {
		t.Fatalf("updated intervals = %s/%s, applies = %d", poll, heartbeat, executor.applyCalls)
	}
}

func TestManagerSchedulesPollAtConfigurationExpiry(t *testing.T) {
	now := time.Date(2026, 9, 4, 8, 0, 0, 0, time.UTC)
	manager := &Manager{
		options: ManagerOptions{PollInterval: time.Minute}, pollInterval: time.Minute,
		intervalJitter: func(delay time.Duration) time.Duration { return delay },
		status:         Status{ValidUntil: now.Add(1500 * time.Millisecond)},
	}
	if got := manager.nextPollDelay(now); got != 1500*time.Millisecond {
		t.Fatalf("next poll delay = %s, want exact expiry delay", got)
	}
}

func TestValidConnectScopeRequiresGrantForZTNA(t *testing.T) {
	t.Parallel()
	resources := []string{"resource-db"}
	if validConnectScope("internal_ztna", resources, "", "") {
		t.Fatal("internal ZTNA accepted without grant")
	}
	if !validConnectScope("internal_ztna", resources, "grant-1", testAccessGrantToken) {
		t.Fatal("internal ZTNA rejected with grant")
	}
	if !validConnectScope("external_vpn", nil, "", "") || validConnectScope("external_vpn", nil, "grant-1", testAccessGrantToken) {
		t.Fatal("pure VPN grant validation mismatch")
	}
	if !validLeaseShape("internal_ztna", 0, 1) {
		t.Fatal("internal ZTNA resource lease rejected")
	}
}

func TestManagerExpiresTunnelWhenControlIsUnavailable(t *testing.T) {
	t.Parallel()
	privateKey, _ := wgtypes.GeneratePrivateKey()
	peerKey, _ := wgtypes.GeneratePrivateKey()
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	desired := desiredConfiguration(privateKey.PublicKey(), peerKey.PublicKey(), 2, now.Add(time.Minute))
	raw, _ := json.Marshal(desired)
	control := &fakeControl{
		connectResult: VPNConnectResult{RequestID: "request-1", Decision: "allow", ReasonCode: "policy_allowed", SessionID: "session-1", GatewayID: "gateway-1", ConfigurationVersion: 2, PolicyVersion: 3, ValidUntil: desired.ValidUntil, NetworkLeases: desired.NetworkLeases},
		configuration: RuntimeMessage{SchemaVersion: RuntimeSchemaVersion, MessageID: "message-1", MessageType: MessageConfiguration, ProducerID: "network-control", RuntimeID: "endpoint-1", RuntimeKind: "endpoint", OccurredAt: now, ExpiresAt: desired.ValidUntil, Payload: raw},
	}
	system := &fakeSystem{}
	executor, _ := NewExecutor(privateKey, system)
	manager, _ := NewManager(ManagerOptions{RuntimeID: "endpoint-1", DeviceID: "device-1", PollInterval: time.Second, HeartbeatInterval: time.Minute, RenewBefore: 10 * time.Second, MaxClockSkew: time.Minute}, control, executor, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	manager.now = func() time.Time { return now }
	if _, err := manager.Connect(context.Background(), ConnectInput{SiteID: "site-1", NetworkSpaceID: "space-1"}); err != nil {
		t.Fatal(err)
	}
	control.configurationErr = errors.New("offline")
	manager.now = func() time.Time { return now.Add(61 * time.Second) }
	if err := manager.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if system.disableCalls == 0 || control.revokeCalls != 1 || control.lastRevoke.ReasonCode != "configuration_expired" || manager.Status().State != StateDisconnected {
		t.Fatalf("expiry disable=%d revoke=%#v status=%#v", system.disableCalls, control.lastRevoke, manager.Status())
	}
}

func TestManagerRetriesFailedExpiryCleanup(t *testing.T) {
	t.Parallel()
	privateKey, _ := wgtypes.GeneratePrivateKey()
	now := time.Now().UTC()
	system := &fakeSystem{disableErr: errors.New("disable failed")}
	executor, _ := NewExecutor(privateKey, system)
	control := &fakeControl{}
	manager, _ := NewManager(ManagerOptions{RuntimeID: "endpoint-1", DeviceID: "device-1", PollInterval: time.Second, HeartbeatInterval: time.Minute, RenewBefore: 10 * time.Second, MaxClockSkew: time.Minute}, control, executor, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	manager.now = func() time.Time { return now }
	manager.status.SessionID = "session-1"
	manager.status.ValidUntil = now.Add(-time.Second)
	manager.leaseIDs = []string{"lease-1"}
	manager.disabled = false

	if err := manager.Cycle(context.Background()); err == nil || manager.Status().State != StateDegraded {
		t.Fatalf("first Cycle() err=%v status=%#v", err, manager.Status())
	}
	system.disableErr = nil
	if err := manager.Cycle(context.Background()); err != nil || manager.Status().State != StateDisconnected {
		t.Fatalf("retry Cycle() err=%v status=%#v", err, manager.Status())
	}
}

func TestManagerConnectFailureRevokesSession(t *testing.T) {
	t.Parallel()
	privateKey, _ := wgtypes.GeneratePrivateKey()
	now := time.Now().UTC()
	control := &fakeControl{
		connectResult:    VPNConnectResult{Decision: "allow", SessionID: "session-1", GatewayID: "gateway-1", ConfigurationVersion: 1, PolicyVersion: 1, ValidUntil: now.Add(time.Minute), NetworkLeases: []NetworkLease{{ID: "lease-1"}}},
		configurationErr: errors.New("offline"),
	}
	executor, _ := NewExecutor(privateKey, &fakeSystem{})
	manager, _ := NewManager(ManagerOptions{RuntimeID: "endpoint-1", DeviceID: "device-1", PollInterval: time.Second, HeartbeatInterval: time.Minute, RenewBefore: 10 * time.Second, MaxClockSkew: time.Minute}, control, executor, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	manager.now = func() time.Time { return now }

	if _, err := manager.Connect(context.Background(), ConnectInput{SiteID: "site-1", NetworkSpaceID: "space-1"}); err == nil {
		t.Fatal("Connect() error = nil")
	}
	status := manager.Status()
	if control.revokeCalls != 1 || status.SessionID != "" || status.State != StateDisconnected {
		t.Fatalf("revoke=%d status=%#v", control.revokeCalls, status)
	}
}

func TestManagerDisconnectRetainsSessionUntilRevokeSucceeds(t *testing.T) {
	t.Parallel()
	privateKey, _ := wgtypes.GeneratePrivateKey()
	now := time.Now().UTC()
	control := &fakeControl{revokeErr: errors.New("offline")}
	executor, _ := NewExecutor(privateKey, &fakeSystem{})
	manager, _ := NewManager(ManagerOptions{RuntimeID: "endpoint-1", DeviceID: "device-1", PollInterval: time.Second, HeartbeatInterval: time.Minute, RenewBefore: 10 * time.Second, MaxClockSkew: time.Minute}, control, executor, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	manager.now = func() time.Time { return now }
	manager.status.SessionID = "session-1"
	manager.status.ValidUntil = now.Add(time.Minute)
	manager.leaseIDs = []string{"lease-1"}

	if _, err := manager.Disconnect(context.Background()); err == nil {
		t.Fatal("Disconnect() error = nil")
	}
	if status := manager.Status(); status.SessionID != "session-1" || status.State != StateDegraded {
		t.Fatalf("status after failed revoke = %#v", status)
	}
	control.revokeErr = nil
	if _, err := manager.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if status := manager.Status(); status.SessionID != "" || status.State != StateDisconnected {
		t.Fatalf("status after retry = %#v", status)
	}
}

func TestManagerStatusIncludesUptime(t *testing.T) {
	t.Parallel()
	privateKey, _ := wgtypes.GeneratePrivateKey()
	executor, _ := NewExecutor(privateKey, &fakeSystem{})
	manager, _ := NewManager(ManagerOptions{RuntimeID: "endpoint-1", DeviceID: "device-1", PollInterval: time.Second, HeartbeatInterval: time.Minute, RenewBefore: 10 * time.Second, MaxClockSkew: time.Minute}, &fakeControl{}, executor, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	started := time.Now().UTC()
	manager.startedAt = started
	manager.now = func() time.Time { return started.Add(23 * time.Second) }
	if got := manager.Status().UptimeSeconds; got != 23 {
		t.Fatalf("uptime = %d", got)
	}
}

func desiredConfiguration(publicKey, peerKey wgtypes.Key, version int, validUntil time.Time) ConfigurationDesired {
	lease := NetworkLease{ID: "lease-1", SessionID: "session-1", SubjectID: "user-1", DeviceID: "device-1", NetworkSpaceID: "space-1", CIDRs: []string{"10.20.0.0/24"}, PolicyVersion: 3, IssuedAt: validUntil.Add(-5 * time.Minute), ExpiresAt: validUntil}
	expiresAt := validUntil
	return ConfigurationDesired{
		ConfigurationVersion: version,
		PolicyVersion:        3,
		ValidUntil:           validUntil,
		AccessProfile:        "full",
		ProtectedResourceIDs: []string{},
		NetworkLeases:        []NetworkLease{lease},
		ResourceLeases:       []ResourceLease{},
		WireGuard: &WireGuardConfiguration{
			Role: "endpoint", InterfaceName: "soha0", PublicKey: publicKey.String(), Addresses: []string{"100.96.0.2/32"}, MTU: 1380, RoutingMode: "routed", FirewallDefault: "deny",
			Peers:  []WireGuardPeer{{RuntimeID: "gateway-runtime-1", PublicKey: peerKey.String(), EndpointHost: "vpn.example.com", EndpointPort: 51820, AllowedIPs: []string{"10.20.0.0/24"}, PersistentKeepaliveSeconds: 25}},
			Routes: []string{"10.20.0.0/24"}, DNSServers: []string{"10.20.0.53"},
			FirewallRules: []WireGuardFirewallRule{{ID: "allow-1", Effect: "allow", LeaseID: "lease-1", SourceCIDR: "100.96.0.2/32", DestinationCIDR: "10.20.0.0/24", Protocol: "any", ExpiresAt: &expiresAt}},
		},
	}
}

func directZTNAConfiguration(publicKey, peerKey wgtypes.Key, version int, validUntil time.Time) ConfigurationDesired {
	desired := desiredConfiguration(publicKey, peerKey, version, validUntil)
	desired.NetworkLeases = []NetworkLease{}
	desired.ResourceLeases = []ResourceLease{{ID: "resource-lease", SessionID: "session-1", SubjectID: "user-1", DeviceID: "device-1", ResourceIDs: []string{"resource-db"}, PolicyVersion: 3, IssuedAt: validUntil.Add(-5 * time.Minute), ExpiresAt: validUntil}}
	desired.WireGuard.Routes = []string{"10.20.8.10/32"}
	desired.WireGuard.Peers[0].AllowedIPs = []string{"10.20.8.10/32"}
	desired.WireGuard.DNSServers = []string{}
	expiresAt := validUntil
	desired.WireGuard.FirewallRules = []WireGuardFirewallRule{
		{ID: "resource-allow", Effect: "allow", LeaseID: "resource-lease", SourceCIDR: "100.96.0.2/32", DestinationCIDR: "10.20.8.10/32", Protocol: "tcp", Ports: []int{5432}, ExpiresAt: &expiresAt},
		{ID: "protected-deny", Effect: "deny", SourceCIDR: "100.96.0.2/32", DestinationCIDR: "10.20.8.10/32", Protocol: "any"},
	}
	return desired
}

type fakeSystem struct {
	current      TunnelReadback
	applyCalls   int
	applyErrAt   int
	disableCalls int
	disableErr   error
}

func (system *fakeSystem) Apply(_ context.Context, plan TunnelPlan) error {
	system.applyCalls++
	if system.applyCalls == system.applyErrAt {
		return errors.New("apply failed")
	}
	system.current = plan.Readback()
	return nil
}

func (system *fakeSystem) Readback(context.Context) (TunnelReadback, error) {
	return system.current, nil
}

func (system *fakeSystem) Disable(context.Context) error {
	system.disableCalls++
	if system.disableErr != nil {
		return system.disableErr
	}
	system.current = TunnelReadback{}
	return nil
}

type fakeControl struct {
	connectResult    VPNConnectResult
	configuration    RuntimeMessage
	renewResult      LeaseRenewResult
	configurationErr error
	source           MihomoSource
	sourceErr        error
	sourceCalls      int
	renewCalls       int
	revokeCalls      int
	revokeErr        error
	lastRevoke       LeaseRevoke
	lastConnect      VPNConnectRequest
}

func (control *fakeControl) Connect(_ context.Context, request VPNConnectRequest) (VPNConnectResult, error) {
	control.lastConnect = request
	return control.connectResult, nil
}

func (control *fakeControl) Configuration(context.Context) (RuntimeMessage, error) {
	return control.configuration, control.configurationErr
}

func (control *fakeControl) MihomoSource(context.Context, string) (MihomoSource, error) {
	control.sourceCalls++
	return control.source, control.sourceErr
}

func (control *fakeControl) Report(context.Context, ConfigurationApplied) error { return nil }

func (control *fakeControl) Renew(context.Context, LeaseRenewRequest) (LeaseRenewResult, error) {
	control.renewCalls++
	return control.renewResult, nil
}

func (control *fakeControl) Revoke(_ context.Context, revoke LeaseRevoke) error {
	control.revokeCalls++
	control.lastRevoke = revoke
	return control.revokeErr
}
