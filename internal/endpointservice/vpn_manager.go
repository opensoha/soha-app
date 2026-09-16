package endpointservice

import (
	"context"
	"errors"
	"time"
)

type ManagedVPNControl interface {
	PrepareManagedVPN(context.Context, VPNManagedConnectRequest) (VPNManagedPrepareResult, error)
	ProbeVPN(context.Context, VPNManagedPrepareResult) (VPNProbeBatch, error)
	ConnectManagedVPN(context.Context, VPNManagedConnectRequest) (VPNManagedConnectResult, error)
}

func (manager *Manager) connectManaged(ctx context.Context, input ConnectInput) (Status, error) {
	manager.operationMu.Lock()
	defer manager.operationMu.Unlock()
	if input.SiteID != "" || input.NetworkSpaceID != "" || input.GatewayID != "" || input.Mode != "" || len(input.ResourceIDs) > 0 || input.AccessGrantID != "" || input.AccessGrantToken != "" {
		return manager.Status(), errors.New("managed VPN does not accept local scope overrides")
	}
	request := VPNManagedConnectRequest{RequestID: input.RequestID, IntentID: input.IntentID, IntentToken: input.IntentToken}
	if request.RequestID == "" {
		request.RequestID = randomID()
	}
	if !validManagedRequest(request) {
		return manager.Status(), errors.New("invalid managed VPN intent")
	}
	control, ok := manager.control.(ManagedVPNControl)
	if !ok {
		return manager.Status(), errors.New("managed VPN runtime is unavailable")
	}
	manager.stateMu.RLock()
	active, cleanup := manager.status.SessionID != "", manager.cleanupReason != ""
	manager.stateMu.RUnlock()
	if active || cleanup {
		return manager.Status(), errors.New("disconnect and finish cleanup before reconnecting")
	}
	manager.update(func(status *Status) { status.State, status.Phase, status.Diagnostic = StateConnecting, "preparing", "" })
	prepared, err := control.PrepareManagedVPN(ctx, request)
	if err != nil {
		manager.degrade("vpn_prepare_failed")
		return manager.Status(), err
	}
	manager.update(func(status *Status) {
		status.ProfileID, status.ProfileRevision, status.Phase = prepared.ProfileID, prepared.ProfileRevision, "measuring"
	})
	batch, err := control.ProbeVPN(ctx, prepared)
	if err != nil {
		manager.degrade("vpn_probe_failed")
		return manager.Status(), err
	}
	manager.update(func(status *Status) {
		status.ProbeResults, status.ProbeMeasuredAt, status.Phase = batch.Results, &batch.WindowEndedAt, "selecting"
	})
	if telemetry, ok := manager.telemetry.(interface {
		VPNProbe(context.Context, VPNProbeBatch) error
	}); ok {
		// A missing ingest snapshot is handled by the central policy's explicit fallback.
		if err := telemetry.VPNProbe(ctx, batch); err == nil {
			request.ProbeBatchID = batch.BatchID
		}
	}
	result, err := control.ConnectManagedVPN(ctx, request)
	if err != nil {
		manager.degrade("vpn_connect_failed")
		return manager.Status(), err
	}
	if result.ProfileID != prepared.ProfileID || result.ProfileRevision != prepared.ProfileRevision || result.SelectionPolicyRevision != prepared.SelectionPolicyRevision {
		manager.degrade("vpn_profile_changed")
		return manager.Status(), errors.New("VPN profile changed during selection")
	}
	manager.update(func(status *Status) {
		status.SiteID, status.NetworkSpaceID, status.Mode, status.ResourceIDs = result.SiteID, result.NetworkSpaceID, result.Mode, result.ResourceIDs
		status.Selection, status.SelectionReason, status.DecisionID = result.Selection, result.SelectionReason, result.DecisionID
		status.FailoverOnDisconnect, status.RetryCooldownSeconds, status.MaxAttempts = result.FailoverOnDisconnect, result.RetryCooldownSeconds, result.MaxAttempts
		status.Phase = "applying"
	})
	status, err := manager.acceptVPNConnection(ctx, result.VPNConnectResult, result.Mode)
	if err != nil {
		return status, err
	}
	connectedAt := manager.now().UTC()
	manager.update(func(status *Status) { status.Phase = ""; status.ConnectedAt = &connectedAt })
	return manager.Status(), nil
}

func (manager *Manager) managedConfigurationRevoked(desired ConfigurationDesired) bool {
	manager.stateMu.RLock()
	defer manager.stateMu.RUnlock()
	return manager.status.ProfileID != "" && manager.status.SessionID != "" && desired.WireGuard == nil
}

// Cleanup gets its own bounded context even when a UI request is cancelled.
func (manager *Manager) cleanupFailedVPN(ctx context.Context) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_, err := manager.disconnectLocked(cleanup, "connect_failed")
	return err
}

func validVPNHandshake(at, now time.Time) bool {
	return !at.IsZero() && !at.After(now.Add(5*time.Second)) && now.Sub(at) <= 3*time.Minute
}
