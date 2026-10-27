package endpointservice

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"
)

const MessageEndpointPresenceRequest = "endpoint.presence.request"
const MessageEndpointPresenceResult = "endpoint.presence.result"

type EndpointPresenceRequest struct {
	AdmissionPolicyVersion int        `json:"admissionPolicyVersion,omitempty"`
	DeviceID               string     `json:"deviceId"`
	BootID                 string     `json:"bootId"`
	Sequence               int64      `json:"sequence"`
	Status                 string     `json:"status"`
	ConfigurationVersion   int        `json:"configurationVersion"`
	PolicyVersion          int        `json:"policyVersion"`
	UIState                string     `json:"uiState"`
	UIObservedAt           *time.Time `json:"uiObservedAt,omitempty"`
}

type EndpointPresenceResult struct {
	AdmissionPolicyVersion int       `json:"admissionPolicyVersion,omitempty"`
	Accepted               bool      `json:"accepted"`
	PresenceEpoch          int       `json:"presenceEpoch"`
	ReceivedAt             time.Time `json:"receivedAt"`
	NextHeartbeatSeconds   int       `json:"nextHeartbeatSeconds"`
}

type EndpointPresenceControl interface {
	PublishPresence(context.Context, EndpointPresenceRequest) (EndpointPresenceResult, error)
}

func (client *ControlClient) PublishPresence(ctx context.Context, payload EndpointPresenceRequest) (EndpointPresenceResult, error) {
	if !identifierPattern.MatchString(payload.DeviceID) || !identifierPattern.MatchString(payload.BootID) || payload.Sequence < 1 || payload.Status != "healthy" && payload.Status != "unhealthy" || !validUIObservation(payload.UIState, payload.UIObservedAt, slices.Contains(client.capabilities, "endpoint-ui-presence-v1"), client.now()) || payload.ConfigurationVersion < 0 || payload.PolicyVersion < 0 || payload.AdmissionPolicyVersion < 0 {
		return EndpointPresenceResult{}, errors.New("endpoint presence is invalid")
	}
	raw, err := client.runtimeMessage(MessageEndpointPresenceRequest, payload)
	if err != nil {
		return EndpointPresenceResult{}, err
	}
	message, err := client.postMessage(ctx, client.runtimeURL("endpoint:presence"), raw, "", http.StatusOK)
	if err != nil {
		return EndpointPresenceResult{}, err
	}
	var result EndpointPresenceResult
	if err := client.decodeResponse(message, MessageEndpointPresenceResult, &result); err != nil || !result.Accepted || result.AdmissionPolicyVersion < 0 || result.PresenceEpoch < 1 || result.ReceivedAt.IsZero() || !validRuntimeInterval(result.NextHeartbeatSeconds) || result.ReceivedAt.After(client.now().Add(client.maxClockSkew)) {
		return EndpointPresenceResult{}, errors.New("network control returned an invalid endpoint presence result")
	}
	return result, nil
}

func (manager *Manager) runPresence(ctx context.Context, publisher EndpointPresenceControl) {
	delay, retry := time.Duration(0), time.Second
	sequence := int64(0)
	admissionVersion := 0
	for {
		if delay > 0 && !manager.heartbeatWait(ctx, manager.intervalJitter(delay)) {
			return
		}
		if ctx.Err() != nil {
			return
		}
		sequence++
		status := manager.Status()
		health := "healthy"
		manager.stateMu.RLock()
		cleanupPending := manager.cleanupReason != ""
		manager.stateMu.RUnlock()
		if cleanupPending {
			health = "unhealthy"
		}
		callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		uiState, observedAt := manager.options.UIPresence.Snapshot(manager.now().UTC())
		result, err := publisher.PublishPresence(callCtx, EndpointPresenceRequest{DeviceID: manager.options.DeviceID, BootID: manager.presenceBootID, Sequence: sequence, Status: health, ConfigurationVersion: status.ConfigurationVersion, PolicyVersion: status.PolicyVersion, AdmissionPolicyVersion: admissionVersion, UIState: uiState, UIObservedAt: observedAt})
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			manager.update(func(status *Status) { status.PresenceState = "unavailable" })
			manager.logger.Warn("endpoint presence publication failed", "event", "endpoint_network.presence.failed")
			delay, retry = retry, min(retry*2, heartbeatRetryMax)
			continue
		}
		received := result.ReceivedAt
		admissionVersion = result.AdmissionPolicyVersion
		manager.update(func(status *Status) {
			status.PresenceState = health
			status.PresenceLastReceivedAt = &received
			status.PresenceEpoch = result.PresenceEpoch
		})
		delay, retry = time.Duration(result.NextHeartbeatSeconds)*time.Second, time.Second
	}
}
