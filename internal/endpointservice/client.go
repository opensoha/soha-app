package endpointservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const maxRuntimeResponseBytes = 1 << 20

type EnrollmentInput struct {
	EnrollmentID       string
	ChallengeID        string
	DeviceID           string
	DevicePublicKey    string
	WireGuardPublicKey string
	ClientVersion      string
	Token              string
}

type ControlClient struct {
	origin       string
	runtimeID    string
	http         *http.Client
	maxClockSkew time.Duration
	capabilities []string
	now          func() time.Time
}

func NewControlClient(origin, runtimeID string, client *http.Client, maxClockSkew time.Duration, additionalCapabilities ...string) (*ControlClient, error) {
	parsed, err := runtimeOrigin(origin)
	if err != nil || !identifierPattern.MatchString(runtimeID) || client == nil || maxClockSkew <= 0 || maxClockSkew > 5*time.Minute || len(additionalCapabilities) > 1 || len(additionalCapabilities) == 1 && additionalCapabilities[0] != "mihomo" {
		return nil, errors.New("endpoint control client configuration is invalid")
	}
	copy := *client
	copy.CheckRedirect = rejectRedirect
	capabilities := append([]string{"wireguard", "route-coordinator", "dns-coordinator"}, additionalCapabilities...)
	return &ControlClient{origin: parsed, runtimeID: runtimeID, http: &copy, maxClockSkew: maxClockSkew, capabilities: capabilities, now: time.Now}, nil
}

func (client *ControlClient) Enroll(ctx context.Context, input EnrollmentInput) (EnrollmentResult, error) {
	if !identifierPattern.MatchString(input.EnrollmentID) || !identifierPattern.MatchString(input.ChallengeID) || !identifierPattern.MatchString(input.DeviceID) || len(input.DevicePublicKey) < 32 || len(input.DevicePublicKey) > 4096 || strings.TrimSpace(input.DevicePublicKey) != input.DevicePublicKey || len(input.ClientVersion) == 0 || len(input.ClientVersion) > 64 || len(input.Token) < 32 || len(input.Token) > 4096 || strings.TrimSpace(input.Token) != input.Token {
		return EnrollmentResult{}, errors.New("endpoint enrollment parameters are invalid")
	}
	payload := EnrollmentRequest{EnrollmentID: input.EnrollmentID, ChallengeID: input.ChallengeID, DeviceID: input.DeviceID, DevicePublicKey: input.DevicePublicKey, WireGuardPublicKey: input.WireGuardPublicKey, Platform: "windows", ClientVersion: input.ClientVersion, Capabilities: append([]string(nil), client.capabilities...)}
	raw, err := client.runtimeMessage(MessageEnrollmentRequest, payload)
	if err != nil {
		return EnrollmentResult{}, err
	}
	message, err := client.postMessage(ctx, client.runtimeURL("enroll"), raw, "Bearer "+input.Token, http.StatusCreated)
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("enroll endpoint runtime: %w", err)
	}
	var result EnrollmentResult
	if err := client.decodeResponse(message, MessageEnrollmentResult, &result); err != nil {
		return EnrollmentResult{}, err
	}
	if !result.Accepted || !strings.HasPrefix(result.CredentialReference, "secretref:") {
		return EnrollmentResult{}, fmt.Errorf("endpoint enrollment was not accepted: %s", fallback(result.ReasonCode, "authorization_denied"))
	}
	return result, nil
}

func (client *ControlClient) Connect(ctx context.Context, payload VPNConnectRequest) (VPNConnectResult, error) {
	if !identifierPattern.MatchString(payload.RequestID) || !identifierPattern.MatchString(payload.SiteID) || !identifierPattern.MatchString(payload.NetworkSpaceID) || (payload.GatewayID != "" && !identifierPattern.MatchString(payload.GatewayID)) || !validConnectScope(payload.Mode, payload.ResourceIDs, payload.AccessGrantID, payload.AccessGrantToken) {
		return VPNConnectResult{}, errors.New("endpoint VPN request is invalid")
	}
	raw, err := client.runtimeMessage(MessageVPNConnectRequest, payload)
	if err != nil {
		return VPNConnectResult{}, err
	}
	message, err := client.postMessage(ctx, client.runtimeURL("vpn:connect"), raw, "", http.StatusOK)
	if err != nil {
		return VPNConnectResult{}, fmt.Errorf("connect endpoint VPN: %w", err)
	}
	var result VPNConnectResult
	if err := client.decodeResponse(message, MessageVPNConnectResult, &result); err != nil || result.RequestID != payload.RequestID {
		return VPNConnectResult{}, errors.New("network control returned an invalid VPN result")
	}
	return result, nil
}

func (client *ControlClient) Configuration(ctx context.Context) (RuntimeMessage, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.runtimeURL("configuration"), nil)
	if err != nil {
		return RuntimeMessage{}, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.http.Do(request)
	if err != nil {
		return RuntimeMessage{}, fmt.Errorf("get endpoint configuration: %w", err)
	}
	raw, err := readRuntimeResponse(response, http.StatusOK)
	if err != nil {
		return RuntimeMessage{}, err
	}
	var message RuntimeMessage
	if err := decodeStrict(raw, &message); err != nil || client.validateResponse(message, MessageConfiguration) != nil {
		return RuntimeMessage{}, errors.New("network control returned an invalid endpoint configuration")
	}
	return message, nil
}

func (client *ControlClient) MihomoSource(ctx context.Context, profileID string) (MihomoSource, error) {
	if !identifierPattern.MatchString(profileID) {
		return MihomoSource{}, errors.New("mihomo profile ID is invalid")
	}
	endpoint := client.origin + "/api/network-control/v1/runtimes/" + url.PathEscape(client.runtimeID) + "/mihomo-profiles/" + url.PathEscape(profileID) + "/source"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return MihomoSource{}, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.http.Do(request)
	if err != nil {
		return MihomoSource{}, fmt.Errorf("get mihomo source: %w", err)
	}
	if !strings.Contains(strings.ToLower(response.Header.Get("Cache-Control")), "no-store") {
		response.Body.Close()
		return MihomoSource{}, errors.New("network control returned a cacheable mihomo source")
	}
	raw, err := readRuntimeResponse(response, http.StatusOK)
	if err != nil {
		return MihomoSource{}, err
	}
	var result MihomoSource
	if decodeStrict(raw, &result) != nil || result.ProfileID != profileID || result.ProfileRevision < 1 || !validMihomoSource(result) {
		return MihomoSource{}, errors.New("network control returned an invalid mihomo source")
	}
	return result, nil
}

func (client *ControlClient) MihomoSubscription(ctx context.Context, profileID string) (MihomoSubscription, error) {
	source, err := client.MihomoSource(ctx, profileID)
	if err != nil || source.SourceType != "managed_subscription" {
		return MihomoSubscription{}, errors.Join(errors.New("network control returned an invalid mihomo subscription"), err)
	}
	return MihomoSubscription{ProfileID: source.ProfileID, ProfileRevision: source.ProfileRevision, SubscriptionURL: source.SubscriptionURL}, nil
}

func validMihomoSource(source MihomoSource) bool {
	switch source.SourceType {
	case "managed_subscription":
		return source.ManualNode == nil && validSubscriptionURL(source.SubscriptionURL)
	case "manual_node":
		return source.SubscriptionURL == "" && validMihomoManualNode(source.ManualNode)
	default:
		return false
	}
}

func validMihomoManualNode(node *MihomoManualNode) bool {
	if node == nil || !slicesContains([]string{"http", "https", "socks5"}, node.Protocol) || net.ParseIP(node.Server) == nil && !validEndpointHost(node.Server) || node.Port < 1 || node.Port > 65535 || (node.Username == "") != (node.Password == "") {
		return false
	}
	return (node.Username == "" || strings.TrimSpace(node.Username) != "") && utf8.RuneCountInString(node.Username) <= 256 && utf8.RuneCountInString(node.Password) <= 4096
}

func validSubscriptionURL(raw string) bool {
	if len(raw) == 0 || len(raw) > 4096 || strings.TrimSpace(raw) != raw {
		return false
	}
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.Hostname() != "" && parsed.User == nil && parsed.Fragment == "" && parsed.Opaque == ""
}

func (client *ControlClient) Report(ctx context.Context, payload ConfigurationApplied) error {
	if payload.ConfigurationVersion < 1 || payload.PolicyVersion < 1 || !slicesContains([]string{"applied", "rejected", "rolled-back"}, payload.Status) || !validReadbackHash(payload.ReadbackHash) {
		return errors.New("endpoint configuration report is invalid")
	}
	raw, err := client.runtimeMessage(MessageConfigurationApply, payload)
	if err != nil {
		return err
	}
	_, err = client.postMessage(ctx, client.runtimeURL("configuration:applied"), raw, "", http.StatusNoContent)
	return err
}

func (client *ControlClient) Renew(ctx context.Context, payload LeaseRenewRequest) (LeaseRenewResult, error) {
	if !identifierPattern.MatchString(payload.SessionID) || payload.ObservedConfigurationVersion < 1 || len(payload.LeaseIDs) == 0 || len(payload.LeaseIDs) > 512 || !allIdentifiers(payload.LeaseIDs) {
		return LeaseRenewResult{}, errors.New("endpoint lease renewal is invalid")
	}
	raw, err := client.runtimeMessage(MessageLeaseRenewRequest, payload)
	if err != nil {
		return LeaseRenewResult{}, err
	}
	message, err := client.postMessage(ctx, client.runtimeURL("leases:renew"), raw, "", http.StatusOK)
	if err != nil {
		return LeaseRenewResult{}, fmt.Errorf("renew endpoint lease: %w", err)
	}
	var result LeaseRenewResult
	if err := client.decodeResponse(message, MessageLeaseRenewResult, &result); err != nil {
		return LeaseRenewResult{}, err
	}
	return result, nil
}

func (client *ControlClient) Revoke(ctx context.Context, payload LeaseRevoke) error {
	if !identifierPattern.MatchString(payload.SessionID) || len(payload.LeaseIDs) == 0 || len(payload.LeaseIDs) > 512 || !allIdentifiers(payload.LeaseIDs) || !identifierPattern.MatchString(payload.ReasonCode) || payload.EffectiveAt.IsZero() {
		return errors.New("endpoint lease revoke is invalid")
	}
	raw, err := client.runtimeMessage(MessageLeaseRevoke, payload)
	if err != nil {
		return err
	}
	_, err = client.post(ctx, client.runtimeURL("leases:revoke"), raw, "", http.StatusOK)
	return err
}

func (client *ControlClient) runtimeMessage(messageType string, payload any) ([]byte, error) {
	payloadRaw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	now := client.now().UTC()
	message := RuntimeMessage{SchemaVersion: RuntimeSchemaVersion, MessageID: randomID(), MessageType: messageType, ProducerID: client.runtimeID, RuntimeID: client.runtimeID, RuntimeKind: "endpoint", OccurredAt: now, ExpiresAt: now.Add(min(client.maxClockSkew, 2*time.Minute)), Payload: payloadRaw}
	return json.Marshal(message)
}

func (client *ControlClient) postMessage(ctx context.Context, endpoint string, raw []byte, authorization string, expectedStatus int) (RuntimeMessage, error) {
	responseRaw, err := client.post(ctx, endpoint, raw, authorization, expectedStatus)
	if err != nil {
		return RuntimeMessage{}, err
	}
	if expectedStatus == http.StatusNoContent {
		return RuntimeMessage{}, nil
	}
	var message RuntimeMessage
	if err := decodeStrict(responseRaw, &message); err != nil {
		return RuntimeMessage{}, errors.New("network control returned malformed JSON")
	}
	return message, nil
}

func (client *ControlClient) post(ctx context.Context, endpoint string, raw []byte, authorization string, expectedStatus int) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response, err := client.http.Do(request)
	if err != nil {
		return nil, err
	}
	responseRaw, err := readRuntimeResponse(response, expectedStatus)
	if err != nil {
		return nil, err
	}
	return responseRaw, nil
}

func (client *ControlClient) decodeResponse(message RuntimeMessage, messageType string, payload any) error {
	if err := client.validateResponse(message, messageType); err != nil {
		return err
	}
	if err := decodeStrict(message.Payload, payload); err != nil {
		return errors.New("network control returned an invalid endpoint payload")
	}
	return nil
}

func (client *ControlClient) validateResponse(message RuntimeMessage, messageType string) error {
	now := client.now().UTC()
	if message.SchemaVersion != RuntimeSchemaVersion || message.MessageType != messageType || message.ProducerID != "network-control" || message.RuntimeID != client.runtimeID || message.RuntimeKind != "endpoint" || !identifierPattern.MatchString(message.MessageID) || message.OccurredAt.After(now.Add(client.maxClockSkew)) || message.OccurredAt.Before(now.Add(-client.maxClockSkew)) || !message.ExpiresAt.After(now) || !message.ExpiresAt.After(message.OccurredAt) {
		return errors.New("network control returned a message outside the endpoint trust boundary")
	}
	return nil
}

func (client *ControlClient) runtimeURL(action string) string {
	return client.origin + "/api/network-control/v1/runtimes/" + url.PathEscape(client.runtimeID) + "/" + action
}

type TelemetryClient struct {
	origin       string
	runtimeID    string
	http         *http.Client
	proxyMetrics ProxyMetricsSource
	sequence     atomic.Int64
	sampleMu     sync.Mutex
	previous     *proxyFlowBaseline
	now          func() time.Time
}

type ProxyMetricsSource interface {
	ProxyFlowSnapshot(context.Context) (ProxyFlowSnapshot, error)
}

type ProxyFlowSnapshot struct {
	Active            bool
	Engine            string
	Mode              string
	ProfileID         string
	ProfileRevision   int
	SelectedProxy     string
	UploadTotal       int64
	DownloadTotal     int64
	ActiveConnections int64
}

type proxyFlowBaseline struct {
	at       time.Time
	snapshot ProxyFlowSnapshot
}

func NewTelemetryClient(origin, runtimeID string, client *http.Client, proxyMetrics ...ProxyMetricsSource) (*TelemetryClient, error) {
	parsed, err := runtimeOrigin(origin)
	if err != nil || !identifierPattern.MatchString(runtimeID) || client == nil || len(proxyMetrics) > 1 || len(proxyMetrics) == 1 && proxyMetrics[0] == nil {
		return nil, errors.New("endpoint ingest client configuration is invalid")
	}
	copy := *client
	copy.CheckRedirect = rejectRedirect
	result := &TelemetryClient{origin: parsed, runtimeID: runtimeID, http: &copy, now: time.Now}
	if len(proxyMetrics) == 1 {
		result.proxyMetrics = proxyMetrics[0]
	}
	return result, nil
}

func (client *TelemetryClient) Heartbeat(ctx context.Context, status Status) error {
	if !slicesContains([]string{StateDisconnected, StateConnecting, StateConnected, StateDegraded}, status.State) || status.RuntimeID != client.runtimeID || !identifierPattern.MatchString(status.DeviceID) || status.ConfigurationVersion < 0 || status.PolicyVersion < 0 || status.UptimeSeconds < 0 {
		return errors.New("endpoint heartbeat status is invalid")
	}
	now := client.now().UTC()
	health := "healthy"
	if status.State == StateDegraded {
		health = "degraded"
	}
	payload, err := json.Marshal(struct {
		Status               string   `json:"status"`
		ConfigurationVersion int      `json:"configurationVersion"`
		PolicyVersion        int      `json:"policyVersion"`
		UptimeSeconds        int64    `json:"uptimeSeconds"`
		Diagnostics          []string `json:"diagnostics,omitempty"`
	}{Status: health, ConfigurationVersion: status.ConfigurationVersion, PolicyVersion: status.PolicyVersion, UptimeSeconds: status.UptimeSeconds, Diagnostics: diagnosticList(status.Diagnostic)})
	if err != nil {
		return err
	}
	events := []IngestEvent{{ID: randomID(), Type: "runtime.heartbeat", Sequence: client.sequence.Add(1), OccurredAt: now, Payload: payload}}
	var metricsErr error
	if client.proxyMetrics != nil {
		snapshot, err := client.proxyMetrics.ProxyFlowSnapshot(ctx)
		if err != nil {
			metricsErr = fmt.Errorf("read proxy flow aggregate: %w", err)
		} else if aggregate, ok := client.proxyAggregate(now, snapshot); ok {
			payload, err := json.Marshal(aggregate)
			if err != nil {
				metricsErr = err
			} else {
				events = append(events, IngestEvent{ID: randomID(), Type: "proxy.flow.aggregate", Sequence: client.sequence.Add(1), OccurredAt: now, Payload: payload})
			}
		}
	}
	batch := IngestBatch{SchemaVersion: IngestSchemaVersion, BatchID: randomID(), ProducerID: client.runtimeID, ProducerKind: "endpoint", SentAt: now, Events: events}
	raw, err := json.Marshal(batch)
	if err != nil {
		return errors.Join(metricsErr, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.origin+"/api/ingest/v1/events:batch", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.http.Do(request)
	if err != nil {
		return errors.Join(metricsErr, fmt.Errorf("send endpoint heartbeat: %w", err))
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusAccepted {
		return errors.Join(metricsErr, fmt.Errorf("network ingest returned HTTP %d", response.StatusCode))
	}
	return metricsErr
}

func (client *TelemetryClient) proxyAggregate(now time.Time, snapshot ProxyFlowSnapshot) (any, bool) {
	client.sampleMu.Lock()
	defer client.sampleMu.Unlock()
	if !snapshot.Active {
		client.previous = nil
		return nil, false
	}
	if snapshot.Engine != "mihomo" || !slicesContains([]string{"managed_follow", "app_subscription"}, snapshot.Mode) || !identifierPattern.MatchString(snapshot.ProfileID) || snapshot.ProfileRevision < 1 || !validMihomoName(snapshot.SelectedProxy) || snapshot.UploadTotal < 0 || snapshot.DownloadTotal < 0 || snapshot.ActiveConnections < 0 || snapshot.ActiveConnections > 1_000_000 {
		return nil, false
	}
	startedAt, uploadBytes, downloadBytes := now, int64(0), int64(0)
	if previous := client.previous; previous != nil && sameProxyFlow(previous.snapshot, snapshot) && snapshot.UploadTotal >= previous.snapshot.UploadTotal && snapshot.DownloadTotal >= previous.snapshot.DownloadTotal {
		startedAt = previous.at
		uploadBytes = snapshot.UploadTotal - previous.snapshot.UploadTotal
		downloadBytes = snapshot.DownloadTotal - previous.snapshot.DownloadTotal
	}
	client.previous = &proxyFlowBaseline{at: now, snapshot: snapshot}
	return struct {
		WindowStartedAt   time.Time `json:"windowStartedAt"`
		WindowEndedAt     time.Time `json:"windowEndedAt"`
		Engine            string    `json:"engine"`
		ProfileID         string    `json:"profileId"`
		ProfileRevision   int       `json:"profileRevision"`
		Mode              string    `json:"mode"`
		SelectedProxy     string    `json:"selectedProxy"`
		UploadBytes       int64     `json:"uploadBytes"`
		DownloadBytes     int64     `json:"downloadBytes"`
		ActiveConnections int64     `json:"activeConnections"`
	}{startedAt, now, snapshot.Engine, snapshot.ProfileID, snapshot.ProfileRevision, snapshot.Mode, snapshot.SelectedProxy, uploadBytes, downloadBytes, snapshot.ActiveConnections}, true
}

func sameProxyFlow(left, right ProxyFlowSnapshot) bool {
	return left.Engine == right.Engine && left.Mode == right.Mode && left.ProfileID == right.ProfileID && left.ProfileRevision == right.ProfileRevision && left.SelectedProxy == right.SelectedProxy
}

func runtimeOrigin(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", errors.New("runtime endpoint must be an HTTPS origin")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func readRuntimeResponse(response *http.Response, expectedStatus int) ([]byte, error) {
	defer response.Body.Close()
	if response.StatusCode != expectedStatus {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("network runtime returned HTTP %d", response.StatusCode)
	}
	if expectedStatus == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil, nil
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, errors.New("network runtime returned a non-JSON response")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxRuntimeResponseBytes+1))
	if err != nil || len(raw) > maxRuntimeResponseBytes {
		return nil, errors.New("network runtime response exceeded the safe limit")
	}
	return raw, nil
}

func rejectRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func validReadbackHash(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func allIdentifiers(values []string) bool {
	seen := map[string]struct{}{}
	for _, value := range values {
		if !identifierPattern.MatchString(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func slicesContains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func diagnosticList(value string) []string {
	if value == "" {
		return nil
	}
	return []string{value}
}
