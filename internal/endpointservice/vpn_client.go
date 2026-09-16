package endpointservice

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

func validManagedRequest(request VPNManagedConnectRequest) bool {
	token, err := base64.RawURLEncoding.DecodeString(request.IntentToken)
	return identifierPattern.MatchString(request.RequestID) && identifierPattern.MatchString(request.IntentID) && err == nil && len(token) == 32 && (request.ProbeBatchID == "" || identifierPattern.MatchString(request.ProbeBatchID))
}

func (c *ControlClient) PrepareManagedVPN(ctx context.Context, request VPNManagedConnectRequest) (VPNManagedPrepareResult, error) {
	var result VPNManagedPrepareResult
	if !validManagedRequest(request) || request.ProbeBatchID != "" {
		return result, errors.New("invalid managed VPN request")
	}
	raw, err := c.runtimeMessage("vpn.managed.prepare.request", request)
	if err != nil {
		return result, err
	}
	message, err := c.postMessage(ctx, c.runtimeURL("vpn:prepare-managed"), raw, "", http.StatusOK)
	if err != nil {
		return result, err
	}
	if c.decodeResponse(message, "vpn.managed.prepare.result", &result) != nil || result.RequestID != request.RequestID || result.IntentID != request.IntentID || !validVPNPrepare(result, c.now().UTC()) {
		return VPNManagedPrepareResult{}, errors.New("invalid VPN probe preparation")
	}
	return result, nil
}

func (c *ControlClient) ConnectManagedVPN(ctx context.Context, request VPNManagedConnectRequest) (VPNManagedConnectResult, error) {
	var result VPNManagedConnectResult
	if !validManagedRequest(request) {
		return result, errors.New("invalid managed VPN request")
	}
	raw, err := c.runtimeMessage("vpn.managed.connect.request", request)
	if err != nil {
		return result, err
	}
	message, err := c.postMessage(ctx, c.runtimeURL("vpn:connect-managed"), raw, "", http.StatusOK)
	if err != nil {
		return result, err
	}
	if c.decodeResponse(message, "vpn.managed.connect.result", &result) != nil || result.RequestID != request.RequestID || result.DecisionID != request.IntentID || !identifierPattern.MatchString(result.ProfileID) || result.ProfileRevision < 1 || result.SelectionPolicyRevision < 1 || !slicesContains([]string{"auto", "manual"}, result.Selection) || result.MaxAttempts < 1 || result.MaxAttempts > 5 || result.RetryCooldownSeconds < 5 || result.RetryCooldownSeconds > 300 {
		return VPNManagedConnectResult{}, errors.New("invalid managed VPN result")
	}
	return result, nil
}

func validVPNPrepare(p VPNManagedPrepareResult, now time.Time) bool {
	if !identifierPattern.MatchString(p.ProfileID) || p.ProfileRevision < 1 || p.SelectionPolicyRevision < 1 || !p.ExpiresAt.After(now) || p.ExpiresAt.After(now.Add(2*time.Minute)) || p.SamplesPerGateway < 1 || p.SamplesPerGateway > 10 || p.MaxConcurrency < 1 || p.MaxConcurrency > 4 || p.TimeoutMillis < 100 || p.TimeoutMillis > 2000 || len(p.Descriptors) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, d := range p.Descriptors {
		if !identifierPattern.MatchString(d.GatewayID) || !identifierPattern.MatchString(d.RuntimeID) || seen[d.GatewayID] {
			return false
		}
		seen[d.GatewayID] = true
		if d.URL == "" {
			if d.Token != "" || d.ExpiresAt != nil {
				return false
			}
			continue
		}
		u, err := url.Parse(d.URL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Path != "/vpn/probe" || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || d.Token == "" || len(d.Token) > 4096 || d.ExpiresAt == nil || !d.ExpiresAt.After(now) || d.ExpiresAt.After(p.ExpiresAt) {
			return false
		}
	}
	return true
}

func (c *ControlClient) ProbeVPN(ctx context.Context, prepared VPNManagedPrepareResult) (VPNProbeBatch, error) {
	if !validVPNPrepare(prepared, c.now().UTC()) {
		return VPNProbeBatch{}, errors.New("invalid VPN probe preparation")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	batch := VPNProbeBatch{IntentID: prepared.IntentID, ProfileID: prepared.ProfileID, ProfileRevision: prepared.ProfileRevision, SelectionPolicyRevision: prepared.SelectionPolicyRevision, BatchID: randomID(), NetworkEpoch: randomID(), WindowStartedAt: c.now().UTC(), Results: []VPNProbeResult{}}
	results := make([]VPNProbeResult, len(prepared.Descriptors))
	slots := make(chan struct{}, prepared.MaxConcurrency)
	var workers sync.WaitGroup
	for index, descriptor := range prepared.Descriptors {
		if descriptor.URL == "" {
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				return
			}
			sample := VPNProbeResult{GatewayID: descriptor.GatewayID, RTTSamplesMs: []float64{}}
			for attempt := 0; attempt < prepared.SamplesPerGateway && ctx.Err() == nil && descriptor.ExpiresAt.After(c.now().UTC()); attempt++ {
				sample.SentCount++
				if ms, ok := c.probeVPNOnce(ctx, descriptor, time.Duration(prepared.TimeoutMillis)*time.Millisecond); ok {
					sample.RTTSamplesMs = append(sample.RTTSamplesMs, ms)
				}
			}
			results[index] = sample
		}()
	}
	workers.Wait()
	for _, sample := range results {
		if sample.SentCount > 0 {
			batch.Results = append(batch.Results, sample)
		}
	}
	batch.WindowEndedAt = c.now().UTC()
	if !batch.WindowEndedAt.After(batch.WindowStartedAt) {
		batch.WindowEndedAt = batch.WindowStartedAt.Add(time.Nanosecond)
	}
	return batch, nil
}

func (c *ControlClient) probeVPNOnce(ctx context.Context, d VPNProbeDescriptor, timeout time.Duration) (float64, bool) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, d.URL, nil)
	if err != nil {
		return 0, false
	}
	request.Header.Set("Authorization", "Bearer "+d.Token)
	started := time.Now()
	response, err := c.http.Do(request)
	if err != nil {
		return 0, false
	}
	defer response.Body.Close()
	_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 1))
	return float64(time.Since(started)) / float64(time.Millisecond), response.StatusCode == http.StatusNoContent && readErr == nil
}

func (c *TelemetryClient) VPNProbe(ctx context.Context, probe VPNProbeBatch) error {
	payload, err := json.Marshal(probe)
	if err != nil {
		return err
	}
	now := c.now().UTC()
	batch := IngestBatch{SchemaVersion: IngestSchemaVersion, BatchID: probe.BatchID, ProducerID: c.runtimeID, ProducerKind: "endpoint", SentAt: now, Events: []IngestEvent{{ID: probe.BatchID, Type: "vpn.probe.batch", Sequence: c.sequence.Add(1), OccurredAt: now, Payload: payload}}}
	raw, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+"/api/ingest/v1/events:batch", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusAccepted {
		return errors.New("VPN probe telemetry was not accepted")
	}
	return nil
}
