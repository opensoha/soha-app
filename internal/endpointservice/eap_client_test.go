package endpointservice

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEAPClientPreservesRuntimeAndCertificateBindings(t *testing.T) {
	certificate, csr, _ := eapCertificateFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	var wrongRuntime, wrongFingerprint atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var message RuntimeMessage
		if err := json.NewDecoder(r.Body).Decode(&message); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if message.RuntimeID != "endpoint-1" || message.RuntimeKind != "endpoint" || message.ProducerID != "endpoint-1" {
			t.Error("wrong request identity")
			w.WriteHeader(400)
			return
		}
		var payload any
		switch r.URL.Path {
		case "/api/network-control/v1/runtimes/endpoint-1/eap:certificate":
			var request EAPCertificateRequest
			if message.MessageType != MessageEAPCertificateRequest || json.Unmarshal(message.Payload, &request) != nil || request.RequestID != "request-1" || request.CSRPEM != csr {
				t.Error("wrong CSR request")
				w.WriteHeader(400)
				return
			}
			payload = certificate
			message.MessageType = MessageEAPCertificateResult
		case "/api/network-control/v1/runtimes/endpoint-1/eap:activate":
			var request EAPCertificateActivateRequest
			if message.MessageType != MessageEAPCertificateActivateRequest || json.Unmarshal(message.Payload, &request) != nil || request.CredentialID != certificate.CredentialID || request.Fingerprint != certificate.Fingerprint {
				t.Error("wrong activation binding")
				w.WriteHeader(400)
				return
			}
			result := EAPCertificateActivateResult{CredentialID: certificate.CredentialID, Fingerprint: certificate.Fingerprint, ExpiresAt: certificate.ExpiresAt, Status: "active"}
			if wrongFingerprint.Load() {
				result.Fingerprint = "sha256:" + strings.Repeat("0", 64)
			}
			payload = result
			message.MessageType = MessageEAPCertificateActivateResult
		default:
			w.WriteHeader(404)
			return
		}
		message.ProducerID, message.OccurredAt, message.ExpiresAt = "network-control", now, now.Add(time.Minute)
		if wrongRuntime.Load() {
			message.RuntimeID = "other-endpoint"
		}
		message.Payload, _ = json.Marshal(payload)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(message)
	}))
	defer server.Close()
	client, err := NewControlClient(server.URL, "endpoint-1", server.Client(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request := EAPCertificateRequest{RequestID: "request-1", CSRPEM: csr}
	if _, err := client.IssueEAPCertificate(context.Background(), request, "device-1", "subject-1"); err != nil {
		t.Fatal(err)
	}
	activation := EAPCertificateActivateRequest{CredentialID: certificate.CredentialID, Fingerprint: certificate.Fingerprint}
	if _, err := client.ActivateEAPCertificate(context.Background(), activation); err != nil {
		t.Fatal(err)
	}
	wrongRuntime.Store(true)
	if _, err := client.IssueEAPCertificate(context.Background(), request, "device-1", "subject-1"); err == nil {
		t.Fatal("different runtime certificate accepted")
	}
	wrongRuntime.Store(false)
	wrongFingerprint.Store(true)
	if _, err := client.ActivateEAPCertificate(context.Background(), activation); err == nil {
		t.Fatal("different activation fingerprint accepted")
	}
}
