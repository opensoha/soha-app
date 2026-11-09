package endpointservice

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestConfigPublicKeyEnrollmentMTLS(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	directory := t.TempDir()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "enrollment test CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := url.Parse("spiffe://opensoha.local/network-control/endpoint/endpoint-1")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), URIs: []*url.URL{identity}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	certDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	expectedDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("test-enrollment-token-", 3)
	var calls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/api/network-control/v1/runtimes/endpoint-1/enroll" || r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("constructed enrollment request route/auth mismatch")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			t.Error("enrollment did not use verified device mTLS")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		peerDER, err := x509.MarshalPKIXPublicKey(r.TLS.PeerCertificates[0].PublicKey)
		if err != nil || !bytes.Equal(peerDER, expectedDER) {
			t.Error("mTLS device key changed")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var message RuntimeMessage
		var payload EnrollmentRequest
		if json.NewDecoder(r.Body).Decode(&message) != nil || json.Unmarshal(message.Payload, &payload) != nil || message.MessageType != MessageEnrollmentRequest || message.RuntimeID != "endpoint-1" || message.ProducerID != "endpoint-1" || message.RuntimeKind != "endpoint" || payload.DeviceID != "device-1" || payload.EnrollmentID != "enrollment-1" || payload.ChallengeID != "challenge-1" {
			t.Error("constructed enrollment envelope mismatch")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		block, rest := pem.Decode([]byte(payload.DevicePublicKey))
		if block == nil || block.Type != "PUBLIC KEY" || len(rest) != 0 || !bytes.Equal(block.Bytes, expectedDER) || strings.TrimSpace(payload.DevicePublicKey) != payload.DevicePublicKey {
			t.Error("canonical enrollment PEM changed public-key DER")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		result, _ := json.Marshal(EnrollmentResult{Accepted: true, ReasonCode: "accepted", CredentialReference: "secretref:enrollment-test"})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(RuntimeMessage{SchemaVersion: RuntimeSchemaVersion, MessageID: "enrollment-result-1", MessageType: MessageEnrollmentResult, ProducerID: "network-control", RuntimeID: "endpoint-1", RuntimeKind: "endpoint", OccurredAt: now, ExpiresAt: now.Add(time.Minute), Payload: result})
	}))
	roots := x509.NewCertPool()
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(rootCert)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	config := Config{RuntimeID: "endpoint-1", DeviceID: "device-1", ControlURL: server.URL, StateDirectory: directory, ControlCAFile: write("server-ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})), ControlCertFile: write("client-cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})), ControlKeyFile: write("client-key.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})), EnrollmentID: "enrollment-1", EnrollmentChallengeID: "challenge-1", EnrollmentTokenFile: write("enrollment-token", []byte(token))}
	httpClient, publicKey, err := config.ControlHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	defer httpClient.CloseIdleConnections()
	wgKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	input, err := config.Enrollment(wgKey.PublicKey().String(), publicKey, "test-client")
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewControlClient(config.ControlURL, config.RuntimeID, httpClient, time.Minute, "mihomo")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := client.Enroll(ctx, input)
	if err != nil || !result.Accepted || calls.Load() != 1 {
		t.Fatalf("constructor enrollment chain did not reach verified handler: err=%v calls=%d", err, calls.Load())
	}
	for name, mutate := range map[string]func(*EnrollmentInput){
		"public PEM trailing newline": func(in *EnrollmentInput) { in.DevicePublicKey += "\n" },
		"public PEM leading space":    func(in *EnrollmentInput) { in.DevicePublicKey = " " + in.DevicePublicKey },
		"public key short":            func(in *EnrollmentInput) { in.DevicePublicKey = strings.Repeat("a", 31) },
		"public key oversized":        func(in *EnrollmentInput) { in.DevicePublicKey = strings.Repeat("a", 4097) },
		"token whitespace":            func(in *EnrollmentInput) { in.Token += "\n" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := input
			mutate(&bad)
			if _, err := client.Enroll(ctx, bad); err == nil {
				t.Fatal("malformed direct enrollment input accepted")
			}
			if calls.Load() != 1 {
				t.Fatal("malformed direct input reached network")
			}
		})
	}
}
