package endpointservice

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

func eapCertificateFixture(t *testing.T, changes ...func(*x509.Certificate)) (EAPCertificateResult, string, AdmissionProfile) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "EAP issuer"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(48 * time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, issuer, issuer, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://opensoha.local/network-eap/endpoint/device-1")
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "subject-1"}, URIs: []*url.URL{uri}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(23 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	for _, change := range changes {
		change(leaf)
	}
	der, err = x509.CreateCertificate(rand.Reader, leaf, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(der)
	result := EAPCertificateResult{CredentialID: "eap-1", CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), CACertificatePEM: caPEM, Fingerprint: fmt.Sprintf("sha256:%x", digest), ExpiresAt: leaf.NotAfter, Status: "pending"}
	profile := AdmissionProfile{ID: "profile-1", SiteID: "site-1", AccessMedium: "wifi", SSID: "Soha & Lab", Identity: "subject-1", ServerNames: []string{"radius.example.test"}, CACertificates: []string{caPEM}, WifiSecurity: "wpa2-enterprise"}
	return result, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), profile
}

func TestEAPCertificateRejectsOtherPurposesAndIdentities(t *testing.T) {
	for name, change := range map[string]func(*x509.Certificate){
		"control namespace":     func(c *x509.Certificate) { c.URIs[0].Path = "/network-control/endpoint/device-1" },
		"server authentication": func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth) },
		"DNS identity":          func(c *x509.Certificate) { c.DNSNames = []string{"device.example.test"} },
		"CA privilege": func(c *x509.Certificate) {
			c.IsCA = true
			c.BasicConstraintsValid = true
			c.KeyUsage |= x509.KeyUsageCertSign
		},
		"long lifetime": func(c *x509.Certificate) { c.NotAfter = time.Now().Add(25 * time.Hour).UTC().Truncate(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			result, csr, _ := eapCertificateFixture(t, change)
			if err := validateEAPCertificate(result, csr, "device-1", "subject-1", time.Now()); err == nil {
				t.Fatal("overprivileged certificate accepted")
			}
		})
	}
}

func TestEAPCertificateBindsIssuerKeyAndEndpointIdentity(t *testing.T) {
	result, csr, _ := eapCertificateFixture(t)
	if err := validateEAPCertificate(result, csr, "device-1", "subject-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	other, otherCSR, _ := eapCertificateFixture(t)
	tests := []struct {
		name                 string
		change               func(*EAPCertificateResult)
		csr, device, subject string
	}{
		{name: "different private key", csr: otherCSR},
		{name: "different endpoint", device: "device-2"},
		{name: "different subject", subject: "subject-2"},
		{name: "different issuer", change: func(r *EAPCertificateResult) { r.CACertificatePEM = other.CACertificatePEM }},
		{name: "different digest", change: func(r *EAPCertificateResult) { r.Fingerprint = "sha256:" + strings.Repeat("0", 64) }},
		{name: "different expiry", change: func(r *EAPCertificateResult) { r.ExpiresAt = r.ExpiresAt.Add(time.Second) }},
		{name: "private key block", change: func(r *EAPCertificateResult) {
			r.CertificatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2}})) + r.CertificatePEM
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := result
			if test.change != nil {
				test.change(&candidate)
			}
			inputCSR, device, subject := test.csr, test.device, test.subject
			if inputCSR == "" {
				inputCSR = csr
			}
			if device == "" {
				device = "device-1"
			}
			if subject == "" {
				subject = "subject-1"
			}
			if err := validateEAPCertificate(candidate, inputCSR, device, subject, time.Now()); err == nil {
				t.Fatal("unbound EAP certificate accepted")
			}
		})
	}
}

func TestAdmissionProfileRequiresExactServerTrust(t *testing.T) {
	_, _, profile := eapCertificateFixture(t)
	if err := validateAdmissionProfile(profile, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*AdmissionProfile){
		func(p *AdmissionProfile) { p.ServerNames = []string{"*.example.test"} },
		func(p *AdmissionProfile) { p.ServerNames = []string{"radius.example.test", "RADIUS.example.test"} },
		func(p *AdmissionProfile) { p.CACertificates = nil },
		func(p *AdmissionProfile) { p.SSID = "bad\x00ssid" },
		func(p *AdmissionProfile) { p.AccessMedium = "wired" },
		func(p *AdmissionProfile) { p.ClientCertificateFingerprint = "sha256:bad" },
	} {
		candidate := profile
		mutate(&candidate)
		if err := validateAdmissionProfile(candidate, time.Now()); err == nil {
			t.Fatalf("unsafe profile accepted: %+v", candidate)
		}
	}
}
