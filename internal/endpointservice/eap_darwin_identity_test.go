//go:build darwin

package endpointservice

import (
	"context"
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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDarwinEAPCSRIsStableAndExportStaysInsideDesktopHome(t *testing.T) {
	system := &DarwinEAPSystem{directory: t.TempDir(), home: t.TempDir(), uid: uint32(os.Getuid()), deviceID: "device-1"}
	first, err := system.CreateCSR(context.Background(), "request-1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := system.CreateCSR(context.Background(), "request-1")
	if err != nil || first != second {
		t.Fatalf("retry changed CSR: %v", err)
	}
	csr, err := parseEAPCSR(first)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(system.eapKeyPath("request-1"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("private key permissions: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test EAP CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://opensoha.local/network-eap/endpoint/device-1")
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "subject-1"}, URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute)}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(der)
	certificate := EAPCertificateResult{CredentialID: "credential-1", CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), CACertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), Fingerprint: fmt.Sprintf("sha256:%x", digest), ExpiresAt: leaf.NotAfter, Status: "pending"}
	profile := AdmissionProfile{ID: "profile-1", SiteID: "site-1", AccessMedium: "wifi", SSID: "Task53 test", Identity: "subject-1", ServerNames: []string{"radius.example.test"}, CACertificates: []string{certificate.CACertificatePEM}, WifiSecurity: "wpa2-enterprise"}
	artifact, err := system.ExportProfile(context.Background(), "request-1", profile, certificate, 0)
	if err != nil {
		t.Fatal(err)
	}
	path := artifact.Path
	relative, err := filepath.Rel(system.home, path)
	if err != nil || !filepath.IsLocal(relative) {
		t.Fatal("identity was exported outside desktop home")
	}
	raw, err := readFileBounded(path, 1<<20, false)
	if err != nil || !strings.Contains(string(raw), eapProfileIdentifier("device-1", profile.ID)) || strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatalf("profile export is invalid: %v", err)
	}
	plist, err := parseEAPPlist(raw)
	if err != nil {
		t.Fatal(err)
	}
	identity := plist["PayloadContent"].([]any)[0].(map[string]any)
	identityHash, err := eapIdentityPayloadHash(identity)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.IdentitySHA256 != identityHash {
		t.Fatal("exported identity ownership proof does not match")
	}
	info, err = os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("export permissions: %v", err)
	}
	other := &DarwinEAPSystem{home: t.TempDir(), uid: system.uid}
	if err := os.Symlink(t.TempDir(), filepath.Join(other.home, "Library")); err != nil {
		t.Fatal(err)
	}
	if _, err := other.exportEAPFile([]byte("test")); err == nil {
		t.Fatal("export escaped through a symlink")
	}
	if err := os.Chmod(system.eapKeyPath("request-1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := system.CreateCSR(context.Background(), "request-1"); err == nil {
		t.Fatal("insecure private key accepted")
	}
}
