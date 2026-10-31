package endpointservice

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

func parseEAPCSR(raw string) (*x509.CertificateRequest, error) {
	block, rest := pem.Decode([]byte(raw))
	if len(raw) > 4096 || block == nil || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("EAP CSR must contain one public certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, errors.New("EAP CSR signature is invalid")
	}
	public, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() {
		return nil, errors.New("EAP CSR requires a P-256 key")
	}
	return csr, nil
}

func parseEAPCertificate(raw string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(raw))
	if len(raw) > 16384 || block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("EAP certificate must contain one public certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func validateEAPCertificate(result EAPCertificateResult, csrPEM, deviceID, subjectID string, now time.Time) error {
	csr, err := parseEAPCSR(csrPEM)
	if err != nil {
		return err
	}
	certificate, err := parseEAPCertificate(result.CertificatePEM)
	if err != nil {
		return err
	}
	ca, err := parseEAPCertificate(result.CACertificatePEM)
	if err != nil || !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("EAP issuer certificate is invalid")
	}
	expectedURI := "spiffe://opensoha.local/network-eap/endpoint/" + deviceID
	if !bytes.Equal(csr.RawSubjectPublicKeyInfo, certificate.RawSubjectPublicKeyInfo) || certificate.IsCA || certificate.Subject.CommonName != subjectID || len(certificate.URIs) != 1 || certificate.URIs[0].String() != expectedURI || len(certificate.DNSNames) != 0 || len(certificate.IPAddresses) != 0 || len(certificate.EmailAddresses) != 0 || len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(certificate.UnknownExtKeyUsage) != 0 || certificate.KeyUsage != x509.KeyUsageDigitalSignature || !certificate.NotAfter.Equal(result.ExpiresAt) || !certificate.NotAfter.After(now) || certificate.NotAfter.After(now.Add(24*time.Hour)) {
		return errors.New("EAP certificate does not match the endpoint identity, key or lifetime")
	}
	digest := sha256.Sum256(certificate.Raw)
	if result.Fingerprint != fmt.Sprintf("sha256:%x", digest) {
		return errors.New("EAP certificate fingerprint does not match")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, err = certificate.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	return err
}

func validateAdmissionProfile(profile AdmissionProfile, now time.Time) error {
	if !identifierPattern.MatchString(profile.ID) || !identifierPattern.MatchString(profile.SiteID) || !identifierPattern.MatchString(profile.Identity) || profile.AccessMedium != "wifi" && profile.AccessMedium != "wired" || profile.WifiSecurity != "wpa2-enterprise" && profile.WifiSecurity != "wpa3-enterprise" || profile.ClientCertificateFingerprint != "" && !validReadbackHash(profile.ClientCertificateFingerprint) {
		return errors.New("admission profile identity or medium is invalid")
	}
	if profile.AccessMedium == "wifi" && (len(profile.SSID) < 1 || len(profile.SSID) > 32 || !utf8.ValidString(profile.SSID) || strings.ContainsAny(profile.SSID, "\x00\r\n")) || profile.AccessMedium == "wired" && profile.SSID != "" {
		return errors.New("admission profile SSID is invalid")
	}
	if len(profile.ServerNames) < 1 || len(profile.ServerNames) > 16 || len(profile.CACertificates) < 1 || len(profile.CACertificates) > 8 {
		return errors.New("admission profile server trust is incomplete")
	}
	seen := map[string]bool{}
	for _, name := range profile.ServerNames {
		if len(name) > 253 || !validEndpointHost(name) || strings.ContainsAny(name, "*;\x00") || seen[strings.ToLower(name)] {
			return errors.New("admission profile requires exact unique server DNS names")
		}
		seen[strings.ToLower(name)] = true
	}
	seen = map[string]bool{}
	for _, raw := range profile.CACertificates {
		ca, err := parseEAPCertificate(raw)
		if err != nil || seen[raw] || !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) {
			return errors.New("admission profile CA is invalid, duplicate or expired")
		}
		seen[raw] = true
	}
	return nil
}
