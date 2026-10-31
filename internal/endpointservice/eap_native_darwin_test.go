//go:build darwin && cgo

package endpointservice

import (
	"context"
	"testing"
)

func TestDarwinEAPIdentityReadbackRejectsUninstalledCertificate(t *testing.T) {
	certificate, _, _ := eapCertificateFixture(t)
	leaf, err := parseEAPCertificate(certificate.CertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := darwinEAPIdentityReadback(context.Background(), leaf.Raw); err == nil {
		t.Fatal("uninstalled private identity was accepted")
	}
}
