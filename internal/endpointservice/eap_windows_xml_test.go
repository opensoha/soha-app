package endpointservice

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func TestEAPWindowsXMLUsesUserIdentityAndExactTrust(t *testing.T) {
	certificate, _, profile := eapCertificateFixture(t)
	leaf, err := parseEAPCertificate(certificate.CertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	thumb := sha1.Sum(leaf.Raw)
	for _, medium := range []string{"wifi", "wired"} {
		t.Run(medium, func(t *testing.T) {
			candidate := profile
			candidate.AccessMedium = medium
			if medium == "wired" {
				candidate.SSID = ""
			}
			result, err := renderEAPWindowsProfile(candidate, "device-1", certificate, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			for _, raw := range [][]byte{result.XML, result.UserData} {
				decoder := xml.NewDecoder(bytes.NewReader(raw))
				for {
					if _, err := decoder.Token(); err == io.EOF {
						break
					} else if err != nil {
						t.Fatal(err)
					}
				}
			}
			for _, part := range []string{`<authMode>user</authMode>`, `<SimpleCertSelection>false</SimpleCertSelection>`, `<DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation>`, `<ServerNames>radius.example.test</ServerNames>`, `<TrustedRootCA>`, `<DifferentUsername>true</DifferentUsername>`} {
				if !strings.Contains(string(result.XML), part) {
					t.Fatalf("missing %s", part)
				}
			}
			if !strings.Contains(string(result.UserData), `<Username>subject-1</Username>`) || !strings.Contains(string(result.UserData), fmt.Sprintf("<UserCert>%x</UserCert>", thumb)) || strings.Contains(string(result.UserData), "https://www.microsoft.com/provisioning") {
				t.Fatal("EAP user identity or namespace mismatch")
			}
			if medium == "wifi" && !strings.Contains(string(result.XML), "<hex>"+hex.EncodeToString([]byte(profile.SSID))+"</hex>") {
				t.Fatal("SSID bytes changed")
			}
			if medium == "wired" && !strings.Contains(string(result.XML), "<OneXEnforced>true</OneXEnforced>") {
				t.Fatal("wired authentication can fail open")
			}
		})
	}
}
