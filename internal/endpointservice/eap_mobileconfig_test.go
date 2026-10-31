package endpointservice

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"
	"testing"
	"time"
)

func TestEAPMobileconfigUsesDedicatedIdentityAndExactServerTrust(t *testing.T) {
	certificate, _, profile := eapCertificateFixture(t)
	for _, medium := range []string{"wifi", "wired"} {
		t.Run(medium, func(t *testing.T) {
			candidate := profile
			candidate.AccessMedium = medium
			if medium == "wired" {
				candidate.SSID = ""
			}
			raw, err := renderEAPMobileconfig(candidate, "device-1", certificate, []byte("dedicated-pkcs12"), strings.Repeat("p", 32), 1, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			decoder := xml.NewDecoder(bytes.NewReader(raw))
			for {
				if _, err := decoder.Token(); err == io.EOF {
					break
				} else if err != nil {
					t.Fatal(err)
				}
			}
			text := string(raw)
			for _, required := range []string{"com.apple.security.pkcs12", "<key>KeyIsExtractable</key><false/>", "<key>AllowAllAppsAccess</key><false/>", "<key>AcceptEAPTypes</key><array><integer>13</integer></array>", "<key>UserName</key><string>subject-1</string>", "<key>TLSTrustedServerNames</key><array><string>radius.example.test</string></array>", "<key>TLSAllowTrustExceptions</key><false/>", "<key>TLSCertificateIsRequired</key><true/>", eapProfileIdentifier("device-1", profile.ID)} {
				if !strings.Contains(text, required) {
					t.Fatalf("missing %q", required)
				}
			}
			if medium == "wifi" && !strings.Contains(text, "<string>Soha &amp; Lab</string>") {
				t.Fatal("SSID was not XML escaped")
			}
			if medium == "wired" && (!strings.Contains(text, "com.apple.firstethernet.managed") || strings.Contains(text, "SSID_STR")) {
				t.Fatal("incorrect wired payload")
			}
		})
	}
}
