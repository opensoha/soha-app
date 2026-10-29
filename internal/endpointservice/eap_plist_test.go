package endpointservice

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func installedEAPPlistFixture(t *testing.T) (map[string]any, map[string]any) {
	t.Helper()
	certificate, _, profile := eapCertificateFixture(t)
	raw, err := renderEAPMobileconfig(profile, "device-1", certificate, []byte{1}, strings.Repeat("p", 32), 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	expected, err := parseEAPPlist(raw)
	if err != nil {
		t.Fatal(err)
	}
	return installedEAPProfileFixture(expected), expected
}

func installedEAPProfileFixture(expected map[string]any) map[string]any {
	items := []any{}
	for _, value := range expected["PayloadContent"].([]any) {
		payload := value.(map[string]any)
		item := map[string]any{"PayloadIdentifier": payload["PayloadIdentifier"], "PayloadUUID": payload["PayloadUUID"], "PayloadType": payload["PayloadType"]}
		if strings.HasSuffix(payload["PayloadType"].(string), ".managed") {
			content := map[string]any{}
			for key, value := range payload {
				content[key] = value
			}
			item["PayloadContent"] = content
		} else {
			item["PayloadContent"] = payload["PayloadContent"]
		}
		if payload["PayloadType"] == "com.apple.security.pkcs12" {
			for _, key := range []string{"Password", "KeyIsExtractable", "AllowAllAppsAccess"} {
				item[key] = payload[key]
			}
		}
		items = append(items, item)
	}
	installed := map[string]any{"ProfileIdentifier": expected["PayloadIdentifier"], "ProfileUUID": expected["PayloadUUID"], "ProfileItems": items}
	return installed
}

func TestDarwinEAPReadbackBindsOnlyOwnedSystemProfileAndExactTrust(t *testing.T) {
	installed, expected := installedEAPPlistFixture(t)
	identifier := installed["ProfileIdentifier"].(string)
	var raw bytes.Buffer
	raw.WriteString("<plist version=\"1.0\">")
	if err := writeEAPPlist(&raw, map[string]any{"_computerLevel": []any{installed}, "other-user": []any{installed}}); err != nil {
		t.Fatal(err)
	}
	raw.WriteString("</plist>")
	plist, err := parseEAPPlist(raw.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	owned, err := findDarwinEAPProfile(plist, identifier)
	if err != nil || owned == nil {
		t.Fatalf("owned = %+v, %v", owned, err)
	}
	if err := matchDarwinEAPPayloads(owned, expected); err != nil {
		t.Fatal(err)
	}
	if found, err := findDarwinEAPProfile(map[string]any{"other-user": []any{installed}}, identifier); err != nil || found != nil {
		t.Fatal("user profile was accepted as system profile")
	}
	if _, err := findDarwinEAPProfile(map[string]any{"_computerLevel": []any{installed, installed}}, identifier); err == nil {
		t.Fatal("duplicate managed profile was accepted")
	}
	for _, item := range owned["ProfileItems"].([]any) {
		payload := item.(map[string]any)
		if payload["PayloadType"] != "com.apple.wifi.managed" {
			continue
		}
		content := payload["PayloadContent"].(map[string]any)
		content["EAPClientConfiguration"].(map[string]any)["TLSAllowTrustExceptions"] = true
	}
	if err := matchDarwinEAPPayloads(owned, expected); err == nil {
		t.Fatal("weakened TLS trust was accepted")
	}
}

func TestEAPPlistParserRejectsAmbiguousAndUnboundedInput(t *testing.T) {
	for _, raw := range []string{
		`<plist><dict><key>a</key><string>one</string><key>a</key><string>two</string></dict></plist>`,
		`<plist><dict><key>a</key></dict></plist>`,
		`<plist><dict></dict><dict></dict></plist>`,
		`<plist><dict><key>a</key><unknown/></dict></plist>`,
		`<plist><dict><key>a</key>` + strings.Repeat("<array>", 34) + strings.Repeat("</array>", 34) + `</dict></plist>`,
		strings.Repeat("x", (4<<20)+1),
	} {
		if _, err := parseEAPPlist([]byte(raw)); err == nil {
			t.Fatal("invalid plist was accepted")
		}
	}
}

func TestDarwinEAPRemovalRejectsReplacedProfileContent(t *testing.T) {
	certificate, _, profile := eapCertificateFixture(t)
	adapter := EAPAdapter{Medium: "wifi"}
	for _, name := range []string{"unchanged", "ssid", "server names", "CA", "identity", "identity content", "opaque identity", "password", "extractable", "all apps", "missing access controls", "extra payload", "medium", "ethernet order"} {
		t.Run(name, func(t *testing.T) {
			selected, selectedAdapter := profile, adapter
			if name == "ethernet order" {
				selected.AccessMedium, selectedAdapter.Medium, selectedAdapter.EthernetPosition = "wired", "wired", 1
				selected.SSID = ""
			}
			raw, err := renderEAPMobileconfig(selected, "device-1", certificate, []byte{1}, strings.Repeat("p", 32), selectedAdapter.EthernetPosition, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			expected, err := parseEAPPlist(raw)
			if err != nil {
				t.Fatal(err)
			}
			installed := installedEAPProfileFixture(expected)
			items := installed["ProfileItems"].([]any)
			for _, item := range items {
				payload := item.(map[string]any)
				if strings.HasSuffix(payload["PayloadType"].(string), ".managed") {
					content := payload["PayloadContent"].(map[string]any)
					switch name {
					case "ssid":
						content["SSID_STR"] = "Another network"
					case "server names":
						content["EAPClientConfiguration"].(map[string]any)["TLSTrustedServerNames"] = []any{"another.example.test"}
					}
				}
				if name == "CA" && payload["PayloadType"] == "com.apple.security.root" {
					payload["PayloadContent"] = []byte("another CA")
				}
				if name == "identity content" && payload["PayloadType"] == "com.apple.security.pkcs12" {
					payload["PayloadContent"] = []byte("another identity")
				}
				if name == "opaque identity" && payload["PayloadType"] == "com.apple.security.pkcs12" {
					delete(payload, "PayloadContent")
				}
				if payload["PayloadType"] == "com.apple.security.pkcs12" {
					switch name {
					case "password":
						payload["Password"] = strings.Repeat("q", 32)
					case "extractable":
						payload["KeyIsExtractable"] = true
					case "all apps":
						payload["AllowAllAppsAccess"] = true
					case "missing access controls":
						delete(payload, "KeyIsExtractable")
					}
				}
				if name == "identity" && payload["PayloadType"] == "com.apple.security.pkcs12" {
					payload["PayloadUUID"] = eapPayloadUUID("another credential")
				}
			}
			switch name {
			case "extra payload":
				installed["ProfileItems"] = append(items, map[string]any{"PayloadIdentifier": "foreign"})
			case "medium":
				selectedAdapter.Medium = "wired"
			case "ethernet order":
				selectedAdapter.EthernetPosition = 2
			}
			err = matchDarwinEAPRemoval(installed, selected, selectedAdapter, "device-1", []EAPProfileIdentity{{Fingerprint: certificate.Fingerprint, IdentitySHA256: testEAPIdentityHash(t)}})
			if name == "unchanged" && err != nil {
				t.Fatal(err)
			}
			if name != "unchanged" && err == nil {
				t.Fatal("changed managed profile was accepted for removal")
			}
		})
	}
}

func TestDarwinEAPRemovalDoesNotRequireUnexpiredTrust(t *testing.T) {
	certificate, _, profile := eapCertificateFixture(t)
	raw, err := renderEAPMobileconfig(profile, "device-1", certificate, []byte{1}, strings.Repeat("p", 32), 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	expected, err := parseEAPPlist(raw)
	if err != nil {
		t.Fatal(err)
	}
	installed := installedEAPProfileFixture(expected)
	if _, err := renderEAPMobileconfig(profile, "device-1", certificate, []byte{1}, strings.Repeat("p", 32), 0, time.Now().Add(72*time.Hour)); err == nil {
		t.Fatal("expired CA was accepted for a new profile")
	}
	if err := matchDarwinEAPRemoval(installed, profile, EAPAdapter{Medium: "wifi"}, "device-1", []EAPProfileIdentity{{Fingerprint: certificate.Fingerprint, IdentitySHA256: testEAPIdentityHash(t)}}); err != nil {
		t.Fatalf("owned prior profile cannot be removed after expiry: %v", err)
	}
}

func testEAPIdentityHash(t *testing.T) string {
	t.Helper()
	digest, err := eapIdentityPayloadHash(map[string]any{"PayloadContent": []byte{1}, "Password": strings.Repeat("p", 32), "KeyIsExtractable": false, "AllowAllAppsAccess": false})
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
