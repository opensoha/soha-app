package endpointservice

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

func TestWindowsEAPProfileReadbackPreservesTrustAndIdentity(t *testing.T) {
	certificate, _, profile := eapCertificateFixture(t)
	configuration, err := renderEAPWindowsProfile(profile, "device-1", certificate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := matchEAPWindowsXML(configuration.XML, configuration.XML); err != nil {
		t.Fatal(err)
	}
	actual := strings.ReplaceAll(string(configuration.XML), "><", ">\r\n<")
	actual = strings.ReplaceAll(actual, `encoding="UTF-8"`, `encoding="UTF-16"`)
	units := utf16.Encode([]rune(actual))
	raw := make([]byte, 2+2*len(units))
	raw[0], raw[1] = 0xff, 0xfe
	for index, unit := range units {
		binary.LittleEndian.PutUint16(raw[2+2*index:], unit)
	}
	if err := matchEAPWindowsXML(raw, configuration.XML); err != nil {
		t.Fatal(err)
	}
	for _, changed := range []string{
		strings.Replace(string(configuration.XML), ">true</PerformServerValidation>", ">false</PerformServerValidation>", 1),
		strings.Replace(string(configuration.XML), profile.ServerNames[0], "other-radius.example.test", 1),
		strings.Replace(string(configuration.XML), "<TrustedRootCA>", "<UnknownRootCA>", 1),
		strings.Replace(string(configuration.XML), "<authMode>user</authMode>", "<authMode>machine</authMode>", 1),
		strings.Replace(string(configuration.XML), "</MSM>", "<unexpected>true</unexpected></MSM>", 1),
	} {
		if err := matchEAPWindowsXML([]byte(changed), configuration.XML); err == nil {
			t.Fatal("changed EAP server trust, authentication mode or unknown field was accepted")
		}
	}
}

func TestWindowsEAPProfileParserRejectsAmbiguousInput(t *testing.T) {
	for _, raw := range []string{
		`<p xmlns="urn:test"><field>one</field><field>two</field></p>`,
		`<p xmlns="urn:test" unexpected="ignored"/>`,
		`<p xmlns="urn:test" xmlns:e="urn:evil" e:xmlns="ignored"/>`,
		`<!DOCTYPE p [<!ENTITY x "hidden">]><p xmlns="urn:test">&x;</p>`,
		`<p xmlns="urn:test"/><p xmlns="urn:test"/>`,
		strings.Repeat(`<p xmlns="urn:test">`, 33) + strings.Repeat(`</p>`, 33),
		strings.Repeat("x", (128<<10)+1),
	} {
		if _, err := parseEAPWindowsXML([]byte(raw)); err == nil {
			t.Fatal("ambiguous or unbounded EAP profile was accepted")
		}
	}
	left := []byte(`<p xmlns="urn:test"><a>one</a><b>two</b></p>`)
	right := []byte(`<q:p xmlns:q="urn:test"><q:b>two</q:b><q:a>one</q:a></q:p>`)
	if err := matchEAPWindowsXML(left, right); err != nil {
		t.Fatal("namespace prefixes or field order changed profile meaning:", err)
	}
}

func TestWindowsEAPWiredBaselineRejectsExistingAuthentication(t *testing.T) {
	disabled := []byte(`<LANProfile xmlns="http://www.microsoft.com/networking/LAN/profile/v1"><MSM><security><OneXEnabled>false</OneXEnabled></security></MSM></LANProfile>`)
	if !eapWindowsLANBaselineAllowed(disabled) {
		t.Fatal("disabled wired baseline cannot be preserved")
	}
	for _, raw := range [][]byte{nil, []byte(strings.Replace(string(disabled), ">false<", ">true<", 1)), []byte(strings.ReplaceAll(string(disabled), "OneXEnabled", "unknown"))} {
		if eapWindowsLANBaselineAllowed(raw) {
			t.Fatal("existing or unknown wired authentication may be replaced")
		}
	}
}
