package endpointservice

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"
)

func eapPayloadUUID(value string) string {
	digest := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x-%x-%x-%x-%x", digest[:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
}

func eapProfileIdentifier(deviceID, profileID string) string {
	return "org.opensoha.network.eap." + eapPayloadUUID(deviceID+"/"+profileID)
}

func eapPayload(kind, identifier, uuid string) map[string]any {
	return map[string]any{"PayloadType": kind, "PayloadIdentifier": identifier, "PayloadUUID": uuid, "PayloadVersion": 1}
}

func renderEAPMobileconfig(profile AdmissionProfile, deviceID string, certificate EAPCertificateResult, pkcs12 []byte, password string, ethernetPosition int, now time.Time) ([]byte, error) {
	if err := validateAdmissionProfile(profile, now); err != nil {
		return nil, err
	}
	if !identifierPattern.MatchString(deviceID) || !validReadbackHash(certificate.Fingerprint) || len(pkcs12) < 1 || len(pkcs12) > 65536 || len(password) < 32 || len(password) > 128 {
		return nil, errors.New("EAP profile certificate material is invalid")
	}
	bundle, err := eapMobileconfigPayload(profile, deviceID, certificate.Fingerprint, pkcs12, password, ethernetPosition)
	if err != nil {
		return nil, err
	}
	return marshalEAPMobileconfig(bundle)
}

func marshalEAPMobileconfig(bundle map[string]any) ([]byte, error) {
	var output bytes.Buffer
	output.WriteString(xml.Header + "<plist version=\"1.0\">")
	if err := writeEAPPlist(&output, bundle); err != nil {
		return nil, err
	}
	output.WriteString("</plist>\n")
	return output.Bytes(), nil
}

func eapMobileconfigPayload(profile AdmissionProfile, deviceID, fingerprint string, pkcs12 []byte, password string, ethernetPosition int) (map[string]any, error) {
	identifier := eapProfileIdentifier(deviceID, profile.ID)
	identityUUID := eapPayloadUUID(identifier + "/" + fingerprint)
	identity := eapPayload("com.apple.security.pkcs12", identifier+".identity", identityUUID)
	identity["PayloadContent"], identity["Password"] = pkcs12, password
	identity["KeyIsExtractable"], identity["AllowAllAppsAccess"] = false, false
	identity["PayloadDisplayName"] = "Soha EAP identity"
	payloads := []any{identity}
	anchors := []any{}
	for index, raw := range profile.CACertificates {
		ca, err := parseEAPCertificate(raw)
		if err != nil {
			return nil, err
		}
		uuid := eapPayloadUUID(identifier + "/anchor/" + raw)
		anchor := eapPayload("com.apple.security.root", identifier+".anchor."+strconv.Itoa(index), uuid)
		anchor["PayloadContent"] = ca.Raw
		payloads = append(payloads, anchor)
		anchors = append(anchors, uuid)
	}
	eap := map[string]any{"AcceptEAPTypes": []any{13}, "UserName": profile.Identity, "PayloadCertificateAnchorUUID": anchors,
		"TLSTrustedServerNames": profile.ServerNames, "TLSAllowTrustExceptions": false, "TLSCertificateIsRequired": true, "TLSMinimumVersion": "1.2"}
	kind := "com.apple.wifi.managed"
	ethernet := ""
	if profile.AccessMedium == "wired" {
		if ethernetPosition < 1 || ethernetPosition > 3 {
			return nil, errors.New("macOS requires one of the first three Ethernet services")
		}
		position := []string{"first", "second", "third"}[ethernetPosition-1]
		kind = "com.apple." + position + "ethernet.managed"
		ethernet = []string{"FirstEthernet", "SecondEthernet", "ThirdEthernet"}[ethernetPosition-1]
	}
	network := eapPayload(kind, identifier+".network", eapPayloadUUID(identifier+"/network"))
	network["EAPClientConfiguration"], network["PayloadCertificateUUID"] = eap, identityUUID
	network["SetupModes"] = []string{"System"}
	if profile.AccessMedium == "wifi" {
		network["SSID_STR"], network["AutoJoin"] = profile.SSID, true
		network["EncryptionType"] = "WPA2"
		if profile.WifiSecurity == "wpa3-enterprise" {
			network["EncryptionType"] = "WPA3"
		}
	} else {
		network["Interface"] = ethernet
	}
	payloads = append(payloads, network)
	bundle := eapPayload("Configuration", identifier, eapPayloadUUID(identifier))
	bundle["PayloadDisplayName"], bundle["PayloadOrganization"] = "Soha network access", "OpenSoha"
	bundle["PayloadContent"], bundle["PayloadScope"] = payloads, "System"
	return bundle, nil
}

func writeEAPPlist(output *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		output.WriteString("<dict>")
		for _, key := range keys {
			output.WriteString("<key>")
			if err := xml.EscapeText(output, []byte(key)); err != nil {
				return err
			}
			output.WriteString("</key>")
			if err := writeEAPPlist(output, typed[key]); err != nil {
				return err
			}
		}
		output.WriteString("</dict>")
	case []any:
		output.WriteString("<array>")
		for _, item := range typed {
			if err := writeEAPPlist(output, item); err != nil {
				return err
			}
		}
		output.WriteString("</array>")
	case []string:
		values := make([]any, len(typed))
		for index, item := range typed {
			values[index] = item
		}
		return writeEAPPlist(output, values)
	case []byte:
		output.WriteString("<data>" + base64.StdEncoding.EncodeToString(typed) + "</data>")
	case string:
		output.WriteString("<string>")
		if err := xml.EscapeText(output, []byte(typed)); err != nil {
			return err
		}
		output.WriteString("</string>")
	case int:
		output.WriteString("<integer>" + strconv.Itoa(typed) + "</integer>")
	case bool:
		output.WriteString("<" + strconv.FormatBool(typed) + "/>")
	default:
		return errors.New("unsupported EAP plist value")
	}
	return nil
}
