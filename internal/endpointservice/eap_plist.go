package endpointservice

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
)

func parseEAPPlist(raw []byte) (map[string]any, error) {
	if len(raw) > 4<<20 {
		return nil, errors.New("profile readback exceeds the safe size")
	}
	decoder, remaining := xml.NewDecoder(bytes.NewReader(raw)), 32768
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		if start, ok := token.(xml.StartElement); ok {
			if start.Name.Local != "plist" {
				return nil, errors.New("profile readback is not a plist")
			}
			value, err := nextEAPPlistValue(decoder, 0, &remaining)
			result, ok := value.(map[string]any)
			if err != nil || !ok {
				return nil, errors.New("profile readback is not a dictionary")
			}
			for {
				token, err := decoder.Token()
				if err == io.EOF {
					return result, nil
				}
				if err != nil {
					return nil, err
				}
				if _, ok := token.(xml.StartElement); ok {
					return nil, errors.New("profile readback has trailing values")
				}
			}
		}
	}
}

func nextEAPPlistValue(decoder *xml.Decoder, depth int, remaining *int) (any, error) {
	if depth > 32 || *remaining <= 0 {
		return nil, errors.New("profile readback exceeds the nesting or item limit")
	}
	*remaining--
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			if _, ended := token.(xml.EndElement); ended {
				return nil, io.EOF
			}
			continue
		}
		switch start.Name.Local {
		case "dict":
			result := map[string]any{}
			for {
				key, err := nextEAPPlistValue(decoder, depth+1, remaining)
				if err == io.EOF {
					return result, nil
				}
				if err != nil {
					return nil, err
				}
				name, ok := key.(eapPlistKey)
				if !ok {
					return nil, errors.New("profile dictionary has no key")
				}
				if _, duplicate := result[string(name)]; duplicate {
					return nil, errors.New("profile dictionary has duplicate keys")
				}
				value, err := nextEAPPlistValue(decoder, depth+1, remaining)
				if err != nil {
					return nil, errors.New("profile dictionary has no value")
				}
				result[string(name)] = value
			}
		case "array":
			result := []any{}
			for {
				value, err := nextEAPPlistValue(decoder, depth+1, remaining)
				if err == io.EOF {
					return result, nil
				}
				if err != nil {
					return nil, err
				}
				result = append(result, value)
			}
		default:
			var value string
			if err := decoder.DecodeElement(&value, &start); err != nil {
				return nil, err
			}
			switch start.Name.Local {
			case "key":
				return eapPlistKey(value), nil
			case "string", "date":
				return value, nil
			case "integer":
				return strconv.Atoi(strings.TrimSpace(value))
			case "true":
				return true, nil
			case "false":
				return false, nil
			case "data":
				return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(value), ""))
			case "real":
				return strconv.ParseFloat(strings.TrimSpace(value), 64)
			default:
				return nil, errors.New("profile contains an unsupported plist value")
			}
		}
	}
}

type eapPlistKey string

func findDarwinEAPProfile(plist map[string]any, identifier string) (map[string]any, error) {
	profiles, _ := plist["_computerLevel"].([]any)
	var result map[string]any
	for _, value := range profiles {
		profile, ok := value.(map[string]any)
		if !ok || profile["ProfileIdentifier"] != identifier {
			continue
		}
		if result != nil || profile["ProfileUUID"] != eapPayloadUUID(identifier) {
			return nil, errors.New("managed EAP profile identity is ambiguous")
		}
		result = profile
	}
	return result, nil
}

func matchDarwinEAPPayloads(installed map[string]any, expected map[string]any) error {
	items, _ := installed["ProfileItems"].([]any)
	payloads, _ := expected["PayloadContent"].([]any)
	if len(items) != len(payloads) {
		return errors.New("managed EAP profile payload count changed")
	}
	for _, value := range payloads {
		payload, ok := value.(map[string]any)
		if !ok {
			return errors.New("expected EAP payload is invalid")
		}
		var match map[string]any
		for _, item := range items {
			candidate, _ := item.(map[string]any)
			if candidate["PayloadIdentifier"] == payload["PayloadIdentifier"] {
				if match != nil {
					return errors.New("managed EAP payload is duplicated")
				}
				match = candidate
			}
		}
		if match == nil || match["PayloadUUID"] != payload["PayloadUUID"] || match["PayloadType"] != payload["PayloadType"] {
			return errors.New("managed EAP payload identity changed")
		}
		if payload["PayloadType"] == "com.apple.security.pkcs12" {
			continue
		}
		content, _ := match["PayloadContent"].(map[string]any)
		if payload["PayloadType"] == "com.apple.security.root" {
			if !reflect.DeepEqual(match["PayloadContent"], payload["PayloadContent"]) {
				return errors.New("managed EAP server CA changed")
			}
			continue
		}
		for key, value := range payload {
			if strings.HasPrefix(key, "Payload") && key != "PayloadCertificateUUID" {
				continue
			}
			if !reflect.DeepEqual(content[key], value) {
				return errors.New("managed EAP network trust or interface changed")
			}
		}
	}
	return nil
}

func matchDarwinEAPRemoval(installed map[string]any, profile AdmissionProfile, adapter EAPAdapter, deviceID string, identities []EAPProfileIdentity) error {
	if !identifierPattern.MatchString(deviceID) || !identifierPattern.MatchString(profile.ID) || len(identities) == 0 || len(identities) > 17 || profile.AccessMedium != adapter.Medium || profile.AccessMedium != "wifi" && profile.AccessMedium != "wired" {
		return errors.New("managed EAP removal identity is invalid")
	}
	// The user may have installed any exported generation before reporting readback.
	// Only protected fingerprints from this unchanged profile/adapter are eligible.
	for _, identity := range identities {
		if !validReadbackHash(identity.Fingerprint) || identity.IdentitySHA256 != "" && !validReadbackHash("sha256:"+identity.IdentitySHA256) {
			return errors.New("managed EAP removal fingerprint is invalid")
		}
	}
	for _, identity := range identities {
		if identity.IdentitySHA256 == "" {
			continue
		} // Legacy exports lack content ownership proof.
		expected, err := eapMobileconfigPayload(profile, deviceID, identity.Fingerprint, []byte{1}, strings.Repeat("x", 32), adapter.EthernetPosition)
		if err != nil {
			return err
		}
		raw, err := marshalEAPMobileconfig(expected)
		if err != nil {
			return err
		}
		expected, err = parseEAPPlist(raw)
		if err != nil {
			return err
		}
		if err := matchDarwinEAPPayloads(installed, expected); err == nil {
			for _, value := range installed["ProfileItems"].([]any) {
				payload := value.(map[string]any)
				if payload["PayloadType"] != "com.apple.security.pkcs12" {
					continue
				}
				digest, err := eapIdentityPayloadHash(payload)
				if err == nil && digest == identity.IdentitySHA256 {
					return nil
				}
			}
		}
	}
	return errors.New("managed EAP profile content or credential changed")
}

// Only a full readback of these identity security fields proves an owned export.
// Redacted or missing fields must not be inferred from the payload UUID.
func eapIdentityPayloadHash(payload map[string]any) (string, error) {
	content, contentOK := payload["PayloadContent"].([]byte)
	password, passwordOK := payload["Password"].(string)
	extractable, extractableOK := payload["KeyIsExtractable"].(bool)
	allApps, allAppsOK := payload["AllowAllAppsAccess"].(bool)
	if !contentOK || len(content) == 0 || len(content) > 65536 || !passwordOK || len(password) < 32 || len(password) > 128 || !extractableOK || extractable || !allAppsOK || allApps {
		return "", errors.New("managed EAP identity content or access controls are unavailable or changed")
	}
	raw, err := json.Marshal(map[string]any{"PayloadContent": content, "Password": password, "KeyIsExtractable": extractable, "AllowAllAppsAccess": allApps})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(raw)), nil
}
