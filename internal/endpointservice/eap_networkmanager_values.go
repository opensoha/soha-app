package endpointservice

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

// nmEAPSettings contains native D-Bus values; conversion to variants is confined to Linux.
type nmEAPSettings map[string]map[string]any

type nmEAPCapability struct {
	Owner                                                       string // Unique bus owner, never the well-known name.
	AddConnection2, ExactServerMatch, TLS12, TLS, TTLSPAP, WPA3 bool
}

type nmEAPDevice struct {
	Path, Interface, MAC, Medium string
	Managed                      bool
}

type nmEAPMaterial struct {
	Method, InnerMethod                           string
	CAFile, ClientCertificateFile, PrivateKeyFile string
	Password                                      []byte
}

type nmEAPInput struct {
	DeviceID, Incarnation string
	Profile               AdmissionProfile
	Device                nmEAPDevice
	Material              nmEAPMaterial
}

type nmEAPReceipt struct {
	Settings                                               nmEAPSettings `json:"settings"`
	Owner, UUID, ConnectionPath, SettingsHash, Incarnation string
	Device                                                 nmEAPDevice
}

// The native implementation must validate every parent and the opened inode, not only mode bits.
type nmEAPFileCheck func(path string, private bool) error

func nmEAPFileURI(path string, private bool, check nmEAPFileCheck) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") || check == nil {
		return nil, errors.New("EAP material requires a protected absolute path")
	}
	if err := check(path, private); err != nil {
		return nil, errors.New("EAP material permissions or ownership are invalid")
	}
	return append([]byte("file://"+path), 0), nil
}

func buildNMEAPSettings(input nmEAPInput, capability nmEAPCapability, check nmEAPFileCheck, now time.Time) (nmEAPSettings, error) {
	profile, device, material := input.Profile, input.Device, input.Material
	if material.Method != admissionMethod(profile) || material.InnerMethod != profile.InnerMethod {
		return nil, errors.New("NetworkManager method differs from authorized profile")
	}
	if err := validateAdmissionProfile(profile, now); err != nil {
		return nil, err
	}
	if !identifierPattern.MatchString(input.DeviceID) || !identifierPattern.MatchString(input.Incarnation) || !strings.HasPrefix(capability.Owner, ":") || !capability.AddConnection2 || !capability.ExactServerMatch || !capability.TLS12 {
		return nil, errors.New("NetworkManager lacks the required protected EAP capabilities")
	}
	mac, err := net.ParseMAC(device.MAC)
	if err != nil || len(mac) != 6 || !device.Managed || device.Medium != profile.AccessMedium || !strings.HasPrefix(device.Path, "/org/freedesktop/NetworkManager/Devices/") || device.Interface == "" || len(device.Interface) > 15 || strings.ContainsAny(device.Interface, "/ :\x00\r\n") {
		return nil, errors.New("NetworkManager device identity is invalid")
	}
	ca, err := nmEAPFileURI(material.CAFile, false, check)
	if err != nil {
		return nil, err
	}
	eap := map[string]any{"eap": []string{material.Method}, "identity": profile.Identity, "ca-cert": ca, "domain-match": strings.Join(profile.ServerNames, ";"), "system-ca-certs": false, "optional": false,
		// NM flags 1 and 2 disable TLS 1.0 and 1.1; do not disable certificate/time checks.
		"phase1-auth-flags": uint32(3)}
	switch material.Method {
	case "tls":
		if !capability.TLS || material.InnerMethod != "" || len(material.Password) != 0 {
			return nil, errors.New("EAP TLS material is invalid or unsupported")
		}
		cert, err := nmEAPFileURI(material.ClientCertificateFile, false, check)
		if err != nil {
			return nil, err
		}
		key, err := nmEAPFileURI(material.PrivateKeyFile, true, check)
		if err != nil {
			return nil, err
		}
		eap["client-cert"], eap["private-key"] = cert, key
	case "ttls":
		if !capability.TTLSPAP || material.InnerMethod != "pap" || validateEAPPassword(string(material.Password)) != nil || material.PrivateKeyFile != "" || material.ClientCertificateFile != "" {
			return nil, errors.New("EAP TTLS PAP credentials are invalid or unsupported")
		}
		if !utf8.Valid(material.Password) || strings.ContainsRune(string(material.Password), '\x00') {
			return nil, errors.New("NetworkManager D-Bus STRING cannot represent a NUL or non-UTF-8 password")
		}
		eap["phase2-auth"], eap["password"], eap["password-flags"] = "pap", string(material.Password), uint32(2)
	default:
		return nil, errors.New("EAP method is unsupported")
	}
	kind := "802-3-ethernet"
	if device.Medium == "wifi" {
		kind = "802-11-wireless"
	}
	uuid := eapPayloadUUID(input.DeviceID + "/" + profile.ID + "/" + input.Incarnation)
	settings := nmEAPSettings{
		"user":       {"data": map[string]string{"org.opensoha.eap.incarnation": input.Incarnation, "org.opensoha.eap.device": input.DeviceID}},
		"connection": {"id": "Soha-EAP-" + uuid, "uuid": uuid, "type": kind, "interface-name": device.Interface, "autoconnect": false},
		"802-1x":     eap,
		"ipv4":       {"method": "auto"}, "ipv6": {"method": "auto"},
	}
	if kind == "802-11-wireless" {
		if profile.WifiSecurity == "wpa3-enterprise" && !capability.WPA3 {
			return nil, errors.New("NetworkManager WPA3 enterprise is unavailable")
		}
		settings[kind] = map[string]any{"ssid": []byte(profile.SSID), "mode": "infrastructure", "mac-address": []byte(mac)}
		security := map[string]any{"key-mgmt": "wpa-eap", "proto": []string{"rsn"}, "pairwise": []string{"ccmp"}, "group": []string{"ccmp"}}
		if profile.WifiSecurity == "wpa3-enterprise" {
			security["pmf"] = uint32(3)
		}
		settings["802-11-wireless-security"] = security
	} else {
		settings[kind] = map[string]any{"mac-address": []byte(mac)}
	}
	return settings, nil
}

func nmEAPSettingsHash(settings nmEAPSettings) string {
	// GetSettings omits secrets; never persist a password or its digest in a receipt.
	clean := nmEAPSettings{}
	for group, values := range settings {
		clean[group] = map[string]any{}
		for key, value := range values {
			if group != "802-1x" || key != "password" {
				clean[group][key] = value
			}
		}
	}
	raw, _ := json.Marshal(clean)
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

// Operations are bound to the receipt's unique bus owner. Implementations reject owner,
// UUID, incarnation, device or settings changes immediately before each destructive call.
type nmEAPOps interface {
	Capability(context.Context) (nmEAPCapability, error)
	Add(context.Context, nmEAPSettings, uint32) (string, error)
	Inspect(context.Context, nmEAPReceipt) (nmEAPReceipt, error)
	Activate(context.Context, nmEAPReceipt) error
	WaitActivated(context.Context, nmEAPReceipt) error
	RemoveOwned(context.Context, nmEAPReceipt) error
}

var errNMEAPConnectionAbsent = errors.New("NetworkManager has no connection with the managed UUID")

func reconcileNMEAPStage(ctx context.Context, ops nmEAPOps, receipt nmEAPReceipt, sameRequest bool) (nmEAPReceipt, bool, error) {
	if !sameRequest {
		return receipt, false, ops.RemoveOwned(ctx, receipt)
	}
	actual, err := ops.Inspect(ctx, receipt)
	if errors.Is(err, errNMEAPConnectionAbsent) {
		return receipt, false, nil
	}
	return actual, err == nil, err
}

type nmEAPRemovalOps interface {
	Inspect(context.Context, nmEAPReceipt) (nmEAPReceipt, error)
	active(context.Context, nmEAPReceipt) (path string, owned bool, err error)
	deactivate(context.Context, string) error
	deleteConnection(context.Context, string) error
}

func removeNMEAPProfile(ctx context.Context, ops nmEAPRemovalOps, receipt nmEAPReceipt) error {
	actual, err := ops.Inspect(ctx, receipt)
	if errors.Is(err, errNMEAPConnectionAbsent) {
		return nil
	}
	if err != nil {
		return err
	}
	active, owned, err := ops.active(ctx, actual)
	if err != nil {
		return err
	}
	if owned {
		if err := ops.deactivate(ctx, active); err != nil {
			return err
		}
	}
	if _, err := ops.Inspect(ctx, actual); err != nil {
		if errors.Is(err, errNMEAPConnectionAbsent) {
			return nil
		}
		return err
	}
	// NM has no compare-delete API. Recheck ownership immediately before deleting.
	return ops.deleteConnection(ctx, actual.ConnectionPath)
}

func matchNMEAPReceipt(expected, actual nmEAPReceipt) error {
	if expected.Owner == "" || expected.UUID == "" || expected.ConnectionPath == "" || expected.Incarnation == "" || expected.SettingsHash == "" || !reflect.DeepEqual(expected, actual) {
		return errors.New("managed NetworkManager connection identity changed")
	}
	return nil
}

// Cleanup gets an independent deadline after cancellation. A retained receipt is the
// retry identity when cleanup fails; callers must durably retain it before any add.
func connectNMEAP(ctx context.Context, ops nmEAPOps, input nmEAPInput, check nmEAPFileCheck, now time.Time, persist func(nmEAPReceipt) error) (receipt nmEAPReceipt, result error) {
	if ops == nil || persist == nil {
		return receipt, errors.New("NetworkManager lifecycle dependencies are unavailable")
	}
	capability, err := ops.Capability(ctx)
	if err != nil {
		return receipt, err
	}
	settings, err := buildNMEAPSettings(input, capability, check, now)
	if err != nil {
		return receipt, err
	}
	defer delete(settings["802-1x"], "password")
	expectedSettings := nmEAPSettings{}
	for group, values := range settings {
		expectedSettings[group] = map[string]any{}
		for key, value := range values {
			if group != "802-1x" || key != "password" {
				expectedSettings[group][key] = value
			}
		}
	}
	receipt = nmEAPReceipt{Settings: expectedSettings, Owner: capability.Owner, UUID: settings["connection"]["uuid"].(string), SettingsHash: nmEAPSettingsHash(settings), Incarnation: input.Incarnation, Device: input.Device}
	// Persist the operation identity before Add: cancellation can race the D-Bus reply.
	if err := persist(receipt); err != nil {
		return receipt, err
	}
	defer func() {
		if result != nil {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			result = errors.Join(result, ops.RemoveOwned(cleanup, receipt))
		}
	}()
	if err := ctx.Err(); err != nil {
		return receipt, err
	}
	// IN_MEMORY | BLOCK_AUTOCONNECT: never write the user's password to a keyfile.
	receipt.ConnectionPath, err = ops.Add(ctx, settings, 0x2|0x20)
	if err != nil {
		return receipt, errors.New("NetworkManager connection installation failed")
	}
	if err := persist(receipt); err != nil {
		return receipt, err
	}
	actual, err := ops.Inspect(ctx, receipt)
	if err != nil {
		return receipt, err
	}
	if err := matchNMEAPReceipt(receipt, actual); err != nil {
		return receipt, err
	}
	if err := ctx.Err(); err != nil {
		return receipt, err
	}
	if err := ops.Activate(ctx, receipt); err != nil {
		return receipt, errors.New("NetworkManager activation failed")
	}
	if err := ops.WaitActivated(ctx, receipt); err != nil {
		return receipt, err
	}
	actual, err = ops.Inspect(ctx, receipt)
	if err != nil {
		return receipt, err
	}
	if err := matchNMEAPReceipt(receipt, actual); err != nil {
		return receipt, err
	}
	return receipt, ctx.Err()
}
