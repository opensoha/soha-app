package endpointservice

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func nmEAPFixture(t *testing.T) (nmEAPInput, nmEAPCapability) {
	_, _, profile := eapCertificateFixture(t)
	profile.EAPMethod, profile.InnerMethod, profile.CredentialSource, profile.ProfileRevision = "ttls", "pap", "user-input", "sha256:"+strings.Repeat("a", 64)
	return nmEAPInput{DeviceID: "device-1", Incarnation: "attempt-1", Profile: profile,
			Device:   nmEAPDevice{Path: "/org/freedesktop/NetworkManager/Devices/4", Interface: "wlan0", MAC: "02:00:00:00:00:04", Medium: "wifi", Managed: true},
			Material: nmEAPMaterial{Method: "ttls", InnerMethod: "pap", CAFile: "/protected/ca.pem", Password: []byte("test-secret")}},
		nmEAPCapability{Owner: ":1.7", AddConnection2: true, ExactServerMatch: true, TLS12: true, TLS: true, TTLSPAP: true}
}
func nmAllowFile(string, bool) error { return nil }

func TestNMEAPSettingsTrustAndSecrets(t *testing.T) {
	input, capability := nmEAPFixture(t)
	for _, method := range []string{"ttls", "tls"} {
		t.Run(method, func(t *testing.T) {
			candidate := input
			if method == "tls" {
				candidate.Profile.EAPMethod, candidate.Profile.InnerMethod, candidate.Profile.CredentialSource = "tls", "", ""
				candidate.Material = nmEAPMaterial{Method: "tls", CAFile: "/protected/ca.pem", ClientCertificateFile: "/protected/cert.pem", PrivateKeyFile: "/protected/key.pem"}
			}
			checkedKey := false
			settings, err := buildNMEAPSettings(candidate, capability, func(path string, private bool) error {
				if private {
					checkedKey = path == "/protected/key.pem"
				}
				return nil
			}, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if method == "tls" && !checkedKey {
				t.Fatal("private key permissions not checked")
			}
			eap := settings["802-1x"]
			if eap["domain-match"] != "radius.example.test" || eap["system-ca-certs"] != false || eap["optional"] != false || eap["phase1-auth-flags"] != uint32(3) {
				t.Fatal("weakened server validation")
			}
			if !reflect.DeepEqual(settings["802-11-wireless"]["ssid"], []byte(input.Profile.SSID)) {
				t.Fatal("SSID changed")
			}
			if settings["connection"]["autoconnect"] != false {
				t.Fatal("automatic activation allowed")
			}
			if method == "ttls" {
				if eap["phase2-auth"] != "pap" || eap["password-flags"] != uint32(2) {
					t.Fatal("unexpected inner method or secret policy")
				}
				before := nmEAPSettingsHash(settings)
				eap["password"] = "different"
				if before != nmEAPSettingsHash(settings) {
					t.Fatal("receipt hashes the password")
				}
			}
		})
	}
}
func TestNMEAPRejectsUnsupportedOrUnsafeInput(t *testing.T) {
	for name, mutate := range map[string]func(*nmEAPInput, *nmEAPCapability){
		"missing NM":       func(_ *nmEAPInput, c *nmEAPCapability) { c.Owner = "" },
		"old NM":           func(_ *nmEAPInput, c *nmEAPCapability) { c.AddConnection2 = false },
		"no exact names":   func(_ *nmEAPInput, c *nmEAPCapability) { c.ExactServerMatch = false },
		"old TLS":          func(_ *nmEAPInput, c *nmEAPCapability) { c.TLS12 = false },
		"no TTLS":          func(_ *nmEAPInput, c *nmEAPCapability) { c.TTLSPAP = false },
		"PEAP fallback":    func(i *nmEAPInput, _ *nmEAPCapability) { i.Material.Method = "peap" },
		"wrong inner":      func(i *nmEAPInput, _ *nmEAPCapability) { i.Material.InnerMethod = "mschapv2" },
		"empty password":   func(i *nmEAPInput, _ *nmEAPCapability) { i.Material.Password = nil },
		"NUL password":     func(i *nmEAPInput, _ *nmEAPCapability) { i.Material.Password = []byte("bad\x00secret") },
		"relative CA":      func(i *nmEAPInput, _ *nmEAPCapability) { i.Material.CAFile = "ca.pem" },
		"unmanaged device": func(i *nmEAPInput, _ *nmEAPCapability) { i.Device.Managed = false },
		"wrong MAC":        func(i *nmEAPInput, _ *nmEAPCapability) { i.Device.MAC = "invalid" },
		"wrong medium":     func(i *nmEAPInput, _ *nmEAPCapability) { i.Device.Medium = "wired" },
		"bad SSID":         func(i *nmEAPInput, _ *nmEAPCapability) { i.Profile.SSID = "bad\x00SSID" },
		"missing CA":       func(i *nmEAPInput, _ *nmEAPCapability) { i.Profile.CACertificates = nil },
		"wildcard server":  func(i *nmEAPInput, _ *nmEAPCapability) { i.Profile.ServerNames = []string{"*.example.test"} },
		"WPA3 unsupported": func(i *nmEAPInput, _ *nmEAPCapability) { i.Profile.WifiSecurity = "wpa3-enterprise" },
	} {
		t.Run(name, func(t *testing.T) {
			i, c := nmEAPFixture(t)
			mutate(&i, &c)
			if _, err := buildNMEAPSettings(i, c, nmAllowFile, time.Now()); err == nil {
				t.Fatal("unsafe input accepted")
			}
		})
	}
	i, c := nmEAPFixture(t)
	if _, err := buildNMEAPSettings(i, c, func(string, bool) error { return errors.New("unsafe owner") }, time.Now()); err == nil {
		t.Fatal("unprotected CA accepted")
	}
}

type nmMockOps struct {
	capability              nmEAPCapability
	current                 nmEAPReceipt
	added                   nmEAPSettings
	flags                   uint32
	activateErr, cleanupErr error
	inspectErr              error
	removed, activated      bool
	cancel                  context.CancelFunc
	mutate                  func(*nmEAPReceipt)
}

func (m *nmMockOps) Capability(context.Context) (nmEAPCapability, error) { return m.capability, nil }
func (m *nmMockOps) Add(_ context.Context, s nmEAPSettings, f uint32) (string, error) {
	m.added = s
	m.flags = f
	return "/org/freedesktop/NetworkManager/Settings/8", nil
}
func (m *nmMockOps) Inspect(_ context.Context, r nmEAPReceipt) (nmEAPReceipt, error) {
	if m.mutate != nil {
		m.mutate(&r)
	}
	return r, m.inspectErr
}

type nmRemovalProbe struct {
	path                 string
	owned                bool
	activeErr            error
	deactivated, deleted string
	inspections          int
	drift                bool
}

func (m *nmRemovalProbe) Inspect(_ context.Context, r nmEAPReceipt) (nmEAPReceipt, error) {
	m.inspections++
	if m.drift && m.inspections > 1 {
		return r, errors.New("profile changed before deletion")
	}
	return r, nil
}

func (m *nmRemovalProbe) active(context.Context, nmEAPReceipt) (string, bool, error) {
	return m.path, m.owned, m.activeErr
}

func (m *nmRemovalProbe) deactivate(_ context.Context, path string) error {
	m.deactivated = path
	return nil
}

func (m *nmRemovalProbe) deleteConnection(_ context.Context, path string) error {
	m.deleted = path
	return nil
}

func TestNMEAPRemoveOwnedInactiveProfilePreservesExternalConnection(t *testing.T) {
	r := nmEAPReceipt{ConnectionPath: "/settings/8", UUID: "managed"}
	ops := &nmRemovalProbe{path: "/active/foreign"}
	if err := removeNMEAPProfile(context.Background(), ops, r); err != nil {
		t.Fatal(err)
	}
	if ops.deactivated != "" || ops.deleted != r.ConnectionPath || ops.inspections != 2 {
		t.Fatalf("foreign active connection was not preserved: %+v", ops)
	}
	ops = &nmRemovalProbe{path: "/active/managed", owned: true}
	if err := removeNMEAPProfile(context.Background(), ops, r); err != nil || ops.deactivated != ops.path || ops.deleted != r.ConnectionPath {
		t.Fatalf("owned active connection was not removed: %+v, %v", ops, err)
	}
	for _, ops := range []*nmRemovalProbe{
		{activeErr: errors.New("active UUID could not be read")},
		{path: "/active/foreign", drift: true},
	} {
		if err := removeNMEAPProfile(context.Background(), ops, r); err == nil || ops.deactivated != "" || ops.deleted != "" {
			t.Fatalf("unverified connection was changed: %+v, %v", ops, err)
		}
	}
}

func TestNMEAPRestageOnlyAfterExactUUIDAbsence(t *testing.T) {
	r := nmEAPReceipt{ConnectionPath: "/settings/8", UUID: "managed"}
	ctx := context.Background()
	for _, test := range []struct {
		name    string
		inspect error
		reuse   bool
		fail    bool
	}{
		{name: "reuse verified current receipt", reuse: true},
		{name: "restage after confirmed cleanup", inspect: errNMEAPConnectionAbsent},
		{name: "preserve on unknown D-Bus object", inspect: errors.New("UnknownObject"), fail: true},
		{name: "preserve on owner drift", inspect: errors.New("owner changed"), fail: true},
		{name: "preserve on timeout", inspect: context.DeadlineExceeded, fail: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ops := &nmMockOps{inspectErr: test.inspect}
			actual, reused, err := reconcileNMEAPStage(ctx, ops, r, true)
			if (err != nil) != test.fail || reused != test.reuse || actual.UUID != r.UUID || ops.removed {
				t.Fatalf("unexpected staging decision: reused=%v, receipt=%+v, err=%v", reused, actual, err)
			}
		})
	}
}
func (m *nmMockOps) Activate(_ context.Context, r nmEAPReceipt) error {
	m.activated = true
	m.current = r
	return m.activateErr
}
func (m *nmMockOps) WaitActivated(ctx context.Context, _ nmEAPReceipt) error {
	if m.cancel != nil {
		m.cancel()
	}
	return ctx.Err()
}
func (m *nmMockOps) RemoveOwned(ctx context.Context, _ nmEAPReceipt) error {
	if ctx.Err() != nil {
		return errors.New("cleanup inherited cancellation")
	}
	m.removed = true
	return m.cleanupErr
}

func TestNMEAPLifecycleSuccessRefusalAndCancellation(t *testing.T) {
	for _, mode := range []string{"success", "refused", "cancelled", "cleanup failed", "persist failed", "owner changed", "device changed", "incarnation changed", "UUID changed", "settings changed"} {
		t.Run(mode, func(t *testing.T) {
			input, capability := nmEAPFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ops := &nmMockOps{capability: capability}
			switch mode {
			case "refused":
				ops.activateErr = errors.New("secret must never appear")
			case "cancelled":
				ops.cancel = cancel
			case "cleanup failed":
				ops.activateErr = errors.New("refused")
				ops.cleanupErr = errors.New("cleanup pending")
			case "owner changed":
				ops.mutate = func(r *nmEAPReceipt) { r.Owner = ":1.9" }
			case "device changed":
				ops.mutate = func(r *nmEAPReceipt) { r.Device.MAC = "02:00:00:00:00:05" }
			case "incarnation changed":
				ops.mutate = func(r *nmEAPReceipt) { r.Incarnation = "other-attempt" }
			case "UUID changed":
				ops.mutate = func(r *nmEAPReceipt) { r.UUID = "another-uuid" }
			case "settings changed":
				ops.mutate = func(r *nmEAPReceipt) { r.SettingsHash = "changed" }
			}
			writes := 0
			receipt, err := connectNMEAP(ctx, ops, input, nmAllowFile, time.Now(), func(r nmEAPReceipt) error {
				writes++
				if mode == "persist failed" && writes == 2 {
					return errors.New("disk full")
				}
				return nil
			})
			if mode == "success" {
				if err != nil || ops.removed || !ops.activated {
					t.Fatalf("success: %v", err)
				}
			} else if err == nil || !ops.removed {
				t.Fatalf("failure did not clean up: %v", err)
			}
			if err != nil && strings.Contains(err.Error(), "secret must never appear") {
				t.Fatal("backend error leaked")
			}
			if mode == "cleanup failed" && !strings.Contains(err.Error(), "cleanup pending") {
				t.Fatal("cleanup retry lost")
			}
			if receipt.UUID == "" || receipt.Incarnation != "attempt-1" || writes != 2 || ops.flags != 0x22 {
				t.Fatal("operation identity not retained")
			}
			if _, exists := ops.added["802-1x"]["password"]; exists {
				t.Fatal("password retained after operation")
			}
		})
	}
}
