package endpointservice

import (
	"context"
	"crypto/x509"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type issuanceBoundControl struct {
	*fakeEAPControl
	requestID string
	requests  []EAPCertificateActivateRequest
	lost      bool
}

func (c *issuanceBoundControl) ActivateEAPCertificate(_ context.Context, request EAPCertificateActivateRequest) (EAPCertificateActivateResult, error) {
	if request.RequestID != c.requestID {
		return EAPCertificateActivateResult{}, ErrEAPCertificateStale
	}
	if len(c.requests) > 0 && request != c.requests[0] {
		return EAPCertificateActivateResult{}, errors.New("activation idempotency binding changed")
	}
	c.requests = append(c.requests, request)
	if c.lost {
		return EAPCertificateActivateResult{}, errors.New("accepted but response lost")
	}
	return EAPCertificateActivateResult{CredentialID: request.CredentialID, Fingerprint: request.Fingerprint, Status: "active", ExpiresAt: c.certificate.ExpiresAt}, nil
}

func TestAdmissionActivationUsesIssuanceRequestAndOneDurableTLSAnchor(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "single activation", true: "lost response restart"}[lost], func(t *testing.T) {
			ctx := context.Background()
			m, c, s, p := admissionFixture(t)
			p.ProfileRevision = "sha256:" + strings.Repeat("a", 64)
			q := p
			q.ID = p.ID + "-second"
			q.ProfileRevision = "sha256:" + strings.Repeat("b", 64)
			profiles := []AdmissionProfile{p, q}
			if err := m.Observe(&AdmissionConfiguration{Profiles: profiles, RestrictionEpoch: 2}, time.Now().Add(time.Minute), time.Now()); err != nil {
				t.Fatal(err)
			}
			for _, profile := range profiles {
				if err := m.Prepare(ctx, AdmissionInput{ProfileID: profile.ID, AdapterID: "wifi-1"}); err != nil {
					t.Fatal(err)
				}
			}
			control := &issuanceBoundControl{fakeEAPControl: c, requestID: m.state.Pending.RequestID, lost: lost}
			m.control = control
			s.installed[p.ID] = c.certificate.Fingerprint
			if err := m.Check(ctx); err != nil {
				t.Fatal(err)
			}
			if len(control.requests) != 0 {
				t.Fatal("activation preceded all TLS readbacks")
			}
			s.installed[q.ID] = c.certificate.Fingerprint
			err := m.Check(ctx)
			if lost {
				if err == nil || m.state.Pending.ActivationAnchor == nil {
					t.Fatal("uncertain activation lost its durable anchor")
				}
				resumed, e := NewAdmissionManager(filepath.Dir(m.path), "device-1", control, s)
				if e != nil {
					t.Fatal(e)
				}
				m = resumed
				if e = m.Observe(&AdmissionConfiguration{Profiles: profiles, RestrictionEpoch: 2}, time.Now().Add(time.Minute), time.Now()); e != nil {
					t.Fatal(e)
				}
				slices.Reverse(m.state.Selections)
				control.lost = false
				if e = m.Check(ctx); e != nil {
					t.Fatal(e)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			want := 1
			if lost {
				want = 2
			}
			if len(control.requests) != want || m.state.Pending != nil || m.state.Active == nil {
				t.Fatal("one certificate activated once per attempt, independent of TLS selection count")
			}
			if control.requests[0].ProfileID != p.ID || control.requests[0].ProfileRevision != p.ProfileRevision {
				t.Fatal("activation was not anchored to current TLS policy")
			}
		})
	}
}

func TestAdmissionLostActivationAnchorCannotMoveAfterPolicyChange(t *testing.T) {
	ctx := context.Background()
	m, c, s, p := admissionFixture(t)
	p.ProfileRevision = "sha256:" + strings.Repeat("a", 64)
	q := p
	q.ID = p.ID + "-second"
	if err := m.Observe(&AdmissionConfiguration{Profiles: []AdmissionProfile{p, q}, RestrictionEpoch: 2}, time.Now().Add(time.Minute), time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, profile := range []AdmissionProfile{p, q} {
		if err := m.Prepare(ctx, AdmissionInput{ProfileID: profile.ID, AdapterID: "wifi-1"}); err != nil {
			t.Fatal(err)
		}
		s.installed[profile.ID] = c.certificate.Fingerprint
	}
	control := &issuanceBoundControl{fakeEAPControl: c, requestID: m.state.Pending.RequestID, lost: true}
	m.control = control
	if m.Check(ctx) == nil {
		t.Fatal("missing response accepted")
	}
	p.ProfileRevision = "sha256:" + strings.Repeat("c", 64)
	if err := m.Observe(&AdmissionConfiguration{Profiles: []AdmissionProfile{p, q}, RestrictionEpoch: 3}, time.Now().Add(time.Minute), time.Now()); err != nil {
		t.Fatal(err)
	}
	control.lost = false
	if err := m.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if len(control.requests) != 1 || m.state.Pending == nil || !m.state.Pending.Stale || m.diagnostic != "certificate_prepare_required" {
		t.Fatal("changed activation anchor was replayed or silently moved")
	}
}

func TestNMEAPFullReadbackRejectsAdditionalAndMissingConfiguration(t *testing.T) {
	input, cap := nmEAPFixture(t)
	expected, err := buildNMEAPSettings(input, cap, nmAllowFile, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	delete(expected["802-1x"], "password")
	clone := func() nmEAPSettings {
		r := nmEAPSettings{}
		for group, values := range expected {
			r[group] = map[string]any{}
			for k, v := range values {
				r[group][k] = v
			}
		}
		return r
	}
	actual := clone()
	actual["connection"]["timestamp"] = uint64(123)
	actual["ipv4"]["routes"] = [][]uint32{}
	actual["ipv4"]["dns"] = []uint32{}
	actual["proxy"] = map[string]any{"method": int32(0)}
	delete(actual["802-1x"], "optional")
	if err := matchNMEAPSettings(expected, actual); err != nil {
		t.Fatal("NM omitted/default and volatile fields rejected", err)
	}
	for name, change := range map[string]func(nmEAPSettings){
		"routes":                 func(s nmEAPSettings) { s["ipv4"]["routes"] = [][]uint32{{1, 2, 3, 4}} },
		"dns":                    func(s nmEAPSettings) { s["ipv4"]["dns"] = []uint32{1} },
		"master":                 func(s nmEAPSettings) { s["connection"]["master"] = "external-bridge" },
		"extra group":            func(s nmEAPSettings) { s["external"] = map[string]any{} },
		"missing safety setting": func(s nmEAPSettings) { delete(s["connection"], "autoconnect") },
		"unexpected secret":      func(s nmEAPSettings) { s["802-1x"]["password"] = "must-not-be-persisted" },
	} {
		t.Run(name, func(t *testing.T) {
			s := clone()
			change(s)
			if matchNMEAPSettings(expected, s) == nil {
				t.Fatal("configuration drift allowed activation/removal")
			}
		})
	}
}

func TestEAPPasswordCAStageRequiresTrustReadback(t *testing.T) {
	_, _, _, p := admissionFixture(t)
	installed := map[string]bool{}
	adds, reads := 0, 0
	install := func(c *x509.Certificate) error { adds++; installed[string(c.Raw)] = true; return nil }
	read := func(c *x509.Certificate) error {
		reads++
		if !installed[string(c.Raw)] {
			return errors.New("CA missing")
		}
		return nil
	}
	if prepareEAPPasswordTrust(p, "network_readback", install, read) == nil {
		t.Fatal("missing CA accepted")
	}
	if err := prepareEAPPasswordTrust(p, "network_stage", install, read); err != nil {
		t.Fatal(err)
	}
	if adds != len(p.CACertificates) || reads < 2 {
		t.Fatal("CA import was not read back")
	}
	if err := prepareEAPPasswordTrust(p, "network_readback", install, read); err != nil {
		t.Fatal(err)
	}
	if err := prepareEAPPasswordTrust(p, "network_stage", install, func(*x509.Certificate) error { return errors.New("store drift") }); err == nil {
		t.Fatal("CA write without readback accepted")
	}
}

func TestEAPPasswordRawByteLimitAndPlatformBoundary(t *testing.T) {
	for _, p := range []string{" ", "a\r\nb", "a\x00b", strings.Repeat("x", 72), strings.Repeat("界", 24)} {
		if validateEAPPassword(p) != nil {
			t.Fatal("valid raw password rejected")
		}
	}
	for _, p := range []string{"", strings.Repeat("x", 73), strings.Repeat("界", 25)} {
		if validateEAPPassword(p) == nil {
			t.Fatal("invalid byte length accepted")
		}
	}
	m, s, p := passwordFixture(t)
	ctx := context.Background()
	if err := m.Prepare(ctx, AdmissionInput{ProfileID: p.ID, AdapterID: "wifi-1"}); err != nil {
		t.Fatal(err)
	}
	raw := " leading\r\ntrailing "
	if err := m.ConnectInput(ctx, AdmissionInput{ProfileID: p.ID, Password: raw}); err != nil {
		t.Fatal(err)
	}
	if string(s.got) != raw {
		t.Fatal("password bytes changed")
	}
	input, cap := nmEAPFixture(t)
	input.Material.Password = []byte(raw)
	settings, err := buildNMEAPSettings(input, cap, nmAllowFile, time.Now())
	if err != nil || settings["802-1x"]["password"] != raw {
		t.Fatal("D-Bus representable CR/LF password changed", err)
	}
	input.Material.Password = []byte("a\x00b")
	if _, err := buildNMEAPSettings(input, cap, nmAllowFile, time.Now()); err == nil || !strings.Contains(err.Error(), "D-Bus STRING") {
		t.Fatal("Linux NUL limitation was not explicit")
	}
}
