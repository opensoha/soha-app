package endpointservice

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

type fakePasswordSystem struct {
	*fakeEAPSystem
	installed   bool
	supported   bool
	interaction string
	connectErr  error
	got         []byte
	csrCalls    int
	allowTLS    bool
}

func (s *fakePasswordSystem) CreateCSR(ctx context.Context, id string) (string, error) {
	if s.allowTLS {
		return s.fakeEAPSystem.CreateCSR(ctx, id)
	}
	s.csrCalls++
	return "", errors.New("password flow requested a certificate")
}
func (s *fakePasswordSystem) PasswordSupport(context.Context, AdmissionProfile) (bool, string) {
	if !s.supported {
		return false, "native_password_api_unavailable"
	}
	return true, ""
}
func (s *fakePasswordSystem) CredentialInteraction(AdmissionProfile) string {
	if s.interaction != "" {
		return s.interaction
	}
	return "app-input"
}
func (s *fakePasswordSystem) StagePassword(context.Context, string, AdmissionProfile, EAPAdapter) (EAPStagedProfile, error) {
	s.installed = true
	return EAPStagedProfile{}, nil
}
func (s *fakePasswordSystem) ReadbackPassword(context.Context, string, AdmissionProfile, EAPAdapter) error {
	if !s.installed {
		return errors.New("not installed")
	}
	return nil
}
func (s *fakePasswordSystem) ConnectPassword(_ context.Context, _ string, _ AdmissionProfile, _ EAPAdapter, p []byte) error {
	s.got = append([]byte(nil), p...)
	return s.connectErr
}
func (s *fakePasswordSystem) Remove(ctx context.Context, p AdmissionProfile, a EAPAdapter, ids []EAPProfileIdentity) error {
	s.installed = false
	return s.fakeEAPSystem.Remove(ctx, p, a, ids)
}
func passwordFixture(t *testing.T) (*AdmissionManager, *fakePasswordSystem, AdmissionProfile) {
	base, control, tls, p := admissionFixture(t)
	p.EAPMethod, p.InnerMethod, p.CredentialSource, p.ProfileRevision = "ttls", "pap", "user-input", "sha256:"+strings.Repeat("a", 64)
	system := &fakePasswordSystem{fakeEAPSystem: tls, supported: true}
	base.system = system
	if err := base.Observe(&AdmissionConfiguration{Profiles: []AdmissionProfile{p}, RestrictionEpoch: 2}, time.Now().Add(time.Minute), time.Now()); err != nil {
		t.Fatal(err)
	}
	control.issueError = errors.New("must not issue password credential")
	return base, system, p
}
func TestEAPPasswordLifecycleNeverPersistsPassword(t *testing.T) {
	m, s, p := passwordFixture(t)
	ctx := context.Background()
	if err := m.Prepare(ctx, AdmissionInput{ProfileID: p.ID, AdapterID: "wifi-1"}); err != nil {
		t.Fatal(err)
	}
	if err := m.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.ConnectInput(ctx, AdmissionInput{ProfileID: p.ID, Password: "one-shot-secret"}); err != nil {
		t.Fatal(err)
	}
	if string(s.got) != "one-shot-secret" || s.csrCalls != 0 || m.state.Active != nil || m.state.Pending != nil {
		t.Fatal("password flow reused certificate lifecycle")
	}
	raw, err := os.ReadFile(m.path)
	if err != nil {
		t.Fatal(err)
	}
	status, _ := m.Status(ctx)
	public, _ := json.Marshal(status)
	if strings.Contains(string(raw), "one-shot-secret") || strings.Contains(string(public), "one-shot-secret") {
		t.Fatal("password escaped operation stack")
	}
	if status.Profiles[0].State != "installed" || !status.Profiles[0].Supported || status.Profiles[0].CredentialInteraction != "app-input" {
		t.Fatal("incorrect method status")
	}
	if err := m.Remove(ctx, p.ID); err != nil || s.installed {
		t.Fatalf("remove: %v", err)
	}
}
func TestEAPPasswordRejectsUnsupportedStaleAndSystemPromptPassword(t *testing.T) {
	for _, mode := range []string{"unsupported", "stale", "uninstalled", "empty", "system-prompt", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			m, s, p := passwordFixture(t)
			ctx := context.Background()
			if err := m.Prepare(ctx, AdmissionInput{ProfileID: p.ID, AdapterID: "wifi-1"}); err != nil {
				t.Fatal(err)
			}
			password := "one-shot-secret"
			switch mode {
			case "unsupported":
				s.supported = false
			case "stale":
				m.validUntil = time.Now().Add(-time.Second)
			case "uninstalled":
				s.installed = false
			case "empty":
				password = ""
			case "system-prompt":
				s.interaction = "system-prompt"
			case "cancelled":
				s.connectErr = context.Canceled
			}
			if err := m.ConnectInput(ctx, AdmissionInput{ProfileID: p.ID, Password: password}); err == nil {
				t.Fatal("invalid password action accepted")
			}
		})
	}
	m, s, p := passwordFixture(t)
	s.interaction = "system-prompt"
	s.connectErr = ErrEAPSystemInteractionRequired
	if err := m.Prepare(context.Background(), AdmissionInput{ProfileID: p.ID, AdapterID: "wifi-1"}); err != nil {
		t.Fatal(err)
	}
	if err := m.ConnectInput(context.Background(), AdmissionInput{ProfileID: p.ID}); !errors.Is(err, ErrEAPSystemInteractionRequired) {
		t.Fatal("system handoff claimed authenticated")
	}
	status, _ := m.Status(context.Background())
	if status.Profiles[0].State != "action_required" {
		t.Fatal("system action is not explicit")
	}
}
func TestEAPPasswordProfilesContainNoCredentialsAndRequireServerTrust(t *testing.T) {
	_, _, p := passwordFixture(t)
	for _, medium := range []string{"wired", "wifi"} {
		p.AccessMedium = medium
		if medium == "wired" {
			p.SSID = ""
		} else {
			p.SSID = "Soha & Lab"
		}
		windows, err := renderEAPWindowsProfile(p, "device-1", EAPCertificateResult{}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(windows.XML), "PAPAuthentication") || !strings.Contains(string(windows.XML), "<DisablePrompt>true</DisablePrompt>") || len(windows.UserData) != 0 {
			t.Fatal("Windows TTLS profile is not password-free with exact trust")
		}
		mac, err := renderEAPMobileconfig(p, "device-1", EAPCertificateResult{}, nil, "", 1, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"UserPassword", "pkcs12", "PayloadCertificateUUID"} {
			if strings.Contains(string(mac), forbidden) {
				t.Fatal("macOS TTLS exports credential material")
			}
		}
		for _, required := range []string{"TTLSInnerAuthentication", "PAP", "<integer>21</integer>", "TLSAllowTrustExceptions", "radius.example.test"} {
			if !strings.Contains(string(mac), required) {
				t.Fatal("macOS TTLS omitted method or trust")
			}
		}
	}
}

func TestEAPPasswordMixedSelectionsAndRevisionDrift(t *testing.T) {
	m, s, p := passwordFixture(t)
	ctx := context.Background()
	if err := m.Prepare(ctx, AdmissionInput{ProfileID: p.ID, AdapterID: "wifi-1"}); err != nil {
		t.Fatal(err)
	}
	m.state.Selections = append([]eapSelection{{Profile: AdmissionProfile{ID: "other-tls", EAPMethod: "tls"}, Adapter: EAPAdapter{ID: "wired-1"}}}, m.state.Selections...)
	if err := m.ConnectInput(ctx, AdmissionInput{ProfileID: p.ID, Password: "one-shot-secret"}); err != nil {
		t.Fatal("another TLS selection blocked password flow", err)
	}
	p.ProfileRevision = "sha256:" + strings.Repeat("b", 64)
	if err := m.Observe(&AdmissionConfiguration{Profiles: []AdmissionProfile{p}, RestrictionEpoch: 3}, time.Now().Add(time.Minute), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := m.Prepare(ctx, AdmissionInput{ProfileID: p.ID, AdapterID: "wifi-1"}); err == nil {
		t.Fatal("changed policy overwrote installed selection")
	}
	if err := m.ConnectInput(ctx, AdmissionInput{ProfileID: p.ID, Password: "one-shot-secret"}); err == nil {
		t.Fatal("changed profile revision connected")
	}
	if !s.installed {
		t.Fatal("drift check removed configuration without ownership check")
	}
}

func TestEAPPasswordIncompleteSelectionDoesNotBlockTLSOrCleanup(t *testing.T) {
	m, control, tls, tlsProfile := admissionFixture(t)
	system := &fakePasswordSystem{fakeEAPSystem: tls, supported: true, allowTLS: true}
	m.system = system
	passwordProfile := cloneAdmissionProfile(tlsProfile)
	passwordProfile.ID = "password-profile"
	passwordProfile.SSID = "Password network"
	passwordProfile.EAPMethod, passwordProfile.InnerMethod, passwordProfile.CredentialSource = "ttls", "pap", "user-input"
	passwordProfile.ProfileRevision = "sha256:" + strings.Repeat("a", 64)
	if err := m.Observe(&AdmissionConfiguration{Profiles: []AdmissionProfile{passwordProfile, tlsProfile}, RestrictionEpoch: 2}, time.Now().Add(time.Minute), time.Now()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, id := range []string{passwordProfile.ID, tlsProfile.ID} {
		if err := m.Prepare(ctx, AdmissionInput{ProfileID: id, AdapterID: "wifi-1"}); err != nil {
			t.Fatal(err)
		}
	}
	// Password readback failed, so its staged artifact must survive.
	system.installed = false
	passwordArtifact := "/Users/example/password.mobileconfig"
	m.state.Selections[0].ArtifactPath = passwordArtifact
	m.state.Selections[0].ArtifactSHA256 = strings.Repeat("b", 64)
	tls.installed[tlsProfile.ID] = control.certificate.Fingerprint
	m.queueCleanup(EAPCleanup{RequestID: "retired-request"})
	if err := m.save(); err != nil {
		t.Fatal(err)
	}
	if err := m.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if control.activations != 1 || m.state.Active == nil || len(m.state.Cleanup) != 0 {
		t.Fatal("incomplete password selection blocked TLS activation or queued cleanup")
	}
	if m.state.Selections[0].ArtifactPath != passwordArtifact || m.diagnostic != "installation_or_readback_required" {
		t.Fatal("incomplete password selection lost its artifact or diagnostic")
	}
	for _, job := range tls.cleanup {
		for _, artifact := range job.Artifacts {
			if artifact.Path == passwordArtifact {
				t.Fatal("uninstalled password artifact was cleaned up")
			}
		}
	}
}

type lifecycleEAPControl struct {
	*fakeEAPControl
	activation EAPCertificateActivateRequest
	revoked    int
}

func (c *lifecycleEAPControl) ActivateEAPCertificate(ctx context.Context, p EAPCertificateActivateRequest) (EAPCertificateActivateResult, error) {
	c.activation = p
	return c.fakeEAPControl.ActivateEAPCertificate(ctx, p)
}
func (c *lifecycleEAPControl) RevokeEAPCertificate(_ context.Context, p EAPCertificateRevokeRequest) (EAPCertificateRevokeResult, error) {
	c.revoked++
	return EAPCertificateRevokeResult{RequestID: p.RequestID, CredentialID: p.CredentialID, Fingerprint: p.Fingerprint, Status: "revoked"}, nil
}
func TestEAPCertificateLifecycleBindsRevisionAndRevokesOwnedCredential(t *testing.T) {
	m, c, s, p := admissionFixture(t)
	control := &lifecycleEAPControl{fakeEAPControl: c}
	m.control = control
	p.ProfileRevision = "sha256:" + strings.Repeat("a", 64)
	if err := m.Observe(&AdmissionConfiguration{Profiles: []AdmissionProfile{p}, RestrictionEpoch: 2}, time.Now().Add(time.Minute), time.Now()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := m.Prepare(ctx, AdmissionInput{ProfileID: p.ID, AdapterID: "wifi-1"}); err != nil {
		t.Fatal(err)
	}
	s.installed[p.ID] = c.certificate.Fingerprint
	if err := m.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if control.activation.ProfileID != p.ID || control.activation.ProfileRevision != p.ProfileRevision || control.activation.RequestID == "" {
		t.Fatal("activation did not bind the policy revision")
	}
	if err := m.Remove(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if control.revoked != 1 {
		t.Fatal("owned certificate was not revoked")
	}
}
