package endpointservice

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type fakeEAPControl struct {
	certificate     EAPCertificateResult
	activations     int
	activationError error
	issueError      error
}

func (control *fakeEAPControl) IssueEAPCertificate(context.Context, EAPCertificateRequest, string, string) (EAPCertificateResult, error) {
	return control.certificate, control.issueError
}

func (control *fakeEAPControl) ActivateEAPCertificate(_ context.Context, request EAPCertificateActivateRequest) (EAPCertificateActivateResult, error) {
	control.activations++
	return EAPCertificateActivateResult{CredentialID: request.CredentialID, Fingerprint: request.Fingerprint, ExpiresAt: control.certificate.ExpiresAt, Status: "active"}, control.activationError
}

type fakeEAPSystem struct {
	csr          string
	installed    map[string]string
	staged       []string
	removed      []string
	connects     int
	cleanup      []EAPCleanup
	cleanupError error
}

func (system *fakeEAPSystem) Adapters(context.Context) ([]EAPAdapter, error) {
	return []EAPAdapter{{ID: "wifi-1", Name: "en0", Medium: "wifi", MACAddress: "02:00:00:00:00:01", Enabled: true}}, nil
}
func (system *fakeEAPSystem) CreateCSR(context.Context, string) (string, error) {
	return system.csr, nil
}
func (system *fakeEAPSystem) Stage(_ context.Context, _ string, profile AdmissionProfile, certificate EAPCertificateResult, _ EAPAdapter) (EAPStagedProfile, error) {
	system.staged = append(system.staged, profile.ID)
	return EAPStagedProfile{EAPArtifact: EAPArtifact{Path: "/Users/example/Soha-EAP.mobileconfig", SHA256: strings.Repeat("a", 64)}, IdentitySHA256: strings.Repeat("b", 64)}, nil
}
func (system *fakeEAPSystem) Readback(_ context.Context, _ string, profile AdmissionProfile, certificate EAPCertificateResult, _ EAPAdapter) error {
	if system.installed[profile.ID] != certificate.Fingerprint {
		return errors.New("not installed")
	}
	return nil
}
func (system *fakeEAPSystem) Remove(_ context.Context, profile AdmissionProfile, _ EAPAdapter, identities []EAPProfileIdentity) error {
	if installed := system.installed[profile.ID]; installed != "" && !slices.ContainsFunc(identities, func(identity EAPProfileIdentity) bool { return identity.Fingerprint == installed }) {
		return errors.New("installed credential does not belong to removal request")
	}
	system.removed = append(system.removed, profile.ID)
	delete(system.installed, profile.ID)
	return nil
}
func (system *fakeEAPSystem) Connect(context.Context, string, AdmissionProfile, EAPCertificateResult, EAPAdapter) error {
	system.connects++
	return nil
}
func (system *fakeEAPSystem) Cleanup(_ context.Context, job EAPCleanup) error {
	system.cleanup = append(system.cleanup, job)
	return system.cleanupError
}
func (*fakeEAPSystem) RecoverArtifacts(context.Context, []EAPArtifact) error { return nil }

func admissionFixture(t *testing.T) (*AdmissionManager, *fakeEAPControl, *fakeEAPSystem, AdmissionProfile) {
	t.Helper()
	certificate, csr, profile := eapCertificateFixture(t)
	control := &fakeEAPControl{certificate: certificate}
	system := &fakeEAPSystem{csr: csr, installed: map[string]string{}}
	manager, err := NewAdmissionManager(t.TempDir(), "device-1", control, system)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Observe(&AdmissionConfiguration{Profiles: []AdmissionProfile{profile}, RestrictionEpoch: 1}, time.Now().Add(5*time.Minute), time.Now()); err != nil {
		t.Fatal(err)
	}
	return manager, control, system, profile
}

func TestAdmissionRequiresOSReadbackBeforeActivationAndConnection(t *testing.T) {
	ctx := context.Background()
	manager, control, system, profile := admissionFixture(t)
	if err := manager.Prepare(ctx, AdmissionInput{ProfileID: profile.ID, AdapterID: "wifi-1"}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if control.activations != 0 {
		t.Fatal("export activated an uninstalled certificate")
	}
	if err := manager.Connect(ctx, profile.ID); err == nil {
		t.Fatal("uninstalled profile connected")
	}
	status, err := manager.Status(ctx)
	if err != nil || status.Profiles[0].State != "installation_required" {
		t.Fatalf("status = %+v, %v", status, err)
	}
	system.installed[profile.ID] = control.certificate.Fingerprint
	if err := manager.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if control.activations != 1 || manager.state.Active == nil || manager.state.Pending != nil {
		t.Fatal("installed identity was not activated")
	}
	if err := manager.Connect(ctx, profile.ID); err != nil || system.connects != 1 {
		t.Fatalf("connect = %v", err)
	}
	delete(system.installed, profile.ID)
	if err := manager.Connect(ctx, profile.ID); err == nil {
		t.Fatal("drifted identity connected")
	}
	resumed, err := NewAdmissionManager(manager.path[:len(manager.path)-len("eap-state.json")], "device-1", control, system)
	if err != nil || resumed.state.Active == nil {
		t.Fatalf("resume = %+v, %v", resumed, err)
	}
	if err := resumed.Connect(ctx, profile.ID); err == nil {
		t.Fatal("restart reused authorization without a new control configuration")
	}
}

func TestAdmissionPolicyChangeAndExpiryCannotActivateOldSelection(t *testing.T) {
	for _, change := range []string{"policy", "expiry", "revocation"} {
		t.Run(change, func(t *testing.T) {
			ctx := context.Background()
			manager, control, system, profile := admissionFixture(t)
			if err := manager.Prepare(ctx, AdmissionInput{ProfileID: profile.ID, AdapterID: "wifi-1"}); err != nil {
				t.Fatal(err)
			}
			system.installed[profile.ID] = control.certificate.Fingerprint
			switch change {
			case "policy":
				profile.ServerNames = []string{"new-radius.example.test"}
				if err := manager.Observe(&AdmissionConfiguration{Profiles: []AdmissionProfile{profile}, RestrictionEpoch: 2}, time.Now().Add(time.Minute), time.Now()); err != nil {
					t.Fatal(err)
				}
			case "revocation":
				if err := manager.Observe(&AdmissionConfiguration{Profiles: []AdmissionProfile{}, RestrictionEpoch: 2}, time.Now().Add(time.Minute), time.Now()); err != nil {
					t.Fatal(err)
				}
			case "expiry":
				manager.now = func() time.Time { return time.Now().Add(10 * time.Minute) }
			}
			if err := manager.Check(ctx); err != nil {
				t.Fatal(err)
			}
			if control.activations != 0 || !slices.Contains(system.removed, profile.ID) || len(manager.state.Selections) != 0 {
				t.Fatalf("old policy survived: %+v", manager.state)
			}
		})
	}
}

func TestAdmissionActivationRetryKeepsTheSameInstalledCredential(t *testing.T) {
	ctx := context.Background()
	manager, control, system, profile := admissionFixture(t)
	if err := manager.Prepare(ctx, AdmissionInput{ProfileID: profile.ID, AdapterID: "wifi-1"}); err != nil {
		t.Fatal(err)
	}
	system.installed[profile.ID] = control.certificate.Fingerprint
	requestID := manager.state.Pending.RequestID
	control.activationError = errors.New("response lost")
	if err := manager.Check(ctx); err == nil {
		t.Fatal("missing response was accepted")
	}
	if manager.state.Pending.RequestID != requestID || manager.state.Pending.Stale {
		t.Fatal("uncertain activation discarded the pending identity")
	}
	control.activationError = nil
	if err := manager.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if manager.state.Active.RequestID != requestID || control.activations != 2 {
		t.Fatal("activation retry changed the identity")
	}
}

func TestAdmissionFailedActivationCommitRestoresPendingState(t *testing.T) {
	ctx := context.Background()
	manager, control, system, profile := admissionFixture(t)
	if err := manager.Prepare(ctx, AdmissionInput{ProfileID: profile.ID, AdapterID: "wifi-1"}); err != nil {
		t.Fatal(err)
	}
	system.installed[profile.ID] = manager.state.Pending.Certificate.Fingerprint
	requestID := manager.state.Pending.RequestID
	manager.state.Selections[0].ArtifactPath, manager.state.Selections[0].ArtifactSHA256 = "", ""
	if err := manager.save(); err != nil {
		t.Fatal(err)
	}
	// A directory at the destination forces the atomic rename to fail on every OS.
	if err := os.Remove(manager.path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(manager.path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manager.path, "occupied"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := manager.Check(ctx); err == nil {
		t.Fatal("failed persistence was accepted")
	}
	if control.activations != 1 || manager.state.Active != nil || manager.state.Pending == nil || manager.state.Pending.RequestID != requestID || manager.validUntil.After(time.Now()) {
		t.Fatal("failed commit left an active or authorized in-memory identity")
	}
	if err := manager.Connect(ctx, profile.ID); err == nil {
		t.Fatal("identity connected after its commit failed")
	}
}

func TestAdmissionCleanupPreservesSharedIdentityAndRetriesAfterRestart(t *testing.T) {
	ctx := context.Background()
	manager, control, system, profile := admissionFixture(t)
	if err := manager.Prepare(ctx, AdmissionInput{ProfileID: profile.ID, AdapterID: "wifi-1"}); err != nil {
		t.Fatal(err)
	}
	system.installed[profile.ID] = control.certificate.Fingerprint
	if err := manager.Check(ctx); err != nil {
		t.Fatal(err)
	}
	requestID := manager.state.Active.RequestID
	profile.ClientCertificateFingerprint = control.certificate.Fingerprint
	second := cloneAdmissionProfile(profile)
	second.ID = "profile-2"
	if err := manager.Observe(&AdmissionConfiguration{Profiles: []AdmissionProfile{profile, second}, RestrictionEpoch: 2}, time.Now().Add(time.Minute), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Prepare(ctx, AdmissionInput{ProfileID: second.ID, AdapterID: "wifi-1"}); err != nil {
		t.Fatal(err)
	}
	system.cleanup = nil
	if err := manager.Remove(ctx, profile.ID); err != nil {
		t.Fatal(err)
	}
	for _, job := range system.cleanup {
		if job.RequestID != "" || len(job.CACertificates) != 0 {
			t.Fatal("shared EAP key or CA was retired while another network used it")
		}
	}
	system.cleanupError = errors.New("desktop user is logged off")
	if err := manager.Remove(ctx, second.ID); err == nil {
		t.Fatal("deferred cleanup was reported as complete")
	}
	if len(manager.state.Selections) != 0 || manager.state.Active != nil || manager.state.Pending != nil || len(manager.state.Cleanup) == 0 {
		t.Fatal("last network removal did not persist identity cleanup")
	}
	resumed, err := NewAdmissionManager(filepath.Dir(manager.path), "device-1", control, system)
	if err != nil {
		t.Fatal(err)
	}
	system.cleanup, system.cleanupError = nil, nil
	if err := resumed.Check(ctx); err != nil || len(resumed.state.Cleanup) != 0 {
		t.Fatalf("cleanup retry = %v", err)
	}
	if !slices.ContainsFunc(system.cleanup, func(job EAPCleanup) bool {
		return job.RequestID == requestID && job.Certificate != nil && len(job.CACertificates) != 0
	}) {
		t.Fatal("obsolete identity and owned CA were not included in cleanup")
	}
}

func TestAdmissionRejectsEpochRollbackAndUntrustedAdapter(t *testing.T) {
	manager, _, _, profile := admissionFixture(t)
	if err := manager.Observe(&AdmissionConfiguration{Profiles: []AdmissionProfile{profile}}, time.Now().Add(time.Minute), time.Now()); err == nil {
		t.Fatal("restriction epoch rollback accepted")
	}
	if err := manager.Prepare(context.Background(), AdmissionInput{ProfileID: profile.ID, AdapterID: "renderer-invented"}); err == nil {
		t.Fatal("untrusted adapter accepted")
	}
}

func TestAdmissionParentRotationReplacesRevokedEAPIdentity(t *testing.T) {
	ctx := context.Background()
	manager, control, system, profile := admissionFixture(t)
	if err := manager.Prepare(ctx, AdmissionInput{ProfileID: profile.ID, AdapterID: "wifi-1"}); err != nil {
		t.Fatal(err)
	}
	system.installed[profile.ID] = control.certificate.Fingerprint
	if err := manager.Check(ctx); err != nil {
		t.Fatal(err)
	}
	oldRequest := manager.state.Active.RequestID
	if err := manager.Check(ctx); err != nil || manager.state.Pending != nil {
		t.Fatal("older observation triggered a spurious rotation")
	}
	if err := manager.Observe(&AdmissionConfiguration{Profiles: []AdmissionProfile{profile}, RestrictionEpoch: 2}, time.Now().Add(time.Minute), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Connect(ctx, profile.ID); err == nil {
		t.Fatal("parent-revoked certificate connected")
	}
	control.certificate, system.csr, _ = eapCertificateFixture(t)
	if err := manager.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if manager.state.Pending == nil || manager.state.Pending.RequestID == oldRequest || manager.state.Pending.Certificate.Fingerprint != control.certificate.Fingerprint {
		t.Fatal("revoked EAP identity was retained")
	}
}

func TestAdmissionExpiredLostIssuanceCanStartANewRequest(t *testing.T) {
	ctx := context.Background()
	manager, control, _, profile := admissionFixture(t)
	control.issueError = errors.New("issue response lost")
	if err := manager.Prepare(ctx, AdmissionInput{ProfileID: profile.ID, AdapterID: "wifi-1"}); err == nil {
		t.Fatal("lost issuance accepted")
	}
	oldRequest := manager.state.Pending.RequestID
	control.issueError = ErrEAPCertificateStale
	if err := manager.Prepare(ctx, AdmissionInput{ProfileID: profile.ID, AdapterID: "wifi-1"}); !errors.Is(err, ErrEAPCertificateStale) || !manager.state.Pending.Stale {
		t.Fatal("stale issuance was not recorded")
	}
	control.issueError = nil
	if err := manager.Prepare(ctx, AdmissionInput{ProfileID: profile.ID, AdapterID: "wifi-1"}); err != nil {
		t.Fatal(err)
	}
	if manager.state.Pending.RequestID == oldRequest || manager.state.Pending.Certificate == nil {
		t.Fatal("stale issuance kept the same request ID")
	}
}

func TestAdmissionUpdatesWithoutVPNVersionChangesOrActiveVPNSession(t *testing.T) {
	admission, _, _, profile := admissionFixture(t)
	now := time.Now()
	desired := ConfigurationDesired{ConfigurationVersion: 1, PolicyVersion: 1, ValidUntil: now.Add(time.Minute), Admission: &AdmissionConfiguration{Profiles: []AdmissionProfile{profile}, RestrictionEpoch: 2}}
	raw, _ := json.Marshal(desired)
	control := &fakeControl{configuration: RuntimeMessage{SchemaVersion: RuntimeSchemaVersion, MessageType: MessageConfiguration, ProducerID: "network-control", RuntimeID: "endpoint-1", RuntimeKind: "endpoint", OccurredAt: now, ExpiresAt: desired.ValidUntil, Payload: raw}}
	executor := &fakeConfigurationExecutor{}
	manager, err := NewManager(ManagerOptions{Admission: admission, RuntimeID: "endpoint-1", DeviceID: "device-1", PollInterval: time.Minute, HeartbeatInterval: time.Minute, RenewBefore: time.Second, MaxClockSkew: time.Minute}, control, executor, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	manager.appliedVersion = 1
	if err := manager.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	desired.Admission.Profiles[0].SSID = "New Organization SSID"
	control.configuration.Payload, _ = json.Marshal(desired)
	control.configuration.OccurredAt = now.Add(time.Millisecond)
	if err := manager.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if admission.profiles[0].SSID != "New Organization SSID" || executor.applyCalls != 0 || manager.Status().SessionID != "" {
		t.Fatal("EAP configuration was gated by the VPN version or session")
	}
}

func TestAdmissionRemovalRetainsExportedGenerationsUntilReadback(t *testing.T) {
	for _, action := range []string{"remove", "policy revocation"} {
		t.Run(action, func(t *testing.T) {
			ctx := context.Background()
			manager, control, system, profile := admissionFixture(t)
			if err := manager.Prepare(ctx, AdmissionInput{ProfileID: profile.ID, AdapterID: "wifi-1"}); err != nil {
				t.Fatal(err)
			}
			original := control.certificate.Fingerprint
			system.installed[profile.ID] = original
			if err := manager.Check(ctx); err != nil {
				t.Fatal(err)
			}
			future := time.Now().Add(23 * time.Hour)
			manager.now = func() time.Time { return future }
			certificate, csr, _ := eapCertificateFixture(t, func(c *x509.Certificate) { c.NotAfter = time.Now().UTC().Truncate(time.Second).Add(46 * time.Hour) })
			control.certificate, system.csr = certificate, csr
			if err := manager.Observe(&AdmissionConfiguration{Profiles: []AdmissionProfile{profile}, RestrictionEpoch: 1}, future.Add(time.Minute), future); err != nil {
				t.Fatal(err)
			}
			if err := manager.Prepare(ctx, AdmissionInput{ProfileID: profile.ID, AdapterID: "wifi-1"}); err != nil {
				t.Fatal(err)
			}
			selection := manager.state.Selections[0]
			if selection.Fingerprint == original || !slices.ContainsFunc(selection.PriorIdentities, func(identity EAPProfileIdentity) bool { return identity.Fingerprint == original }) {
				t.Fatal("staging lost the still installed generation")
			}
			resumed, err := NewAdmissionManager(filepath.Dir(manager.path), "device-1", control, system)
			if err != nil {
				t.Fatal(err)
			}
			resumed.now = manager.now
			if action == "remove" {
				err = resumed.Remove(ctx, profile.ID)
			} else {
				if err = resumed.Observe(&AdmissionConfiguration{RestrictionEpoch: 2}, future.Add(time.Minute), future); err != nil {
					t.Fatal(err)
				}
				err = resumed.Check(ctx)
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(resumed.state.Selections) != 0 || len(system.installed) != 0 {
				t.Fatal("old installed generation remained after removal")
			}
		})
	}
}
