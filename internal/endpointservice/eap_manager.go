package endpointservice

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

type EAPControl interface {
	IssueEAPCertificate(context.Context, EAPCertificateRequest, string, string) (EAPCertificateResult, error)
	ActivateEAPCertificate(context.Context, EAPCertificateActivateRequest) (EAPCertificateActivateResult, error)
}

type EAPSystem interface {
	Adapters(context.Context) ([]EAPAdapter, error)
	CreateCSR(context.Context, string) (string, error)
	Stage(context.Context, string, AdmissionProfile, EAPCertificateResult, EAPAdapter) (EAPStagedProfile, error)
	Readback(context.Context, string, AdmissionProfile, EAPCertificateResult, EAPAdapter) error
	Remove(context.Context, AdmissionProfile, EAPAdapter, []EAPProfileIdentity) error
	Connect(context.Context, string, AdmissionProfile, EAPCertificateResult, EAPAdapter) error
	Cleanup(context.Context, EAPCleanup) error
	RecoverArtifacts(context.Context, []EAPArtifact) error
}

type AdmissionInput struct {
	ProfileID string `json:"profileId"`
	AdapterID string `json:"adapterId"`
}

type AdmissionProfileStatus struct {
	ID           string `json:"id"`
	SiteID       string `json:"siteId"`
	AccessMedium string `json:"accessMedium"`
	SSID         string `json:"ssid,omitempty"`
	AdapterID    string `json:"adapterId,omitempty"`
	State        string `json:"state"`
	ArtifactPath string `json:"artifactPath,omitempty"`
}

type AdmissionStatus struct {
	Supported        bool                     `json:"supported"`
	Profiles         []AdmissionProfileStatus `json:"profiles"`
	Adapters         []EAPAdapter             `json:"adapters"`
	ValidUntil       time.Time                `json:"validUntil,omitempty"`
	CertificateUntil time.Time                `json:"certificateUntil,omitempty"`
	Diagnostic       string                   `json:"diagnostic,omitempty"`
}

// EAPProfileIdentity binds an exported credential generation to its encrypted payload.
type EAPProfileIdentity struct {
	Fingerprint    string `json:"fingerprint"`
	IdentitySHA256 string `json:"identitySha256,omitempty"`
}

type EAPStagedProfile struct {
	EAPArtifact
	IdentitySHA256 string
}

type eapSelection struct {
	Profile         AdmissionProfile     `json:"profile"`
	Adapter         EAPAdapter           `json:"adapter"`
	Fingerprint     string               `json:"fingerprint,omitempty"`
	IdentitySHA256  string               `json:"identitySha256,omitempty"`
	PriorIdentities []EAPProfileIdentity `json:"priorIdentities,omitempty"`
	RequestID       string               `json:"requestId,omitempty"`
	ArtifactPath    string               `json:"artifactPath,omitempty"`
	ArtifactSHA256  string               `json:"artifactSha256,omitempty"`
}

type eapIdentity struct {
	RequestID   string                `json:"requestId"`
	CSR         string                `json:"csr"`
	Certificate *EAPCertificateResult `json:"certificate,omitempty"`
	Stale       bool                  `json:"stale,omitempty"`
	ActivatedAt time.Time             `json:"activatedAt,omitempty"`
}

type eapState struct {
	Version    int            `json:"version"`
	DeviceID   string         `json:"deviceId"`
	Epoch      int            `json:"epoch"`
	Selections []eapSelection `json:"selections"`
	Active     *eapIdentity   `json:"active,omitempty"`
	Pending    *eapIdentity   `json:"pending,omitempty"`
	Cleanup    []EAPCleanup   `json:"cleanup,omitempty"`
}

type AdmissionManager struct {
	mu         sync.Mutex
	control    EAPControl
	system     EAPSystem
	path       string
	state      eapState
	profiles   []AdmissionProfile
	validUntil time.Time
	observedAt time.Time
	diagnostic string
	now        func() time.Time
	savedState []byte
}

func NewAdmissionManager(directory, deviceID string, control EAPControl, system EAPSystem) (*AdmissionManager, error) {
	if !filepath.IsAbs(directory) || !identifierPattern.MatchString(deviceID) || control == nil || system == nil {
		return nil, errors.New("EAP manager dependencies are invalid")
	}
	manager := &AdmissionManager{control: control, system: system, path: filepath.Join(directory, "eap-state.json"), state: eapState{Version: 1, DeviceID: deviceID}, now: time.Now}
	raw, err := readFileBounded(manager.path, 256<<10, true)
	if errors.Is(err, os.ErrNotExist) {
		manager.savedState, _ = json.Marshal(manager.state)
		return manager, nil
	}
	if err != nil {
		return nil, err
	}
	if err := decodeStrict(raw, &manager.state); err != nil || manager.state.Version != 1 || manager.state.DeviceID != deviceID || manager.state.Epoch < 0 || len(manager.state.Selections) > 8 || len(manager.state.Cleanup) > 16 {
		return nil, errors.New("stored EAP state is invalid")
	}
	seen := map[string]bool{}
	for _, selection := range manager.state.Selections {
		if !identifierPattern.MatchString(selection.Profile.ID) || selection.Adapter.ID == "" || seen[selection.Profile.ID] || selection.Fingerprint != "" && !identifierPattern.MatchString(selection.RequestID) {
			return nil, errors.New("stored EAP selection is invalid")
		}
		if len(selection.PriorIdentities) > 16 || slices.ContainsFunc(selection.PriorIdentities, func(value EAPProfileIdentity) bool {
			return !validReadbackHash(value.Fingerprint) || value.IdentitySHA256 != "" && !validReadbackHash("sha256:"+value.IdentitySHA256)
		}) || selection.IdentitySHA256 != "" && !validReadbackHash("sha256:"+selection.IdentitySHA256) {
			return nil, errors.New("stored EAP removal identities are invalid")
		}
		seen[selection.Profile.ID] = true
	}
	for _, identity := range []*eapIdentity{manager.state.Active, manager.state.Pending} {
		if identity != nil && (!identifierPattern.MatchString(identity.RequestID) || len(identity.CSR) > 4096) {
			return nil, errors.New("stored EAP identity is invalid")
		}
	}
	manager.savedState = slices.Clone(raw)
	return manager, nil
}

// Observe is called for every authenticated configuration, independently of VPN versions.
func (manager *AdmissionManager) Observe(configuration *AdmissionConfiguration, validUntil, observedAt time.Time) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if !validUntil.After(manager.now()) || observedAt.Before(manager.observedAt) || configuration == nil || configuration.RestrictionEpoch < manager.state.Epoch || len(configuration.Profiles) > 64 {
		manager.validUntil = time.Time{}
		manager.diagnostic = "configuration_unavailable"
		return errors.New("EAP configuration is missing, stale or expired")
	}
	profiles := make([]AdmissionProfile, len(configuration.Profiles))
	seen, subject := map[string]bool{}, ""
	for index, profile := range configuration.Profiles {
		if err := validateAdmissionProfile(profile, manager.now()); err != nil || seen[profile.ID] || subject != "" && profile.Identity != subject {
			manager.validUntil = time.Time{}
			manager.diagnostic = "configuration_invalid"
			return errors.New("EAP configuration contains an invalid or ambiguous profile")
		}
		seen[profile.ID], subject = true, profile.Identity
		profiles[index] = cloneAdmissionProfile(profile)
	}
	manager.profiles, manager.validUntil, manager.observedAt = profiles, validUntil.UTC(), observedAt.UTC()
	manager.state.Epoch = configuration.RestrictionEpoch
	return manager.save()
}

func (manager *AdmissionManager) Status(ctx context.Context) (AdmissionStatus, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	adapters, err := manager.system.Adapters(ctx)
	status := AdmissionStatus{Supported: true, Profiles: []AdmissionProfileStatus{}, Adapters: adapters, ValidUntil: manager.validUntil, Diagnostic: manager.diagnostic}
	if manager.state.Active != nil && manager.state.Active.Certificate != nil {
		status.CertificateUntil = manager.state.Active.Certificate.ExpiresAt
	}
	for _, profile := range manager.profiles {
		item := AdmissionProfileStatus{ID: profile.ID, SiteID: profile.SiteID, AccessMedium: profile.AccessMedium, SSID: profile.SSID, State: "available"}
		for _, selection := range manager.state.Selections {
			if selection.Profile.ID != profile.ID {
				continue
			}
			item.AdapterID, item.ArtifactPath, item.State = selection.Adapter.ID, selection.ArtifactPath, "installation_required"
			if !manager.validUntil.After(manager.now()) {
				item.State = "authorization_expired"
				break
			}
			if eapProfileHash(selection.Profile) != eapProfileHash(profile) {
				item.State = "drift"
				break
			}
			if certificate := manager.targetCertificate(); certificate != nil && selection.Fingerprint == certificate.Fingerprint {
				if readErr := manager.system.Readback(ctx, selection.RequestID, selection.Profile, *certificate, selection.Adapter); readErr == nil {
					item.State = "installed"
					if manager.state.Pending != nil {
						item.State = "activation_pending"
					}
				} else if selection.ArtifactPath == "" {
					item.State = "drift"
				}
			}
		}
		status.Profiles = append(status.Profiles, item)
	}
	return status, err
}

func (manager *AdmissionManager) Prepare(ctx context.Context, input AdmissionInput) (prepareErr error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	defer func() { prepareErr = errors.Join(prepareErr, manager.recoverArtifacts(ctx)) }()
	profile, err := manager.currentProfile(input.ProfileID)
	if err != nil {
		return err
	}
	adapters, err := manager.system.Adapters(ctx)
	if err != nil {
		return err
	}
	index := slices.IndexFunc(adapters, func(adapter EAPAdapter) bool {
		return adapter.ID == input.AdapterID && adapter.Medium == profile.AccessMedium && adapter.Enabled
	})
	if index < 0 {
		return errors.New("selected EAP adapter is unavailable")
	}
	for _, selection := range manager.state.Selections {
		if selection.Profile.ID == profile.ID && selection.Adapter.ID != input.AdapterID || selection.Profile.ID != profile.ID && selection.Adapter.ID == input.AdapterID && profile.AccessMedium == "wired" {
			return errors.New("remove the existing EAP adapter selection before changing it")
		}
	}
	selected := slices.IndexFunc(manager.state.Selections, func(selection eapSelection) bool { return selection.Profile.ID == profile.ID })
	if selected < 0 {
		if len(manager.state.Selections) >= 8 {
			return errors.New("at most eight managed EAP profiles may be installed")
		}
		manager.state.Selections = append(manager.state.Selections, eapSelection{Profile: profile, Adapter: adapters[index]})
		if err := manager.save(); err != nil {
			return err
		}
	}
	if err := manager.ensureIdentity(ctx, profile.Identity); err != nil {
		return err
	}
	return manager.stage(ctx, profile.ID)
}

func (manager *AdmissionManager) ensureIdentity(ctx context.Context, subjectID string) error {
	if manager.state.Pending != nil && manager.state.Pending.Stale {
		manager.queueCleanup(EAPCleanup{RequestID: manager.state.Pending.RequestID, Certificate: manager.state.Pending.Certificate})
		manager.state.Pending = nil
	}
	if active := manager.state.Active; manager.state.Pending == nil && manager.activeCurrent() && active.Certificate.ExpiresAt.After(manager.now().Add(time.Hour)) {
		return nil
	}
	if manager.state.Pending == nil {
		if len(manager.state.Cleanup) >= 16 {
			return errors.New("EAP cleanup must complete before another identity is created")
		}
		manager.state.Pending = &eapIdentity{RequestID: randomID()}
		if err := manager.save(); err != nil {
			return err
		}
	}
	pending := manager.state.Pending
	if pending.CSR == "" {
		csr, err := manager.system.CreateCSR(ctx, pending.RequestID)
		if err != nil {
			return err
		}
		pending.CSR = csr
		if err := manager.save(); err != nil {
			return err
		}
	}
	if pending.Certificate == nil {
		certificate, err := manager.control.IssueEAPCertificate(ctx, EAPCertificateRequest{RequestID: pending.RequestID, CSRPEM: pending.CSR}, manager.state.DeviceID, subjectID)
		if err != nil {
			if errors.Is(err, ErrEAPCertificateStale) {
				pending.Stale = true
				manager.diagnostic = "certificate_prepare_required"
				return errors.Join(err, manager.save())
			}
			return err
		}
		if err := validateEAPCertificate(certificate, pending.CSR, manager.state.DeviceID, subjectID, manager.now()); err != nil {
			return err
		}
		pending.Certificate = &certificate
		return manager.save()
	}
	return nil
}

func (manager *AdmissionManager) stage(ctx context.Context, forceProfileID string) error {
	identity := manager.state.Pending
	if identity == nil {
		identity = manager.state.Active
	}
	if identity == nil || identity.Certificate == nil || !identity.Certificate.ExpiresAt.After(manager.now()) {
		return errors.New("EAP certificate is unavailable or expired")
	}
	for index := range manager.state.Selections {
		selection := &manager.state.Selections[index]
		profile, err := manager.currentProfile(selection.Profile.ID)
		if err != nil || eapProfileHash(profile) != eapProfileHash(selection.Profile) {
			return errors.New("EAP policy changed; remove the old configuration before preparing it again")
		}
		if selection.Fingerprint == identity.Certificate.Fingerprint && selection.Profile.ID != forceProfileID {
			continue
		}
		// Each export can have a new encrypted PKCS12 payload, even for the same certificate.
		prior := EAPProfileIdentity{Fingerprint: selection.Fingerprint, IdentitySHA256: selection.IdentitySHA256}
		if prior.Fingerprint != "" && !slices.Contains(selection.PriorIdentities, prior) && len(selection.PriorIdentities) >= 16 {
			return errors.New("remove the managed EAP profile before preparing more certificate generations")
		}
		artifact, err := manager.system.Stage(ctx, identity.RequestID, profile, *identity.Certificate, selection.Adapter)
		if err != nil {
			return err
		}
		if prior.Fingerprint != "" && !slices.Contains(selection.PriorIdentities, prior) {
			selection.PriorIdentities = append(selection.PriorIdentities, prior)
		}
		selection.IdentitySHA256 = artifact.IdentitySHA256
		if selection.ArtifactPath != "" {
			manager.queueCleanup(EAPCleanup{Artifacts: []EAPArtifact{{Path: selection.ArtifactPath, SHA256: selection.ArtifactSHA256}}})
		}
		selection.Fingerprint, selection.RequestID = identity.Certificate.Fingerprint, identity.RequestID
		selection.ArtifactPath, selection.ArtifactSHA256 = artifact.Path, artifact.SHA256
		if err := manager.save(); err != nil {
			return err
		}
	}
	return nil
}

func (manager *AdmissionManager) Check(ctx context.Context) (checkErr error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	defer func() { checkErr = errors.Join(checkErr, manager.recoverArtifacts(ctx)) }()
	manager.diagnostic = ""
	for index := len(manager.state.Selections) - 1; index >= 0; index-- {
		selection := manager.state.Selections[index]
		profile, err := manager.currentProfile(selection.Profile.ID)
		if err != nil || eapProfileHash(profile) != eapProfileHash(selection.Profile) {
			if err := manager.system.Remove(ctx, selection.Profile, selection.Adapter, append(slices.Clone(selection.PriorIdentities), EAPProfileIdentity{Fingerprint: selection.Fingerprint, IdentitySHA256: selection.IdentitySHA256})); err != nil {
				manager.diagnostic = "configuration_removal_failed"
				return err
			}
			manager.detachSelection(index)
			if err := manager.save(); err != nil {
				return err
			}
		}
	}
	if len(manager.state.Selections) == 0 {
		return manager.cleanup(ctx)
	}
	if manager.state.Pending != nil && manager.state.Pending.Stale {
		manager.diagnostic = "certificate_prepare_required"
		return nil
	}
	if manager.state.Pending == nil && manager.state.Active != nil && manager.state.Active.Certificate != nil && (!manager.activeCurrent() || !manager.state.Active.Certificate.ExpiresAt.After(manager.now().Add(time.Hour))) {
		if err := manager.ensureIdentity(ctx, manager.state.Selections[0].Profile.Identity); err != nil {
			manager.diagnostic = "certificate_renewal_failed"
			return err
		}
		if err := manager.stage(ctx, ""); err != nil {
			manager.diagnostic = "certificate_installation_required"
			return err
		}
	}
	certificate := manager.targetCertificate()
	if certificate == nil || !certificate.ExpiresAt.After(manager.now()) {
		manager.diagnostic = "certificate_expired"
		return errors.New("EAP certificate expired; prepare the network again")
	}
	for _, selection := range manager.state.Selections {
		if selection.Fingerprint != certificate.Fingerprint || manager.system.Readback(ctx, selection.RequestID, selection.Profile, *certificate, selection.Adapter) != nil {
			manager.diagnostic = "installation_or_readback_required"
			return nil
		}
	}
	artifactsInstalled := false
	for index := range manager.state.Selections {
		selection := &manager.state.Selections[index]
		if len(selection.PriorIdentities) > 0 {
			selection.PriorIdentities = nil
			artifactsInstalled = true
		}
		if selection.ArtifactPath != "" {
			manager.queueCleanup(EAPCleanup{Artifacts: []EAPArtifact{{Path: selection.ArtifactPath, SHA256: selection.ArtifactSHA256}}})
			selection.ArtifactPath, selection.ArtifactSHA256 = "", ""
			artifactsInstalled = true
		}
	}
	if artifactsInstalled {
		if err := manager.save(); err != nil {
			return err
		}
	}
	if manager.state.Pending != nil {
		result, err := manager.control.ActivateEAPCertificate(ctx, EAPCertificateActivateRequest{CredentialID: certificate.CredentialID, Fingerprint: certificate.Fingerprint})
		if err != nil {
			manager.diagnostic = "activation_retry_pending"
			if errors.Is(err, ErrEAPCertificateStale) {
				manager.state.Pending.Stale = true
				manager.diagnostic = "certificate_prepare_required"
				return errors.Join(err, manager.save())
			}
			return err
		}
		if result.CredentialID != certificate.CredentialID || result.Fingerprint != certificate.Fingerprint || result.Status != "active" || !result.ExpiresAt.Equal(certificate.ExpiresAt) {
			return errors.New("EAP activation receipt does not match the installed identity")
		}
		certificate.Status = "active"
		if manager.state.Active != nil {
			manager.queueCleanup(EAPCleanup{RequestID: manager.state.Active.RequestID, Certificate: manager.state.Active.Certificate})
		}
		manager.state.Pending.ActivatedAt = manager.now().UTC()
		manager.state.Active, manager.state.Pending = manager.state.Pending, nil
		if err := manager.save(); err != nil {
			return err
		}
	}
	return manager.cleanup(ctx)
}

func (manager *AdmissionManager) Remove(ctx context.Context, profileID string) (removeErr error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	defer func() { removeErr = errors.Join(removeErr, manager.recoverArtifacts(ctx)) }()
	index := slices.IndexFunc(manager.state.Selections, func(selection eapSelection) bool { return selection.Profile.ID == profileID })
	if index < 0 {
		return errors.New("EAP profile is not managed by this service")
	}
	selection := manager.state.Selections[index]
	if err := manager.system.Remove(ctx, selection.Profile, selection.Adapter, append(slices.Clone(selection.PriorIdentities), EAPProfileIdentity{Fingerprint: selection.Fingerprint, IdentitySHA256: selection.IdentitySHA256})); err != nil {
		return err
	}
	manager.detachSelection(index)
	if err := manager.save(); err != nil {
		return err
	}
	return manager.cleanup(ctx)
}

func (manager *AdmissionManager) Connect(ctx context.Context, profileID string) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.state.Pending != nil || !manager.activeCurrent() {
		return errors.New("EAP identity must be installed and activated before connecting")
	}
	profile, err := manager.currentProfile(profileID)
	if err != nil {
		return err
	}
	for _, selection := range manager.state.Selections {
		if selection.Profile.ID == profileID && eapProfileHash(selection.Profile) == eapProfileHash(profile) {
			if err := manager.system.Readback(ctx, selection.RequestID, profile, *manager.state.Active.Certificate, selection.Adapter); err != nil {
				return err
			}
			return manager.system.Connect(ctx, selection.RequestID, profile, *manager.state.Active.Certificate, selection.Adapter)
		}
	}
	return errors.New("EAP profile has not been installed")
}

func (manager *AdmissionManager) activeCurrent() bool {
	active := manager.state.Active
	if active == nil || active.Certificate == nil || !active.Certificate.ExpiresAt.After(manager.now()) {
		return false
	}
	if manager.observedAt.Before(active.ActivatedAt) {
		return true
	}
	for _, selection := range manager.state.Selections {
		profile, err := manager.currentProfile(selection.Profile.ID)
		if err != nil || profile.ClientCertificateFingerprint != active.Certificate.Fingerprint {
			return false
		}
	}
	return true
}

func (manager *AdmissionManager) currentProfile(id string) (AdmissionProfile, error) {
	if !manager.validUntil.After(manager.now()) {
		return AdmissionProfile{}, errors.New("EAP authorization must be refreshed")
	}
	for _, profile := range manager.profiles {
		if profile.ID == id {
			return profile, nil
		}
	}
	return AdmissionProfile{}, errors.New("EAP profile is no longer authorized")
}

func (manager *AdmissionManager) targetCertificate() *EAPCertificateResult {
	if manager.state.Pending != nil {
		return manager.state.Pending.Certificate
	}
	if manager.state.Active != nil {
		return manager.state.Active.Certificate
	}
	return nil
}

func (manager *AdmissionManager) save() (saveErr error) {
	defer func() {
		if saveErr != nil {
			// A failed commit must not leave a newer identity usable only in memory.
			var saved eapState
			if json.Unmarshal(manager.savedState, &saved) == nil {
				manager.state = saved
			}
			manager.validUntil = time.Time{}
			manager.diagnostic = "state_persistence_failed"
		}
	}()
	raw, err := json.Marshal(manager.state)
	if err != nil || len(raw) > 256<<10 || len(manager.state.Cleanup) > 16 {
		return errors.New("EAP state exceeds the safe size")
	}
	directory := filepath.Dir(manager.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err := secureStateDirectory(directory); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".eap-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(raw)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), manager.path); err != nil {
		return err
	}
	manager.savedState = slices.Clone(raw)
	return nil
}

func eapProfileHash(profile AdmissionProfile) string {
	profile.ClientCertificateFingerprint = ""
	raw, _ := json.Marshal(profile)
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

func cloneAdmissionProfile(profile AdmissionProfile) AdmissionProfile {
	profile.ServerNames, profile.CACertificates = slices.Clone(profile.ServerNames), slices.Clone(profile.CACertificates)
	return profile
}
