//go:build darwin

package endpointservice

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

func (s *DarwinEAPSystem) PasswordSupport(ctx context.Context, p AdmissionProfile) (bool, string) {
	if err := ctx.Err(); err != nil {
		return false, "operation_cancelled"
	}
	if !NativeEAPSupported() {
		return false, "native_eap_api_unavailable"
	}
	return true, ""
}
func (s *DarwinEAPSystem) CredentialInteraction(AdmissionProfile) string { return "system-prompt" }
func (s *DarwinEAPSystem) StagePassword(ctx context.Context, id string, p AdmissionProfile, a EAPAdapter) (EAPStagedProfile, error) {
	if err := s.validateAdapter(ctx, a); err != nil {
		return EAPStagedProfile{}, err
	}
	raw, err := renderEAPMobileconfig(p, s.deviceID, EAPCertificateResult{}, nil, "", a.EthernetPosition, time.Now())
	if err != nil {
		return EAPStagedProfile{}, err
	}
	path, err := s.exportEAPFile(raw)
	if err != nil {
		return EAPStagedProfile{}, err
	}
	return EAPStagedProfile{EAPArtifact: EAPArtifact{Path: path, SHA256: fmt.Sprintf("%x", sha256.Sum256(raw))}}, nil
}
func (s *DarwinEAPSystem) ReadbackPassword(ctx context.Context, id string, p AdmissionProfile, a EAPAdapter) error {
	if err := s.validateAdapter(ctx, a); err != nil {
		return err
	}
	plist, err := darwinEAPProfiles(ctx)
	if err != nil {
		return err
	}
	installed, err := findDarwinEAPProfile(plist, eapProfileIdentifier(s.deviceID, p.ID))
	if err != nil {
		return err
	}
	if installed == nil {
		return errors.New("install the password-free Soha EAP profile in System Settings")
	}
	raw, err := renderEAPMobileconfig(p, s.deviceID, EAPCertificateResult{}, nil, "", a.EthernetPosition, time.Now())
	if err != nil {
		return err
	}
	expected, err := parseEAPPlist(raw)
	if err != nil {
		return err
	}
	return matchDarwinEAPPayloads(installed, expected)
}
func (s *DarwinEAPSystem) ConnectPassword(ctx context.Context, id string, p AdmissionProfile, a EAPAdapter, password []byte) error {
	if len(password) != 0 {
		return errors.New("macOS requires its trusted system credential prompt")
	}
	if err := s.ReadbackPassword(ctx, id, p, a); err != nil {
		return err
	}
	return ErrEAPSystemInteractionRequired
}
