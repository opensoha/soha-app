//go:build darwin

package endpointservice

import (
	"context"
	"errors"
	"strings"
	"time"
)

func (system *DarwinEAPSystem) Adapters(ctx context.Context) ([]EAPAdapter, error) {
	return darwinEAPAdapters(ctx)
}

func (system *DarwinEAPSystem) validateAdapter(ctx context.Context, selected EAPAdapter) error {
	adapters, err := system.Adapters(ctx)
	if err != nil {
		return err
	}
	for _, adapter := range adapters {
		if adapter.ID == selected.ID && adapter.Name == selected.Name && adapter.Medium == selected.Medium && adapter.Enabled && adapter.MACAddress != "" && strings.EqualFold(adapter.MACAddress, selected.MACAddress) && adapter.EthernetPosition == selected.EthernetPosition {
			return nil
		}
	}
	return errors.New("selected EAP network service, MAC or Ethernet order changed")
}

func (system *DarwinEAPSystem) Stage(ctx context.Context, requestID string, profile AdmissionProfile, certificate EAPCertificateResult, adapter EAPAdapter) (EAPStagedProfile, error) {
	if err := system.validateAdapter(ctx, adapter); err != nil {
		return EAPStagedProfile{}, err
	}
	if profile.AccessMedium != adapter.Medium {
		return EAPStagedProfile{}, errors.New("EAP profile and adapter media differ")
	}
	return system.ExportProfile(ctx, requestID, profile, certificate, adapter.EthernetPosition)
}

func darwinEAPProfiles(ctx context.Context) (map[string]any, error) {
	raw, err := eapCommandOutput(ctx, 4<<20, "/usr/bin/profiles", "show", "-type", "configuration", "-output", "stdout-xml")
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	return parseEAPPlist(raw)
}

func (system *DarwinEAPSystem) Readback(ctx context.Context, _ string, profile AdmissionProfile, certificate EAPCertificateResult, adapter EAPAdapter) error {
	if err := system.validateAdapter(ctx, adapter); err != nil {
		return err
	}
	plist, err := darwinEAPProfiles(ctx)
	if err != nil {
		return err
	}
	installed, err := findDarwinEAPProfile(plist, eapProfileIdentifier(system.deviceID, profile.ID))
	if err != nil {
		return err
	}
	if installed == nil {
		return errors.New("install the Soha EAP profile in System Settings")
	}
	// The PKCS12 bytes are intentionally excluded; the native keychain identity is checked below.
	raw, err := renderEAPMobileconfig(profile, system.deviceID, certificate, []byte{1}, strings.Repeat("x", 32), adapter.EthernetPosition, time.Now())
	if err != nil {
		return err
	}
	expected, err := parseEAPPlist(raw)
	if err != nil {
		return err
	}
	if err := matchDarwinEAPPayloads(installed, expected); err != nil {
		return err
	}
	leaf, err := parseEAPCertificate(certificate.CertificatePEM)
	if err != nil {
		return err
	}
	return darwinEAPIdentityReadback(ctx, leaf.Raw)
}

func (system *DarwinEAPSystem) Remove(ctx context.Context, profile AdmissionProfile, adapter EAPAdapter, identities []EAPProfileIdentity) error {
	identifier := eapProfileIdentifier(system.deviceID, profile.ID)
	plist, err := darwinEAPProfiles(ctx)
	if err != nil {
		return err
	}
	installed, err := findDarwinEAPProfile(plist, identifier)
	if err != nil || installed == nil {
		return err
	}
	if err := matchDarwinEAPRemoval(installed, profile, adapter, system.deviceID, identities); err != nil {
		return err
	}
	if _, err := eapCommandOutput(ctx, 4096, "/usr/bin/profiles", "remove", "-identifier", identifier); err != nil {
		return err
	}
	plist, err = darwinEAPProfiles(ctx)
	if err != nil {
		return err
	}
	installed, err = findDarwinEAPProfile(plist, identifier)
	if err != nil || installed != nil {
		return errors.New("managed EAP profile removal was not confirmed")
	}
	return nil
}

func (system *DarwinEAPSystem) Connect(ctx context.Context, requestID string, profile AdmissionProfile, certificate EAPCertificateResult, adapter EAPAdapter) error {
	if err := system.Readback(ctx, requestID, profile, certificate, adapter); err != nil {
		return err
	}
	if adapter.Medium == "wired" {
		return errors.New("macOS starts wired 802.1X after profile installation and link activation; confirm the NAS session")
	}
	leaf, err := parseEAPCertificate(certificate.CertificatePEM)
	if err != nil {
		return err
	}
	return darwinEAPAssociate(ctx, adapter.Name, profile.SSID, profile.Identity, profile.WifiSecurity, leaf.Raw)
}
