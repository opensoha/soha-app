//go:build windows

package endpointservice

import (
	"context"
	"errors"
	"golang.org/x/sys/windows/registry"
	"time"
)

func (s *WindowsEAPSystem) PasswordSupport(ctx context.Context, p AdmissionProfile) (bool, string) {
	if ctx.Err() != nil {
		return false, "operation_cancelled"
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\EapHost\Methods\311\21`, registry.QUERY_VALUE)
	if err != nil {
		return false, "windows_eap_ttls_provider_unavailable"
	}
	key.Close()
	return true, ""
}
func (s *WindowsEAPSystem) CredentialInteraction(AdmissionProfile) string { return "system-prompt" }
func (s *WindowsEAPSystem) StagePassword(ctx context.Context, id string, p AdmissionProfile, a EAPAdapter) (EAPStagedProfile, error) {
	if err := validateWindowsEAPAdapter(ctx, a, true); err != nil {
		return EAPStagedProfile{}, err
	}
	configuration, err := renderEAPWindowsProfile(p, s.deviceID, EAPCertificateResult{}, time.Now())
	if err != nil {
		return EAPStagedProfile{}, err
	}
	binding, err := s.binding(p, a)
	if err != nil {
		return EAPStagedProfile{}, err
	}
	if binding == nil {
		binding = &eapWindowsBinding{Version: 1, DeviceID: s.deviceID, ProfileID: p.ID, Adapter: a, ManagedXML: configuration.XML}
		if a.Medium == "wired" {
			binding.BaselineXML, err = s.lanProfile(ctx, a)
			if err != nil {
				return EAPStagedProfile{}, err
			}
			if !eapWindowsLANBaselineAllowed(binding.BaselineXML) {
				return EAPStagedProfile{}, errors.New("existing wired 802.1X policy was preserved")
			}
		} else {
			result, err := s.helper(ctx, "network_inspect", id, p, nil, a, nil)
			if err != nil {
				return EAPStagedProfile{}, err
			}
			if result.Present {
				return EAPStagedProfile{}, errors.New("wireless profile already exists outside Soha")
			}
		}
		if err := s.saveBinding(*binding); err != nil {
			return EAPStagedProfile{}, err
		}
	}
	if err := matchEAPWindowsXML(binding.ManagedXML, configuration.XML); err != nil {
		return EAPStagedProfile{}, err
	}
	if a.Medium == "wifi" {
		_, err = s.helper(ctx, "network_stage", id, p, nil, a, binding.ManagedXML)
	} else {
		if _, err := s.helper(ctx, "network_stage", id, p, nil, a, binding.ManagedXML); err != nil {
			return EAPStagedProfile{}, err
		}
		actual, readErr := s.lanProfile(ctx, a)
		if readErr != nil {
			return EAPStagedProfile{}, readErr
		}
		if matchEAPWindowsXML(actual, binding.ManagedXML) != nil {
			if matchEAPWindowsXML(actual, binding.BaselineXML) != nil {
				return EAPStagedProfile{}, errors.New("wired profile changed outside Soha")
			}
			err = s.setLANProfile(ctx, a, binding.ManagedXML)
		}
	}
	return EAPStagedProfile{}, err
}
func (s *WindowsEAPSystem) ReadbackPassword(ctx context.Context, id string, p AdmissionProfile, a EAPAdapter) error {
	if err := validateWindowsEAPAdapter(ctx, a, true); err != nil {
		return err
	}
	binding, err := s.binding(p, a)
	if err != nil {
		return err
	}
	if binding == nil {
		return errors.New("password EAP profile has no protected binding")
	}
	configuration, err := renderEAPWindowsProfile(p, s.deviceID, EAPCertificateResult{}, time.Now())
	if err != nil {
		return err
	}
	if err := matchEAPWindowsXML(binding.ManagedXML, configuration.XML); err != nil {
		return err
	}
	if a.Medium == "wired" {
		actual, err := s.lanProfile(ctx, a)
		if err != nil {
			return err
		}
		if err := matchEAPWindowsXML(actual, binding.ManagedXML); err != nil {
			return err
		}
	}
	_, err = s.helper(ctx, "network_readback", id, p, nil, a, binding.ManagedXML)
	return err
}
func (s *WindowsEAPSystem) ConnectPassword(ctx context.Context, id string, p AdmissionProfile, a EAPAdapter, password []byte) error {
	if len(password) != 0 {
		return errors.New("Windows TTLS requires its trusted system credential prompt")
	}
	if err := s.ReadbackPassword(ctx, id, p, a); err != nil {
		return err
	}
	if a.Medium == "wired" {
		_, err := eapWindowsNetsh(ctx, "lan", "reconnect", "interface="+a.Name)
		return err
	}
	_, err := s.helper(ctx, "network_connect", id, p, nil, a, nil)
	return err
}
