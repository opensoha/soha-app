//go:build windows

package endpointservice

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

type WindowsEAPSystem struct {
	directory string
	deviceID  string
	userSID   string
}

type eapWindowsBinding struct {
	Version     int        `json:"version"`
	DeviceID    string     `json:"deviceId"`
	ProfileID   string     `json:"profileId"`
	Adapter     EAPAdapter `json:"adapter"`
	ManagedXML  []byte     `json:"managedXml"`
	BaselineXML []byte     `json:"baselineXml,omitempty"`
}

func NewWindowsEAPSystem(directory, deviceID, userSID string) (*WindowsEAPSystem, error) {
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || !current.User.Sid.IsWellKnown(windows.WinLocalSystemSid) || !filepath.IsAbs(directory) || !identifierPattern.MatchString(deviceID) || !validSID(userSID) {
		return nil, errors.New("Windows EAP requires a LocalSystem service and an enrolled user SID")
	}
	directory = filepath.Join(directory, "eap-windows")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	if err := secureStateDirectory(directory); err != nil {
		return nil, err
	}
	return &WindowsEAPSystem{directory: directory, deviceID: deviceID, userSID: userSID}, nil
}

func (system *WindowsEAPSystem) Adapters(ctx context.Context) ([]EAPAdapter, error) {
	return windowsEAPAdapters(ctx)
}

func (system *WindowsEAPSystem) CreateCSR(ctx context.Context, requestID string) (string, error) {
	result, err := callEAPUserHelper(ctx, system.userSID, eapUserRequest{Action: "csr", DeviceID: system.deviceID, RequestID: requestID})
	return result.CSR, err
}

func (system *WindowsEAPSystem) bindingPath(profileID string) string {
	return filepath.Join(system.directory, fmt.Sprintf("%x.json", sha256.Sum256([]byte(system.deviceID+"/"+profileID))))
}

func (system *WindowsEAPSystem) binding(profile AdmissionProfile, adapter EAPAdapter) (*eapWindowsBinding, error) {
	raw, err := readFileBounded(system.bindingPath(profile.ID), 384<<10, true)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var binding eapWindowsBinding
	if decodeStrict(raw, &binding) != nil || binding.Version != 1 || binding.DeviceID != system.deviceID || binding.ProfileID != profile.ID || binding.Adapter.ID != adapter.ID || binding.Adapter.Name != adapter.Name || binding.Adapter.Medium != adapter.Medium || !strings.EqualFold(binding.Adapter.MACAddress, adapter.MACAddress) || len(binding.ManagedXML) == 0 || len(binding.ManagedXML) > 128<<10 || len(binding.BaselineXML) > 128<<10 {
		return nil, errors.New("stored Windows EAP binding is invalid")
	}
	return &binding, nil
}

func (system *WindowsEAPSystem) saveBinding(binding eapWindowsBinding) error {
	raw, err := json.Marshal(binding)
	if err != nil || len(raw) > 384<<10 {
		return errors.New("Windows EAP binding exceeds the safe size")
	}
	file, err := os.CreateTemp(system.directory, ".binding-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(raw)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	return os.Rename(file.Name(), system.bindingPath(binding.ProfileID))
}

func (system *WindowsEAPSystem) helper(ctx context.Context, action, requestID string, profile AdmissionProfile, certificate *EAPCertificateResult, adapter EAPAdapter, expected []byte) (eapUserResponse, error) {
	result, err := callEAPUserHelper(ctx, system.userSID, eapUserRequest{Action: action, DeviceID: system.deviceID, RequestID: requestID, Profile: &profile, Certificate: certificate, Adapter: &adapter, ExpectedXML: expected})
	if err == nil && certificate != nil && action != "network_inspect" && result.Fingerprint != certificate.Fingerprint {
		return eapUserResponse{}, errors.New("Windows EAP receipt does not match the expected identity")
	}
	return result, err
}

func (system *WindowsEAPSystem) Stage(ctx context.Context, requestID string, profile AdmissionProfile, certificate EAPCertificateResult, adapter EAPAdapter) (EAPStagedProfile, error) {
	if err := validateWindowsEAPAdapter(ctx, adapter, true); err != nil {
		return EAPStagedProfile{}, err
	}
	configuration, err := renderEAPWindowsProfile(profile, system.deviceID, certificate, time.Now())
	if err != nil || profile.AccessMedium != adapter.Medium {
		return EAPStagedProfile{}, errors.New("Windows EAP profile or medium is invalid")
	}
	binding, err := system.binding(profile, adapter)
	if err != nil {
		return EAPStagedProfile{}, err
	}
	if binding == nil {
		binding = &eapWindowsBinding{Version: 1, DeviceID: system.deviceID, ProfileID: profile.ID, Adapter: adapter, ManagedXML: configuration.XML}
		if adapter.Medium == "wifi" {
			result, err := system.helper(ctx, "network_inspect", requestID, profile, &certificate, adapter, nil)
			if err != nil {
				return EAPStagedProfile{}, err
			}
			if result.Present {
				return EAPStagedProfile{}, errors.New("a wireless profile with this name already exists outside Soha")
			}
		} else {
			baseline, err := system.lanProfile(ctx, adapter)
			if err != nil {
				return EAPStagedProfile{}, err
			}
			if !eapWindowsLANBaselineAllowed(baseline) {
				return EAPStagedProfile{}, errors.New("EAP will not replace an existing wired 802.1X policy")
			}
			binding.BaselineXML = baseline
		}
		// Keep the original LAN profile and installation intent before the first OS write.
		if err := system.saveBinding(*binding); err != nil {
			return EAPStagedProfile{}, err
		}
	}
	if err := matchEAPWindowsXML(binding.ManagedXML, configuration.XML); err != nil {
		return EAPStagedProfile{}, err
	}
	if _, err := callEAPUserHelper(ctx, system.userSID, eapUserRequest{Action: "install", DeviceID: system.deviceID, RequestID: requestID, Profile: &profile, Certificate: &certificate}); err != nil {
		return EAPStagedProfile{}, err
	}
	if adapter.Medium == "wifi" {
		_, err = system.helper(ctx, "network_stage", requestID, profile, &certificate, adapter, binding.ManagedXML)
	} else {
		actual, readErr := system.lanProfile(ctx, adapter)
		if readErr != nil {
			return EAPStagedProfile{}, readErr
		}
		if matchEAPWindowsXML(actual, binding.ManagedXML) != nil {
			if matchEAPWindowsXML(actual, binding.BaselineXML) != nil {
				return EAPStagedProfile{}, errors.New("wired EAP profile changed outside Soha")
			}
			if err := system.setLANProfile(ctx, adapter, binding.ManagedXML); err != nil {
				return EAPStagedProfile{}, err
			}
		}
		err = system.Readback(ctx, requestID, profile, certificate, adapter)
	}
	return EAPStagedProfile{}, err
}

func (system *WindowsEAPSystem) Readback(ctx context.Context, requestID string, profile AdmissionProfile, certificate EAPCertificateResult, adapter EAPAdapter) error {
	if err := validateWindowsEAPAdapter(ctx, adapter, true); err != nil {
		return err
	}
	binding, err := system.binding(profile, adapter)
	if err != nil {
		return err
	}
	if binding == nil {
		return errors.New("Windows EAP profile has no protected installation record")
	}
	configuration, err := renderEAPWindowsProfile(profile, system.deviceID, certificate, time.Now())
	if err != nil {
		return err
	}
	if err := matchEAPWindowsXML(binding.ManagedXML, configuration.XML); err != nil {
		return err
	}
	if adapter.Medium == "wired" {
		actual, err := system.lanProfile(ctx, adapter)
		if err != nil {
			return err
		}
		if err := matchEAPWindowsXML(actual, binding.ManagedXML); err != nil {
			return err
		}
	}
	_, err = system.helper(ctx, "network_readback", requestID, profile, &certificate, adapter, binding.ManagedXML)
	return err
}

func (system *WindowsEAPSystem) Remove(ctx context.Context, profile AdmissionProfile, adapter EAPAdapter, _ []EAPProfileIdentity) error {
	binding, err := system.binding(profile, adapter)
	if err != nil || binding == nil {
		return err
	}
	// Removal still requires the protected binding and current adapter identity, but not availability.
	if err := validateWindowsEAPAdapter(ctx, adapter, false); err != nil {
		return err
	}
	if adapter.Medium == "wifi" {
		if _, err := system.helper(ctx, "network_remove", "", profile, nil, adapter, binding.ManagedXML); err != nil {
			return err
		}
	} else {
		actual, err := system.lanProfile(ctx, adapter)
		if err != nil {
			return err
		}
		if matchEAPWindowsXML(actual, binding.BaselineXML) != nil {
			if matchEAPWindowsXML(actual, binding.ManagedXML) != nil {
				return errors.New("wired EAP profile changed outside Soha; original profile was preserved")
			}
			if err := system.setLANProfile(ctx, adapter, binding.BaselineXML); err != nil {
				return err
			}
		}
	}
	return os.Remove(system.bindingPath(profile.ID))
}

func (system *WindowsEAPSystem) Connect(ctx context.Context, requestID string, profile AdmissionProfile, certificate EAPCertificateResult, adapter EAPAdapter) error {
	if err := system.Readback(ctx, requestID, profile, certificate, adapter); err != nil {
		return err
	}
	if adapter.Medium == "wired" {
		_, err := eapWindowsNetsh(ctx, "lan", "reconnect", "interface="+adapter.Name)
		return err
	}
	_, err := system.helper(ctx, "network_connect", requestID, profile, &certificate, adapter, nil)
	return err
}

func eapWindowsNetsh(ctx context.Context, arguments ...string) ([]byte, error) {
	directory, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	return eapCommandOutput(ctx, 8192, filepath.Join(directory, "netsh.exe"), arguments...)
}

func (system *WindowsEAPSystem) lanProfile(ctx context.Context, adapter EAPAdapter) ([]byte, error) {
	directory, err := os.MkdirTemp(system.directory, ".lan-readback-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(directory)
	if _, err := eapWindowsNetsh(ctx, "lan", "export", "profile", "folder="+directory, "interface="+adapter.Name); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 || entries[0].IsDir() || !strings.EqualFold(filepath.Ext(entries[0].Name()), ".xml") {
		return nil, errors.New("wired EAP profile export did not return exactly one interface profile")
	}
	raw, err := readFileBounded(filepath.Join(directory, entries[0].Name()), 128<<10, true)
	if err != nil {
		return nil, err
	}
	if _, err := parseEAPWindowsXML(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func (system *WindowsEAPSystem) setLANProfile(ctx context.Context, adapter EAPAdapter, configuration []byte) error {
	file, err := os.CreateTemp(system.directory, ".lan-*.xml")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(configuration)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	if _, err := eapWindowsNetsh(ctx, "lan", "add", "profile", "filename="+file.Name(), "interface="+adapter.Name); err != nil {
		return err
	}
	actual, err := system.lanProfile(ctx, adapter)
	if err != nil {
		return err
	}
	return matchEAPWindowsXML(actual, configuration)
}
