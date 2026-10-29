//go:build windows

package endpointservice

import (
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
)

// Upgrades and uninstall cannot silently abandon persisted native controls.
func CheckNativeChannelRemoval(configPath string) error {
	if _, err := os.Stat(configPath); errors.Is(err, os.ErrNotExist) {
		marker, markerErr := nativeChannelMarkerPath()
		if markerErr != nil {
			return markerErr
		}
		if _, stateErr := os.Stat(marker); !errors.Is(stateErr, os.ErrNotExist) {
			return errors.New("service configuration is missing after native channel initialization; restore the protected configuration before removal")
		}
		return nil
	}
	config, err := LoadConfig(configPath)
	if err != nil {
		return err
	}
	marker, err := nativeChannelMarkerPath()
	if err != nil {
		return err
	}
	owner, err := loadNativeChannelOwner(marker)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil && (owner.Identity != channelIdentity(config) || owner.StateDirectory != config.StateDirectory) {
		return errors.New("service configuration does not match native channel ownership; restore the protected configuration before removal")
	}
	for _, file := range []string{"channel-floor.json", "channel-printers.json"} {
		raw, err := readFileBounded(filepath.Join(config.StateDirectory, file), 256<<10, true)
		if errors.Is(err, os.ErrNotExist) {
			if file == "channel-floor.json" && owner.Accepted {
				return errors.New("accepted native channel floor is missing; restore protected state before removal")
			}
			continue
		}
		if err != nil {
			return err
		}
		plain, err := unprotectSecret(raw, channelStateDescription)
		if err != nil {
			return err
		}
		if file == "channel-floor.json" {
			var floor channelFloor
			err = decodeStrict(plain, &floor)
			clear(plain)
			if err != nil {
				return err
			}
			if floor.Identity != channelIdentity(config) || floor.Revision < 1 {
				return errors.New("invalid native floor; keep service for repair")
			}
			if floor.Controls.USB || floor.Controls.Print || floor.Controls.Clipboard {
				return errors.New("publish release of native channels and confirm cleanup before upgrade or uninstall")
			}
		} else {
			var journal channelJournal
			err = decodeStrict(plain, &journal)
			clear(plain)
			if err != nil {
				return err
			}
			if journal.Version != 1 || journal.Identity != channelIdentity(config) || journal.Printers == nil {
				return errors.New("invalid native printer journal; keep service for repair")
			}
			if len(journal.Printers) > 0 {
				return errors.New("native printer restoration is pending; keep the service and its journal")
			}
		}
	}
	return nil
}

func nativeChannelMarkerPath() (string, error) {
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "OpenSoha", "Soha", "native-channel-ownership", "registration.dpapi"), nil
}

type nativeChannelOwner struct {
	Version        int    `json:"version"`
	Identity       string `json:"identity"`
	StateDirectory string `json:"stateDirectory"`
	Accepted       bool   `json:"accepted"`
}

func loadNativeChannelOwner(marker string) (nativeChannelOwner, error) {
	var owner nativeChannelOwner
	raw, err := readFileBounded(marker, 32768, true)
	if err != nil {
		return owner, err
	}
	plain, err := unprotectSecret(raw, channelStateDescription)
	if err != nil {
		return owner, err
	}
	defer clear(plain)
	var stored struct {
		Version        int    `json:"version"`
		Identity       string `json:"identity"`
		StateDirectory string `json:"stateDirectory"`
		Accepted       *bool  `json:"accepted"`
	}
	if err := decodeStrict(plain, &stored); err != nil {
		return owner, err
	}
	if stored.Version != 1 || stored.Accepted == nil || stored.Identity == "" || !filepath.IsAbs(stored.StateDirectory) {
		return owner, errors.New("native channel ownership is incomplete; restore protected state")
	}
	owner = nativeChannelOwner{Version: stored.Version, Identity: stored.Identity, StateDirectory: stored.StateDirectory, Accepted: *stored.Accepted}
	return owner, nil
}
func registerNativeChannelOwner(config Config) error {
	marker, err := nativeChannelMarkerPath()
	if err != nil {
		return err
	}
	old, err := loadNativeChannelOwner(marker)
	if err == nil {
		if old.Identity != channelIdentity(config) || old.StateDirectory != config.StateDirectory {
			return errors.New("native channel owner changed; preserve the prior configuration and state")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, _ := json.Marshal(nativeChannelOwner{Version: 1, Identity: channelIdentity(config), StateDirectory: config.StateDirectory})
	return saveProtectedState(marker, data, channelStateDescription)
}
func FinalizeNativeChannelRemoval(configPath string) error {
	if err := CheckNativeChannelRemoval(configPath); err != nil {
		return err
	}
	marker, err := nativeChannelMarkerPath()
	if err != nil {
		return err
	}
	if err := os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
