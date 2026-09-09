package endpointservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

const (
	mihomoAppStateVersion     = 1
	mihomoAppStateDescription = "OpenSoha mihomo app subscription"
	maxMihomoAppStateBytes    = 16 << 10
)

type MihomoAppInput struct {
	SubscriptionURL string `json:"subscriptionUrl"`
	SelectedProxy   string `json:"selectedProxy,omitempty"`
}

type MihomoAppStatus struct {
	Mode            string   `json:"mode"`
	ProfileID       string   `json:"profileId"`
	ProfileRevision int      `json:"profileRevision"`
	Configured      bool     `json:"configured"`
	SelectedProxy   string   `json:"selectedProxy,omitempty"`
	Proxies         []string `json:"proxies"`
}

type mihomoAppState struct {
	Version         int    `json:"version"`
	ProfileID       string `json:"profileId"`
	ProfileRevision int    `json:"profileRevision"`
	SubscriptionURL string `json:"subscriptionUrl"`
	SelectedProxy   string `json:"selectedProxy"`
}

func loadMihomoAppState(path string) (mihomoAppState, error) {
	raw, err := readFileBounded(path, maxMihomoAppStateBytes, true)
	if err != nil {
		return mihomoAppState{}, err
	}
	plain, err := unprotectSecret(raw, mihomoAppStateDescription)
	if err != nil {
		return mihomoAppState{}, fmt.Errorf("unprotect mihomo app subscription: %w", err)
	}
	defer clear(plain)
	var state mihomoAppState
	if err := decodeStrict(plain, &state); err != nil || !validMihomoAppState(state) {
		return mihomoAppState{}, errors.New("stored mihomo app subscription is invalid")
	}
	return state, nil
}

func saveMihomoAppState(path string, state mihomoAppState) error {
	if !filepath.IsAbs(path) || !validMihomoAppState(state) {
		return errors.New("mihomo app subscription state is invalid")
	}
	plain, err := json.Marshal(state)
	if err != nil {
		return err
	}
	protected, err := protectSecret(plain, mihomoAppStateDescription)
	clear(plain)
	if err != nil {
		return fmt.Errorf("protect mihomo app subscription: %w", err)
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err := secureStateDirectory(directory); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".mihomo-app-*.dpapi")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(protected); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func validMihomoAppState(state mihomoAppState) bool {
	return state.Version == mihomoAppStateVersion && identifierPattern.MatchString(state.ProfileID) && state.ProfileRevision > 0 && validSubscriptionURL(state.SubscriptionURL) && validMihomoName(state.SelectedProxy)
}

func cloneMihomoAppStatus(status MihomoAppStatus) MihomoAppStatus {
	status.Proxies = slices.Clone(status.Proxies)
	return status
}
