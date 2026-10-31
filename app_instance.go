package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zalando/go-keyring"
)

// appInstance is resolved once, before reading any saved state or credentials.
type appInstance struct {
	profile         string
	configPath      string
	logDirectory    string
	companionPath   string
	downloadDir     string
	webviewDir      string
	id              string
	title           string
	networkDisabled bool
}

func loadAppInstance() (appInstance, error) {
	profile, networkMode := os.Getenv("SOHA_APP_PROFILE"), os.Getenv("SOHA_APP_NATIVE_NETWORK")
	if err := validateAppInstanceOptions(profile, networkMode); err != nil {
		return appInstance{}, err
	}
	configHome, err := os.UserConfigDir()
	if err != nil {
		return appInstance{}, fmt.Errorf("resolve config directory: %w", err)
	}
	cacheHome, err := os.UserCacheDir()
	if err != nil {
		return appInstance{}, fmt.Errorf("resolve cache directory: %w", err)
	}
	instance, err := resolveAppInstance(profile, networkMode, configHome, cacheHome)
	if err != nil {
		return appInstance{}, err
	}
	if err := validateAppInstancePlatform(instance); err != nil {
		return appInstance{}, err
	}
	return instance, nil
}

func validateAppInstanceOptions(profile, networkMode string) error {
	if profile != "" {
		if len(profile) > 48 || profile[0] < 'a' || profile[0] > 'z' {
			return errors.New("SOHA_APP_PROFILE must start with a lowercase letter and contain at most 48 lowercase letters, digits or hyphens")
		}
		for _, character := range profile {
			if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
				return errors.New("SOHA_APP_PROFILE contains an invalid character")
			}
		}
	}
	if networkMode != "" && networkMode != "disabled" {
		return errors.New("SOHA_APP_NATIVE_NETWORK must be empty or disabled")
	}
	return nil
}

// A profile bundle can also be opened by LaunchServices without its original
// environment. Reject that launch before it can read the default saved state.
func validateAppInstanceBundleID(instance appInstance, bundleID string) error {
	if instance.profile == "" {
		if strings.HasPrefix(bundleID, "com.opensoha.app.profile.") {
			return errors.New("a named macOS App bundle requires an explicit matching SOHA_APP_PROFILE")
		}
		return nil
	}
	if bundleID != instance.id {
		return errors.New("a named App profile requires a separate macOS .app bundle whose CFBundleIdentifier matches com.opensoha.app.profile.<profile>")
	}
	return nil
}

func resolveAppInstance(profile, networkMode, configHome, cacheHome string) (appInstance, error) {
	if err := validateAppInstanceOptions(profile, networkMode); err != nil {
		return appInstance{}, err
	}
	configDir := filepath.Join(configHome, "OpenSoha", "Soha")
	cacheDir := filepath.Join(cacheHome, "OpenSoha", "Soha")
	instance := appInstance{
		profile: profile, id: "com.opensoha.app", title: "Soha",
		companionPath:   filepath.Join(configHome, "OpenSoha", "companion-window.json"),
		downloadDir:     filepath.Join(cacheHome, "Soha", "downloads"),
		networkDisabled: networkMode == "disabled",
	}
	if profile != "" {
		configDir = filepath.Join(configDir, "profiles", profile)
		cacheDir = filepath.Join(cacheDir, "profiles", profile)
		instance.companionPath = filepath.Join(configDir, "companion-window.json")
		instance.downloadDir = filepath.Join(cacheDir, "downloads")
		instance.webviewDir = filepath.Join(cacheDir, "webview")
		instance.id += ".profile." + profile
		instance.title += " [" + profile + "]"
	}
	instance.configPath = filepath.Join(configDir, "config.json")
	instance.logDirectory = filepath.Join(cacheDir, "logs")
	return instance, nil
}

func (instance appInstance) keyring(store keyring.Keyring) keyring.Keyring {
	if instance.profile == "" {
		return store
	}
	return profileKeyring{store: store, profile: instance.profile}
}

// Namespace every operation, including DeleteAll, without migrating a default
// profile credential even when both profiles use the same server origin.
type profileKeyring struct {
	store   keyring.Keyring
	profile string
}

func (ring profileKeyring) service(service string) string {
	return service + ".profile." + ring.profile
}

func (ring profileKeyring) Set(service, user, password string) error {
	return ring.store.Set(ring.service(service), user, password)
}

func (ring profileKeyring) Get(service, user string) (string, error) {
	return ring.store.Get(ring.service(service), user)
}

func (ring profileKeyring) Delete(service, user string) error {
	return ring.store.Delete(ring.service(service), user)
}

func (ring profileKeyring) DeleteAll(service string) error {
	return ring.store.DeleteAll(ring.service(service))
}
