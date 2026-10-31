package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/opensoha/soha-app/internal/endpointservice"
	"github.com/zalando/go-keyring"
)

func TestAppInstanceDefaultPathsPreserved(t *testing.T) {
	configHome, cacheHome := filepath.Join(t.TempDir(), "config"), filepath.Join(t.TempDir(), "cache")
	got, err := resolveAppInstance("", "", configHome, cacheHome)
	want := appInstance{
		configPath:    filepath.Join(configHome, "OpenSoha", "Soha", "config.json"),
		logDirectory:  filepath.Join(cacheHome, "OpenSoha", "Soha", "logs"),
		companionPath: filepath.Join(configHome, "OpenSoha", "companion-window.json"),
		downloadDir:   filepath.Join(cacheHome, "Soha", "downloads"),
		id:            "com.opensoha.app", title: "Soha",
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("instance=%+v error=%v, want %+v", got, err, want)
	}
	ring := newMemoryKeyring()
	if got.keyring(ring) != ring {
		t.Fatal("default instance changed the credential namespace")
	}
}

func TestAppInstanceProfilesDoNotShareState(t *testing.T) {
	configHome, cacheHome := t.TempDir(), t.TempDir()
	seen := map[string]bool{}
	for _, profile := range []string{"", "task115-a", "task115-b"} {
		instance, err := resolveAppInstance(profile, "disabled", configHome, cacheHome)
		if err != nil {
			t.Fatal(err)
		}
		paths := []string{instance.configPath, instance.logDirectory, instance.companionPath, instance.downloadDir, instance.id, instance.title}
		if profile != "" {
			paths = append(paths, instance.webviewDir)
		}
		for _, path := range paths {
			if path == "" || seen[path] {
				t.Fatalf("shared or empty profile state: %q", path)
			}
			seen[path] = true
		}
		if !instance.networkDisabled {
			t.Fatal("native network mode was not captured")
		}
	}
}

func TestAppInstanceRejectsInvalidOptions(t *testing.T) {
	for _, profile := range []string{"../main", "/absolute", `a\b`, "a.b", "a b", "a\n", "A", "9bad", "-bad", "é", strings.Repeat("a", 49)} {
		if _, err := resolveAppInstance(profile, "disabled", t.TempDir(), t.TempDir()); err == nil {
			t.Errorf("accepted profile %q", profile)
		}
	}
	for _, mode := range []string{"enable", "Disabled", " disabled", "disabled\n", "false"} {
		if _, err := resolveAppInstance("task115", mode, t.TempDir(), t.TempDir()); err == nil {
			t.Errorf("accepted network mode %q", mode)
		}
	}
}

func TestAppInstanceMacBundleCannotFallBackToDefaultProfile(t *testing.T) {
	for _, test := range []struct {
		name, profile, bundleID string
		wantError               bool
	}{
		{"unbundled-default", "", "", false},
		{"default-bundle", "", "com.opensoha.app", false},
		{"development-bundle", "", "com.opensoha.app.dev", false},
		{"missing-profile-environment", "", "com.opensoha.app.profile.task115-a", true},
		{"matching-profile", "task115-a", "com.opensoha.app.profile.task115-a", false},
		{"different-profile", "task115-b", "com.opensoha.app.profile.task115-a", true},
		{"profile-in-default-bundle", "task115-a", "com.opensoha.app", true},
		{"unbundled-profile", "task115-a", "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			instance, err := resolveAppInstance(test.profile, "disabled", t.TempDir(), t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := validateAppInstanceBundleID(instance, test.bundleID); (err != nil) != test.wantError {
				t.Fatalf("bundle/profile mismatch result=%v, wantError=%v", err, test.wantError)
			}
		})
	}
}

func TestAppProfileCredentialsStayIsolatedAtSameOrigin(t *testing.T) {
	store := newMemoryKeyring()
	defaultRing := (appInstance{}).keyring(store)
	first := (appInstance{profile: "task115-a"}).keyring(store)
	second := (appInstance{profile: "task115-b"}).keyring(store)
	const account = "https://same-server.example.test"
	for index, ring := range []keyring.Keyring{defaultRing, first, second} {
		if err := ring.Set(sessionKeyringService, account, []string{"default", "first", "second"}[index]); err != nil {
			t.Fatal(err)
		}
	}
	if err := first.Delete(sessionKeyringService, account); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Get(sessionKeyringService, account); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatal("deleted profile still returned a credential or fell back to another profile")
	}
	if err := first.Set(sessionKeyringService, account, "replacement"); err != nil {
		t.Fatal(err)
	}
	if err := first.DeleteAll(sessionKeyringService); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Get(sessionKeyringService, account); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatal("DeleteAll did not clear the selected profile")
	}
	for index, ring := range []keyring.Keyring{defaultRing, second} {
		value, err := ring.Get(sessionKeyringService, account)
		if err != nil || value != []string{"default", "second"}[index] {
			t.Fatalf("another profile credential changed: value=%q error=%v", value, err)
		}
	}
}

func TestAppRuntimeDisabledNetworkNeverTouchesHost(t *testing.T) {
	runtimeAPI := &appRuntime{
		networkDisabled: true,
		networkCall: func(context.Context, string, *endpointservice.ConnectInput) (endpointservice.Status, error) {
			t.Fatal("disabled instance contacted network IPC")
			return endpointservice.Status{}, nil
		},
		networkMihomoCall: func(context.Context, string, *endpointservice.MihomoAppInput) (endpointservice.MihomoAppStatus, error) {
			t.Fatal("disabled instance contacted Mihomo IPC")
			return endpointservice.MihomoAppStatus{}, nil
		},
		networkLinkStatus: func() NetworkLinkStatus {
			t.Fatal("disabled instance inspected native links")
			return NetworkLinkStatus{}
		},
	}
	for _, path := range []string{"status", "link", "connect", "disconnect", "mihomo", "mihomo/selection", "mihomo/refresh", "future-action"} {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			response := httptest.NewRecorder()
			runtimeAPI.ServeHTTP(response, httptest.NewRequest(method, "/app/v1/network/"+path, strings.NewReader("invalid JSON")))
			var body struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || response.Code != http.StatusServiceUnavailable || body.Error.Code != "network_control_disabled" {
				t.Fatalf("%s %s: status=%d body=%s error=%v", method, path, response.Code, response.Body.String(), err)
			}
		}
	}
	response := httptest.NewRecorder()
	runtimeAPI.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/app/v1/info", nil))
	if response.Code != http.StatusOK {
		t.Fatal("disabled native network blocked unrelated runtime metadata")
	}
}
