package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativePersonalExportVerifiesBeforeDialogAndNeverOverwrites(t *testing.T) {
	data := "private fixture archive"
	mode := "valid"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != `{"assistantId":"mine","environmentVersion":2}` || r.URL.Path != "/api/v1/copilot/assistant/environment/export" || r.Header.Get("Authorization") != "Bearer fixture-only" {
			t.Error("native export changed authenticated selection or request body")
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		w.Header().Set("X-Assistant-ID", "mine")
		w.Header().Set("X-Content-SHA256", fmt.Sprintf("%x", sha256.Sum256([]byte(data))))
		if mode == "corrupt" {
			w.Header().Set("X-Content-SHA256", strings.Repeat("0", 64))
		}
		_, _ = io.WriteString(w, data)
	}))
	defer upstream.Close()
	host, err := newTestAppHost(http.NotFoundHandler(), upstream.URL, nil, false, "runtime", AppInfo{Platform: "darwin"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "personal-data.tar")
	prompts := 0
	host.personalArchiveDialog = func() (string, error) {
		prompts++
		if mode == "cancel" {
			return "", nil
		}
		return path, nil
	}
	call := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/app/v1/personal-data/export", strings.NewReader(`{"assistantId":"mine","environmentVersion":2}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "wails://localhost")
		r.Header.Set("Authorization", "Bearer fixture-only")
		w := httptest.NewRecorder()
		host.ServeHTTP(w, r)
		return w
	}
	mode = "corrupt"
	if r := call(); r.Code != http.StatusBadGateway || prompts != 0 {
		t.Fatal("invalid archive reached the native save dialog")
	}
	mode = "cancel"
	if r := call(); r.Code != 200 || !strings.Contains(r.Body.String(), "canceled") {
		t.Fatal("dialog cancel became a save")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("cancel created an export file")
	}
	mode = "valid"
	if r := call(); r.Code != 200 || !strings.Contains(r.Body.String(), "saved") {
		t.Fatalf("native save failed: %d", r.Code)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != data {
		t.Fatal("native save changed bytes")
	}
	if r := call(); r.Code != 503 {
		t.Fatal("existing file was silently replaced")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != data {
		t.Fatal("failed save modified the existing file")
	}
}

func TestNativePersonalExportRejectsUnsupportedPlatformsBeforeDownload(t *testing.T) {
	for _, platform := range []string{"android", "ios", ""} {
		t.Run(platform, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("unsupported export reached upstream")
			}))
			defer upstream.Close()
			host, err := newTestAppHost(http.NotFoundHandler(), upstream.URL, nil, false, "runtime", AppInfo{Platform: platform})
			if err != nil {
				t.Fatal(err)
			}
			host.personalArchiveDialog = func() (string, error) {
				t.Error("unsupported export opened save dialog")
				return "", nil
			}
			r := httptest.NewRequest(http.MethodPost, "/app/v1/personal-data/export", strings.NewReader(`{"assistantId":"mine","environmentVersion":2}`))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", "wails://localhost")
			w := httptest.NewRecorder()
			host.ServeHTTP(w, r)
			if w.Code != http.StatusNotImplemented || !strings.Contains(w.Body.String(), "export_unsupported") {
				t.Fatalf("unsupported platform was not rejected: %d %s", w.Code, w.Body.String())
			}
		})
	}
}
