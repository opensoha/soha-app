package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type testSoftwareCatalog struct {
	items []softwareCatalogItem
}

func (catalog testSoftwareCatalog) List(context.Context, string) ([]softwareCatalogItem, error) {
	return catalog.items, nil
}

func TestServerSoftwareCatalogForwardsAuthorizationThroughInstall(t *testing.T) {
	payload := []byte("managed software package")
	digest := sha256.Sum256(payload)
	const authorization = "Bearer endpoint-token"
	fileName := installerFileName(runtime.GOOS)
	var listCalls atomic.Int32
	var downloadCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != authorization {
			t.Fatalf("authorization was not forwarded to %s", request.URL.Path)
		}
		switch request.URL.Path {
		case "/api/v1/software/packages":
			listCalls.Add(1)
			if request.URL.Query().Get("platform") != runtime.GOOS || request.URL.Query().Get("arch") != runtime.GOARCH {
				t.Fatalf("unexpected catalog filters: %s", request.URL.RawQuery)
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"items": []map[string]any{{
				"id": "0123456789abcdef0123456789abcdef", "softwareId": "managed-tool",
				"name": "Managed Tool", "publisher": "OpenSoha", "version": "1.0.0",
				"platform": runtime.GOOS, "arch": runtime.GOARCH, "fileName": fileName,
				"sizeBytes": len(payload), "sha256": hex.EncodeToString(digest[:]),
				"downloadPath": "/ignored",
			}}})
		case "/api/v1/software/packages/0123456789abcdef0123456789abcdef/download":
			downloadCalls.Add(1)
			_, _ = writer.Write(payload)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	catalog, err := newServerSoftwareCatalog(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	catalog.client = server.Client()
	opened := make(chan string, 1)
	library := newSoftwareLibrary(catalog)
	library.client = server.Client()
	library.downloadDir = t.TempDir()
	library.openFile = func(path string) error {
		opened <- path
		return nil
	}
	runtimeAPI := &appRuntime{version: "0.1.0", software: library}

	request := httptest.NewRequest(http.MethodPost, "/app/v1/software/0123456789abcdef0123456789abcdef/install", nil)
	request.Header.Set("Authorization", authorization)
	response := httptest.NewRecorder()
	runtimeAPI.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("unexpected install status: %d: %s", response.Code, response.Body.String())
	}
	var started softwareTaskResponse
	if err := json.NewDecoder(response.Body).Decode(&started); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		library.tasksMu.RLock()
		current := library.tasks[started.Task.ID]
		library.tasksMu.RUnlock()
		if current.State == softwareTaskCompleted {
			break
		}
		if current.State == softwareTaskFailed {
			t.Fatalf("install failed: %#v", current)
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for install task")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if listCalls.Load() != 1 || downloadCalls.Load() != 1 {
		t.Fatalf("unexpected upstream calls: list=%d download=%d", listCalls.Load(), downloadCalls.Load())
	}
	select {
	case <-opened:
	default:
		t.Fatal("system installer was not opened")
	}
}

func TestSoftwareCatalogListHidesDownloadMetadata(t *testing.T) {
	artifact := softwareArtifact{
		Platform: runtime.GOOS,
		Arch:     runtime.GOARCH,
		URL:      "https://downloads.example.com/soha.pkg",
		SHA256:   strings.Repeat("a", 64),
		FileName: "soha.pkg",
		Size:     1024,
	}
	library := newSoftwareLibrary(testSoftwareCatalog{items: []softwareCatalogItem{{
		ID:          "soha-tools",
		Name:        "Soha Tools",
		Description: "Developer tools",
		Publisher:   "OpenSoha",
		Category:    "开发工具",
		Version:     "1.0.0",
		Artifacts:   []softwareArtifact{artifact},
	}}})
	runtimeAPI := &appRuntime{version: "0.1.0", software: library}

	response := httptest.NewRecorder()
	runtimeAPI.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/app/v1/software", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", response.Code)
	}
	if strings.Contains(response.Body.String(), artifact.URL) || strings.Contains(response.Body.String(), artifact.SHA256) {
		t.Fatalf("software response exposed private artifact metadata: %s", response.Body.String())
	}
	var result softwareListResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != 1 || result.Items[0].ID != "soha-tools" {
		t.Fatalf("unexpected catalog response: %#v", result)
	}
}

func TestSoftwareInstallDownloadsVerifiesAndOpensPackage(t *testing.T) {
	payload := []byte("verified software package")
	digest := sha256.Sum256(payload)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Length", "25")
		_, _ = writer.Write(payload)
	}))
	defer server.Close()

	opened := make(chan string, 1)
	fileName := installerFileName(runtime.GOOS)
	library := newSoftwareLibrary(testSoftwareCatalog{items: []softwareCatalogItem{{
		ID:        "verified-tool",
		Name:      "Verified Tool",
		Publisher: "OpenSoha",
		Version:   "1.0.0",
		Artifacts: []softwareArtifact{{
			Platform: runtime.GOOS,
			Arch:     runtime.GOARCH,
			URL:      server.URL + "/" + fileName,
			SHA256:   hex.EncodeToString(digest[:]),
			FileName: fileName,
			Size:     int64(len(payload)),
		}},
	}}})
	library.client = server.Client()
	library.downloadDir = t.TempDir()
	library.openFile = func(path string) error {
		opened <- path
		return nil
	}
	runtimeAPI := &appRuntime{version: "0.1.0", software: library}

	installResponse := httptest.NewRecorder()
	runtimeAPI.ServeHTTP(installResponse, httptest.NewRequest(http.MethodPost, "/app/v1/software/verified-tool/install", nil))
	if installResponse.Code != http.StatusAccepted {
		t.Fatalf("unexpected install status: %d: %s", installResponse.Code, installResponse.Body.String())
	}
	var started softwareTaskResponse
	if err := json.NewDecoder(installResponse.Body).Decode(&started); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		statusResponse := httptest.NewRecorder()
		runtimeAPI.ServeHTTP(statusResponse, httptest.NewRequest(http.MethodGet, "/app/v1/software/tasks/"+started.Task.ID, nil))
		if statusResponse.Code != http.StatusOK {
			t.Fatalf("unexpected task status: %d", statusResponse.Code)
		}
		var current softwareTaskResponse
		if err := json.NewDecoder(statusResponse.Body).Decode(&current); err != nil {
			t.Fatal(err)
		}
		if current.Task.State == softwareTaskCompleted {
			break
		}
		if current.Task.State == softwareTaskFailed {
			t.Fatalf("install failed: %#v", current.Task)
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for install task")
		}
		time.Sleep(10 * time.Millisecond)
	}

	select {
	case path := <-opened:
		if filepath.Base(path) != fileName {
			t.Fatalf("unexpected installer path: %s", path)
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(contents) != string(payload) {
			t.Fatalf("unexpected installer contents: %q", contents)
		}
	default:
		t.Fatal("system installer was not opened")
	}
}

func TestSoftwareCatalogRejectsInsecureDownloadURL(t *testing.T) {
	library := newSoftwareLibrary(testSoftwareCatalog{items: []softwareCatalogItem{{
		ID:        "unsafe-tool",
		Name:      "Unsafe Tool",
		Publisher: "Example",
		Version:   "1.0.0",
		Artifacts: []softwareArtifact{{
			Platform: runtime.GOOS,
			Arch:     runtime.GOARCH,
			URL:      "http://127.0.0.1/installer.pkg",
			SHA256:   strings.Repeat("0", 64),
			FileName: "installer.pkg",
			Size:     1024,
		}},
	}}})
	runtimeAPI := &appRuntime{version: "0.1.0", software: library}
	response := httptest.NewRecorder()
	runtimeAPI.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/app/v1/software", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected insecure software URL to be rejected, got %d", response.Code)
	}
}

func TestSoftwareCatalogRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(path, make([]byte, (2<<20)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (fileSoftwareCatalog{path: path}).List(context.Background(), ""); err == nil {
		t.Fatal("expected oversized software catalog to be rejected")
	}
}

func installerFileName(platform string) string {
	switch platform {
	case "windows":
		return "verified-tool.exe"
	case "darwin":
		return "verified-tool.pkg"
	default:
		return "verified-tool.AppImage"
	}
}
