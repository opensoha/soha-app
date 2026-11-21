package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMeshWorkspacePreviewOnlyReturnsSelectedMetadata(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sensitive-name.txt"), []byte("sensitive-body"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".hidden"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, "external")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	var scope nativeUIScope
	scope.Authenticated, scope.UserID, scope.Generation = true, "owner", 1
	h := &appHost{nativeScope: scope, meshWorkspaceDialog: func() (string, error) { return dir, nil }}
	req := httptest.NewRequest(http.MethodPost, "/app/v1/assistant-mesh/workspace-summary", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "wails://localhost")
	rec := httptest.NewRecorder()
	h.handleMeshWorkspaceSummary(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview: %d %s", rec.Code, rec.Body)
	}
	var payload struct {
		Data struct {
			meshWorkspaceSummary
			Status string
		}
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data.Status != "preview" || payload.Data.Files != 1 || payload.Data.Directories != 1 ||
		strings.Contains(rec.Body.String(), "sensitive") || strings.Contains(rec.Body.String(), dir) {
		t.Fatalf("unexpected summary %s", rec.Body)
	}
}

func TestMeshWorkspacePreviewCannotReadRequestPathOrSurviveOwnerChange(t *testing.T) {
	dir := t.TempDir()
	h := &appHost{nativeScope: nativeUIScope{Authenticated: true, UserID: "owner", Generation: 2}}
	picked := false
	h.meshWorkspaceDialog = func() (string, error) {
		picked = true
		h.sessionMu.Lock()
		h.invalidateNativeUIScopeLocked()
		h.sessionMu.Unlock()
		return dir, nil
	}
	send := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/app/v1/assistant-mesh/workspace-summary", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "wails://localhost")
		rec := httptest.NewRecorder()
		h.handleMeshWorkspaceSummary(rec, req)
		return rec
	}
	if rec := send(`{"path":"/"}`); rec.Code != http.StatusBadRequest || picked {
		t.Fatalf("request-controlled directory: %d, picked %v", rec.Code, picked)
	}
	if rec := send("{}"); rec.Code != http.StatusConflict || !picked || !strings.Contains(rec.Body.String(), "session_changed") {
		t.Fatalf("stale session received metadata: %d, %s", rec.Code, rec.Body)
	}
}
