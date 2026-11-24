package main

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const maxWorkspaceEntries = 256

type meshWorkspaceSummary struct {
	Files       int  `json:"files"`
	Directories int  `json:"directories"`
	Truncated   bool `json:"truncated"`
}

func summarizeMeshWorkspace(path string) (meshWorkspaceSummary, error) {
	if !filepath.IsAbs(path) {
		return meshWorkspaceSummary{}, errors.New("workspace path is not absolute")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return meshWorkspaceSummary{}, err
	}
	defer func() { _ = root.Close() }()
	dir, err := root.Open(".")
	if err != nil {
		return meshWorkspaceSummary{}, err
	}
	defer func() { _ = dir.Close() }()
	entries, err := dir.ReadDir(maxWorkspaceEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return meshWorkspaceSummary{}, err
	}
	summary := meshWorkspaceSummary{Truncated: len(entries) > maxWorkspaceEntries}
	if summary.Truncated {
		entries = entries[:maxWorkspaceEntries]
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		if entry.IsDir() {
			summary.Directories++
		} else if entry.Type().IsRegular() {
			summary.Files++
		}
	}
	return summary, nil
}

func (h *appHost) handleMeshWorkspaceSummary(w http.ResponseWriter, r *http.Request) {
	if !validateHostMutation(w, r) {
		return
	}
	scope := h.nativeUIScopeSnapshot()
	if !scope.Authenticated {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Sign in before choosing a workspace")
		return
	}
	if err := decodeRequestJSON(r, &struct{}{}); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Choose the directory in the native picker")
		return
	}
	if h.meshWorkspaceDialog == nil {
		writeError(w, http.StatusServiceUnavailable, "picker_unavailable", "Directory selection is unavailable")
		return
	}
	path, err := h.meshWorkspaceDialog()
	if err != nil {
		writeError(w, http.StatusConflict, "picker_failed", "Directory selection did not complete")
		return
	}
	if path == "" {
		writeData(w, http.StatusOK, map[string]string{"status": "canceled"})
		return
	}
	summary, err := summarizeMeshWorkspace(path)
	if err != nil {
		writeError(w, http.StatusConflict, "workspace_unavailable", "The selected directory could not be read")
		return
	}
	if h.nativeUIScopeSnapshot() != scope {
		writeError(w, http.StatusConflict, "session_changed", "The signed-in App account has changed")
		return
	}
	writeData(w, http.StatusOK, struct {
		Status string `json:"status"`
		meshWorkspaceSummary
	}{Status: "preview", meshWorkspaceSummary: summary})
}

func (h *appHost) handleMeshOpenInbox(w http.ResponseWriter, r *http.Request) {
	if !validateHostMutation(w, r) {
		return
	}
	if !h.nativeUIScopeSnapshot().Authenticated {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Sign in before opening the inbox")
		return
	}
	if h.meshOpenInbox == nil {
		writeError(w, http.StatusServiceUnavailable, "main_window_unavailable", "Main window is unavailable")
		return
	}
	h.meshOpenInbox()
	writeData(w, http.StatusOK, map[string]string{"status": "opened"})
}
