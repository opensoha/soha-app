package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const personalArchiveMaxBytes int64 = 256 << 20

func supportsNativePersonalExport(platform string) bool {
	return platform == "darwin" || platform == "linux" || platform == "windows"
}

// The ordinary authenticated reverse proxy writes to a private, unlinked file.
// A native save dialog is shown only after its entire receipt is verified.
type stagedPersonalArchive struct {
	header http.Header
	status int
	file   *os.File
	digest hash.Hash
	size   int64
}

func (s *stagedPersonalArchive) Header() http.Header { return s.header }
func (s *stagedPersonalArchive) WriteHeader(status int) {
	if s.status == 0 {
		s.status = status
	}
}
func (s *stagedPersonalArchive) Write(data []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	if s.size+int64(len(data)) > personalArchiveMaxBytes {
		return 0, errors.New("personal archive exceeds its bound")
	}
	n, err := io.MultiWriter(s.file, s.digest).Write(data)
	s.size += int64(n)
	return n, err
}

func (h *appHost) handlePersonalDataExport(writer http.ResponseWriter, request *http.Request) {
	if !validateHostMutation(writer, request) {
		return
	}
	if !supportsNativePersonalExport(h.appInfo.Platform) {
		writeError(writer, http.StatusNotImplemented, "export_unsupported", "Personal data export is unavailable on this device; use the desktop app or Web")
		return
	}
	var input struct {
		AssistantID        string `json:"assistantId"`
		EnvironmentVersion int64  `json:"environmentVersion"`
	}
	if decodeRequestJSON(request, &input) != nil || input.AssistantID == "" || len(input.AssistantID) > 128 || input.EnvironmentVersion < 1 {
		writeError(writer, http.StatusBadRequest, "invalid_export", "Invalid personal data export selection")
		return
	}
	h.nativeMu.RLock()
	prompt := h.personalArchiveDialog
	h.nativeMu.RUnlock()
	if prompt == nil {
		writeError(writer, http.StatusServiceUnavailable, "native_action_unavailable", "Native save dialog is unavailable")
		return
	}
	file, err := privatePersonalExportFile()
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "export_unavailable", "Unable to stage personal data export")
		return
	}
	defer func() { _ = file.Close(); _ = os.Remove(file.Name()) }()
	target := h.target.Load()
	payload, _ := json.Marshal(input)
	transferCtx, cancel := context.WithTimeout(request.Context(), 45*time.Second)
	defer cancel()
	upstream := request.Clone(transferCtx)
	upstream.URL.Path = apiPrefix + "/copilot/assistant/environment/export"
	upstream.URL.RawQuery = ""
	upstream.Body = io.NopCloser(strings.NewReader(string(payload)))
	upstream.ContentLength = int64(len(payload))
	upstream.Header.Set("Content-Type", "application/json")
	upstream.Header.Set("Accept-Encoding", "identity")
	stage := &stagedPersonalArchive{header: make(http.Header), file: file, digest: sha256.New()}
	h.handleAPI(stage, upstream)
	cancel()
	if stage.status != http.StatusOK {
		status := stage.status
		if status < 400 || status > 599 {
			status = http.StatusBadGateway
		}
		writeError(writer, status, "export_unavailable", "Personal data export was not completed")
		return
	}
	size, err := strconv.ParseInt(stage.header.Get("Content-Length"), 10, 64)
	if err != nil || size != stage.size || size < 1 || stage.header.Get("X-Assistant-ID") != input.AssistantID || stage.header.Get("X-Content-SHA256") != hex.EncodeToString(stage.digest.Sum(nil)) || request.Context().Err() != nil || target != h.target.Load() || h.credentialsBlocked.Load() || h.hasPendingSwitch() {
		writeError(writer, http.StatusBadGateway, "export_unverified", "Personal data export integrity or session changed")
		return
	}
	path, err := prompt()
	if err != nil || request.Context().Err() != nil || target != h.target.Load() || h.credentialsBlocked.Load() || h.hasPendingSwitch() {
		writeError(writer, http.StatusServiceUnavailable, "export_canceled", "Personal data export was not saved")
		return
	}
	if path == "" {
		writeData(writer, http.StatusOK, map[string]string{"status": "canceled"})
		return
	}
	if !filepath.IsAbs(path) || savePersonalArchive(request.Context(), file, path) != nil {
		writeError(writer, http.StatusServiceUnavailable, "export_save_failed", "Unable to save archive; choose a new file name")
		return
	}
	writeData(writer, http.StatusOK, map[string]string{"status": "saved"})
}

func savePersonalArchive(ctx context.Context, source *os.File, path string) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return err
	}
	// Do not replace a pre-existing file or symlink selected in the dialog.
	target, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	original, err := target.Stat()
	if err != nil {
		_ = target.Close()
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, target.Close())
		if resultErr != nil {
			if actual, err := os.Lstat(path); err == nil && original != nil && os.SameFile(original, actual) {
				_ = os.Remove(path)
			}
		}
	}()
	_, err = io.Copy(target, source)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	actual, err := os.Lstat(path)
	if err != nil || !os.SameFile(original, actual) {
		return errors.New("personal export destination changed")
	}
	return target.Sync()
}
