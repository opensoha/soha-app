package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const maxSoftwarePackageSize int64 = 4 << 30

type softwareArtifact struct {
	Platform      string `json:"platform"`
	Arch          string `json:"arch"`
	URL           string `json:"url"`
	SHA256        string `json:"sha256"`
	FileName      string `json:"fileName"`
	Size          int64  `json:"size"`
	Authorization string `json:"-"`
	TrustedSource bool   `json:"-"`
}

type softwareCatalogItem struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description,omitempty"`
	Publisher   string             `json:"publisher"`
	Category    string             `json:"category,omitempty"`
	Version     string             `json:"version"`
	Artifacts   []softwareArtifact `json:"artifacts"`
}

type softwareCatalog interface {
	List(context.Context, string) ([]softwareCatalogItem, error)
}

type fileSoftwareCatalog struct {
	path string
}

func (catalog fileSoftwareCatalog) List(ctx context.Context, _ string) ([]softwareCatalogItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if catalog.path == "" {
		return []softwareCatalogItem{}, nil
	}
	file, err := os.Open(catalog.path)
	if err != nil {
		return nil, fmt.Errorf("open catalog: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat catalog: %w", err)
	}
	if info.Size() > 2<<20 {
		return nil, errors.New("catalog exceeds 2 MiB")
	}

	var document struct {
		Items []softwareCatalogItem `json:"items"`
	}
	decoder := json.NewDecoder(io.LimitReader(file, 2<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode catalog: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("decode catalog: trailing content")
	}
	return document.Items, nil
}

type serverSoftwareCatalog struct {
	baseURL *url.URL
	client  *http.Client
}

type serverSoftwarePackage struct {
	ID          string `json:"id"`
	SoftwareID  string `json:"softwareId"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Publisher   string `json:"publisher"`
	Category    string `json:"category"`
	Version     string `json:"version"`
	Platform    string `json:"platform"`
	Arch        string `json:"arch"`
	FileName    string `json:"fileName"`
	SizeBytes   int64  `json:"sizeBytes"`
	SHA256      string `json:"sha256"`
}

func newServerSoftwareCatalog(rawServerURL string) (*serverSoftwareCatalog, error) {
	baseURL, err := parseServerURL(rawServerURL)
	if err != nil {
		return nil, err
	}
	return &serverSoftwareCatalog{
		baseURL: baseURL,
		client: &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: safeSoftwareRedirect,
		},
	}, nil
}

func (catalog *serverSoftwareCatalog) List(ctx context.Context, authorization string) ([]softwareCatalogItem, error) {
	endpoint := catalog.resolve("/api/v1/software/packages")
	query := endpoint.Query()
	query.Set("platform", runtime.GOOS)
	query.Set("arch", runtime.GOARCH)
	query.Set("limit", "200")
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response, err := catalog.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("load server software catalog: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("load server software catalog: unexpected status %d", response.StatusCode)
	}
	var document struct {
		Items []serverSoftwarePackage `json:"items"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&document); err != nil {
		return nil, fmt.Errorf("decode server software catalog: %w", err)
	}
	items := make([]softwareCatalogItem, 0, len(document.Items))
	for _, item := range document.Items {
		items = append(items, softwareCatalogItem{
			ID: item.ID, Name: item.Name, Description: item.Description, Publisher: item.Publisher,
			Category: item.Category, Version: item.Version,
			Artifacts: []softwareArtifact{{
				Platform: item.Platform, Arch: item.Arch,
				URL:    catalog.resolve("/api/v1/software/packages/" + url.PathEscape(item.ID) + "/download").String(),
				SHA256: item.SHA256, FileName: item.FileName, Size: item.SizeBytes,
				Authorization: authorization, TrustedSource: true,
			}},
		})
	}
	return items, nil
}

func (catalog *serverSoftwareCatalog) resolve(path string) *url.URL {
	target := *catalog.baseURL
	target.Path = strings.TrimRight(target.Path, "/") + path
	target.RawPath = ""
	target.RawQuery = ""
	return &target
}

type softwarePackage struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Publisher   string `json:"publisher"`
	Category    string `json:"category,omitempty"`
	Version     string `json:"version"`
	Size        int64  `json:"size"`
}

type softwareListResponse struct {
	Items []softwarePackage `json:"items"`
}

type softwareTaskState string

const (
	softwareTaskQueued      softwareTaskState = "queued"
	softwareTaskDownloading softwareTaskState = "downloading"
	softwareTaskVerifying   softwareTaskState = "verifying"
	softwareTaskOpening     softwareTaskState = "opening"
	softwareTaskCompleted   softwareTaskState = "completed"
	softwareTaskFailed      softwareTaskState = "failed"
)

type softwareInstallTask struct {
	ID         string            `json:"id"`
	SoftwareID string            `json:"softwareId"`
	Name       string            `json:"name"`
	State      softwareTaskState `json:"state"`
	Progress   int               `json:"progress"`
	Message    string            `json:"message"`
}

type softwareTaskResponse struct {
	Task softwareInstallTask `json:"task"`
}

type softwareLibrary struct {
	catalog     softwareCatalog
	client      *http.Client
	downloadDir string
	openFile    func(string) error
	installMu   sync.Mutex
	tasksMu     sync.RWMutex
	tasks       map[string]softwareInstallTask
}

var errSoftwareInstallBusy = errors.New("another software install is already running")

func newSoftwareLibrary(catalog softwareCatalog) *softwareLibrary {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	return &softwareLibrary{
		catalog: catalog,
		client: &http.Client{
			Timeout:       30 * time.Minute,
			CheckRedirect: safeSoftwareRedirect,
		},
		downloadDir: filepath.Join(cacheDir, "Soha", "downloads"),
		tasks:       make(map[string]softwareInstallTask),
	}
}

func (library *softwareLibrary) ServeHTTP(writer http.ResponseWriter, request *http.Request) bool {
	switch {
	case request.URL.Path == "/app/v1/software":
		if request.Method != http.MethodGet {
			writeSoftwareError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "请求方法不受支持")
			return true
		}
		library.list(writer, request)
		return true
	case strings.HasPrefix(request.URL.Path, "/app/v1/software/tasks/"):
		if request.Method != http.MethodGet {
			writeSoftwareError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "请求方法不受支持")
			return true
		}
		library.getTask(writer, strings.TrimPrefix(request.URL.Path, "/app/v1/software/tasks/"))
		return true
	case strings.HasPrefix(request.URL.Path, "/app/v1/software/") && strings.HasSuffix(request.URL.Path, "/install"):
		if request.Method != http.MethodPost {
			writeSoftwareError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "请求方法不受支持")
			return true
		}
		id := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/app/v1/software/"), "/install")
		library.install(writer, request, id)
		return true
	default:
		return false
	}
}

func (library *softwareLibrary) list(writer http.ResponseWriter, request *http.Request) {
	items, err := library.loadCatalog(request.Context(), request.Header.Get("Authorization"))
	if err != nil {
		log.Printf("Soha software catalog is unavailable: %v", err)
		writeSoftwareError(writer, http.StatusServiceUnavailable, "catalog_unavailable", "软件目录暂不可用")
		return
	}
	packages := make([]softwarePackage, 0, len(items))
	for _, item := range items {
		artifact, ok := matchingArtifact(item, runtime.GOOS, runtime.GOARCH)
		if !ok {
			continue
		}
		packages = append(packages, softwarePackage{
			ID:          item.ID,
			Name:        item.Name,
			Description: item.Description,
			Publisher:   item.Publisher,
			Category:    item.Category,
			Version:     item.Version,
			Size:        artifact.Size,
		})
	}
	writeJSON(writer, http.StatusOK, softwareListResponse{Items: packages})
}

func (library *softwareLibrary) install(writer http.ResponseWriter, request *http.Request, id string) {
	items, err := library.loadCatalog(request.Context(), request.Header.Get("Authorization"))
	if err != nil {
		writeSoftwareError(writer, http.StatusServiceUnavailable, "catalog_unavailable", "软件目录暂不可用")
		return
	}
	item, artifact, ok := findSoftware(items, id, runtime.GOOS, runtime.GOARCH)
	if !ok {
		writeSoftwareError(writer, http.StatusNotFound, "software_not_found", "未找到适用于当前设备的软件")
		return
	}
	if !library.installMu.TryLock() {
		writeSoftwareError(writer, http.StatusConflict, "install_busy", "已有软件正在下载，请稍后再试")
		return
	}
	task := softwareInstallTask{
		ID:         newTaskID(),
		SoftwareID: item.ID,
		Name:       item.Name,
		State:      softwareTaskQueued,
		Message:    "等待下载",
	}
	library.setTask(task)
	go func() {
		defer library.installMu.Unlock()
		library.runInstall(task.ID, item, artifact)
	}()
	writeJSON(writer, http.StatusAccepted, softwareTaskResponse{Task: task})
}

func (library *softwareLibrary) loadCatalog(ctx context.Context, authorization string) ([]softwareCatalogItem, error) {
	items, err := library.catalog.List(ctx, authorization)
	if err != nil {
		return nil, err
	}
	if err := validateSoftwareCatalog(items); err != nil {
		return nil, err
	}
	return items, nil
}

func (library *softwareLibrary) getTask(writer http.ResponseWriter, id string) {
	library.tasksMu.RLock()
	task, ok := library.tasks[id]
	library.tasksMu.RUnlock()
	if !ok {
		writeSoftwareError(writer, http.StatusNotFound, "task_not_found", "安装任务不存在")
		return
	}
	writeJSON(writer, http.StatusOK, softwareTaskResponse{Task: task})
}

func (library *softwareLibrary) runInstall(taskID string, item softwareCatalogItem, artifact softwareArtifact) {
	library.updateTask(taskID, softwareTaskDownloading, 0, "正在下载安装包")
	path, err := library.download(taskID, item, artifact)
	if err != nil {
		log.Printf("Soha software download failed for %s: %v", item.ID, err)
		library.updateTask(taskID, softwareTaskFailed, 0, "安装包下载或校验失败")
		return
	}
	library.updateTask(taskID, softwareTaskOpening, 100, "正在打开系统安装器")
	if library.openFile == nil || library.openFile(path) != nil {
		library.updateTask(taskID, softwareTaskFailed, 100, "无法打开系统安装器")
		return
	}
	library.updateTask(taskID, softwareTaskCompleted, 100, "安装器已打开")
}

func (library *softwareLibrary) download(taskID string, item softwareCatalogItem, artifact softwareArtifact) (string, error) {
	if err := os.MkdirAll(library.downloadDir, 0o700); err != nil {
		return "", err
	}
	directory, err := os.MkdirTemp(library.downloadDir, item.ID+"-")
	if err != nil {
		return "", err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(directory)
		}
	}()

	partialPath := filepath.Join(directory, artifact.FileName+".part")
	file, err := os.OpenFile(partialPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, artifact.URL, nil)
	if err != nil {
		_ = file.Close()
		return "", err
	}
	if artifact.Authorization != "" {
		request.Header.Set("Authorization", artifact.Authorization)
	}
	response, err := library.client.Do(request)
	if err != nil {
		_ = file.Close()
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_ = file.Close()
		return "", fmt.Errorf("unexpected download status %d", response.StatusCode)
	}

	writer := &softwareDownloadWriter{
		writer: io.MultiWriter(file, hash),
		total:  artifact.Size,
		onProgress: func(percent int) {
			library.updateTask(taskID, softwareTaskDownloading, percent, "正在下载安装包")
		},
	}
	written, copyErr := io.Copy(writer, io.LimitReader(response.Body, artifact.Size+1))
	closeErr := file.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if written != artifact.Size {
		return "", fmt.Errorf("downloaded size %d does not match expected size %d", written, artifact.Size)
	}
	library.updateTask(taskID, softwareTaskVerifying, 100, "正在校验安装包")
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), artifact.SHA256) {
		return "", errors.New("software package checksum mismatch")
	}

	finalPath := filepath.Join(directory, artifact.FileName)
	if err := os.Rename(partialPath, finalPath); err != nil {
		return "", err
	}
	// ponytail: completed installers remain cached; add age-based cleanup once retention is defined.
	keep = true
	return finalPath, nil
}

type softwareDownloadWriter struct {
	writer     io.Writer
	total      int64
	written    int64
	percent    int
	onProgress func(int)
}

func (writer *softwareDownloadWriter) Write(data []byte) (int, error) {
	written, err := writer.writer.Write(data)
	writer.written += int64(written)
	percent := int(writer.written * 100 / writer.total)
	if percent > 100 {
		percent = 100
	}
	if percent != writer.percent {
		writer.percent = percent
		writer.onProgress(percent)
	}
	return written, err
}

func (library *softwareLibrary) setTask(task softwareInstallTask) {
	library.tasksMu.Lock()
	library.tasks[task.ID] = task
	library.tasksMu.Unlock()
}

func (library *softwareLibrary) updateTask(id string, state softwareTaskState, progress int, message string) {
	library.tasksMu.Lock()
	task := library.tasks[id]
	task.State = state
	task.Progress = progress
	task.Message = message
	library.tasks[id] = task
	library.tasksMu.Unlock()
}

func matchingArtifact(item softwareCatalogItem, platform, arch string) (softwareArtifact, bool) {
	for _, artifact := range item.Artifacts {
		if artifact.Platform == platform && artifact.Arch == arch {
			return artifact, true
		}
	}
	return softwareArtifact{}, false
}

func findSoftware(items []softwareCatalogItem, id, platform, arch string) (softwareCatalogItem, softwareArtifact, bool) {
	for _, item := range items {
		if item.ID != id {
			continue
		}
		artifact, ok := matchingArtifact(item, platform, arch)
		return item, artifact, ok
	}
	return softwareCatalogItem{}, softwareArtifact{}, false
}

func validateSoftwareCatalog(items []softwareCatalogItem) error {
	ids := make(map[string]struct{}, len(items))
	for _, item := range items {
		if !validSoftwareID(item.ID) || item.Name == "" || len(item.Name) > 100 || len(item.Description) > 500 || item.Publisher == "" || len(item.Publisher) > 100 || len(item.Category) > 50 || item.Version == "" || len(item.Version) > 64 || len(item.Artifacts) == 0 {
			return fmt.Errorf("invalid software catalog item %q", item.ID)
		}
		if _, exists := ids[item.ID]; exists {
			return fmt.Errorf("duplicate software id %q", item.ID)
		}
		ids[item.ID] = struct{}{}
		targets := make(map[string]struct{}, len(item.Artifacts))
		for _, artifact := range item.Artifacts {
			if err := validateSoftwareArtifact(artifact); err != nil {
				return fmt.Errorf("invalid artifact for %s: %w", item.ID, err)
			}
			target := artifact.Platform + "/" + artifact.Arch
			if _, exists := targets[target]; exists {
				return fmt.Errorf("duplicate artifact target %s for %s", target, item.ID)
			}
			targets[target] = struct{}{}
		}
	}
	return nil
}

func validateSoftwareArtifact(artifact softwareArtifact) error {
	if !validSoftwareID(artifact.Platform) || !validSoftwareID(artifact.Arch) || artifact.Size <= 0 || artifact.Size > maxSoftwarePackageSize {
		return errors.New("invalid target or size")
	}
	if artifact.FileName == "" || len(artifact.FileName) > 255 || artifact.FileName == "." || filepath.Base(artifact.FileName) != artifact.FileName || strings.Contains(artifact.FileName, "\\") {
		return errors.New("invalid file name")
	}
	digest, err := hex.DecodeString(artifact.SHA256)
	if err != nil || len(digest) != sha256.Size {
		return errors.New("invalid SHA-256 checksum")
	}
	if len(artifact.URL) > 2048 {
		return errors.New("download URL is too long")
	}
	parsed, err := url.Parse(artifact.URL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Scheme != "https" && !(artifact.TrustedSource && parsed.Scheme == "http") {
		return errors.New("download URL must be HTTPS without credentials or fragment")
	}
	return nil
}

func validSoftwareID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for index, character := range id {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func safeSoftwareRedirect(request *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	original := via[0].URL
	if !strings.EqualFold(request.URL.Scheme, original.Scheme) || !strings.EqualFold(request.URL.Host, original.Host) {
		return errors.New("software download redirect changed origin")
	}
	return nil
}

func newTaskID() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return fmt.Sprintf("task-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(value)
}

func writeSoftwareError(writer http.ResponseWriter, status int, code, message string) {
	writeJSON(writer, status, map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}
