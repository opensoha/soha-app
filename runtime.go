package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/updater"
	githubupdater "github.com/wailsapp/wails/v3/pkg/updater/providers/github"
)

var appVersion = "0.1.0"

type appInfo struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	Platform        string `json:"platform"`
	Arch            string `json:"arch"`
	UpdateSupported bool   `json:"updateSupported"`
	UpdateState     string `json:"updateState,omitempty"`
}

type appRuntime struct {
	version  string
	updater  *updater.Updater
	software *softwareLibrary
	checkMu  sync.Mutex
}

func (runtimeAPI *appRuntime) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	if runtimeAPI.software != nil && runtimeAPI.software.ServeHTTP(writer, request) {
		return
	}
	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/app/v1/info":
		info := appInfo{
			Name:            "Soha",
			Version:         runtimeAPI.version,
			Platform:        runtime.GOOS,
			Arch:            runtime.GOARCH,
			UpdateSupported: runtimeAPI.updater != nil,
		}
		if runtimeAPI.updater != nil {
			info.UpdateState = string(runtimeAPI.updater.State())
		}
		writeJSON(writer, http.StatusOK, info)
	case request.Method == http.MethodPost && request.URL.Path == "/app/v1/updates/check":
		if runtimeAPI.updater == nil {
			writeJSON(writer, http.StatusServiceUnavailable, map[string]string{
				"message": "当前构建未配置更新源",
			})
			return
		}
		if err := runtimeAPI.checkAndPrompt(request.Context()); err != nil {
			writeJSON(writer, http.StatusBadGateway, map[string]string{"message": err.Error()})
			return
		}
		writeJSON(writer, http.StatusOK, map[string]string{"message": "更新检查已完成"})
	default:
		writeJSON(writer, http.StatusNotFound, map[string]string{"message": "not found"})
	}
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func (runtimeAPI *appRuntime) checkAndPrompt(ctx context.Context) error {
	runtimeAPI.checkMu.Lock()
	defer runtimeAPI.checkMu.Unlock()
	return runtimeAPI.updater.CheckAndInstall(ctx)
}

func (runtimeAPI *appRuntime) startAutomaticChecks(ctx context.Context) {
	go func() {
		initial := time.NewTimer(30 * time.Second)
		defer initial.Stop()
		select {
		case <-ctx.Done():
			return
		case <-initial.C:
			runtimeAPI.checkSilently(ctx)
		}

		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runtimeAPI.checkSilently(ctx)
			}
		}
	}()
}

func (runtimeAPI *appRuntime) checkSilently(ctx context.Context) {
	runtimeAPI.checkMu.Lock()
	defer runtimeAPI.checkMu.Unlock()
	_, _ = runtimeAPI.updater.Check(ctx)
}

type checksumRequiredProvider struct {
	updater.Provider
}

func (provider checksumRequiredProvider) Check(ctx context.Context, request updater.CheckRequest) (*updater.Release, error) {
	release, err := provider.Provider.Check(ctx, request)
	if err != nil || release == nil {
		return release, err
	}
	if release.Verification == nil || len(release.Verification.Digest) == 0 {
		return nil, errors.New("update release is missing its required checksum")
	}
	return release, nil
}

func configureAppUpdater(ctx context.Context, runtimeAPI *appRuntime, target *updater.Updater) error {
	repository := strings.TrimSpace(os.Getenv("SOHA_APP_UPDATE_REPOSITORY"))
	if repository == "" {
		return nil
	}
	provider, err := githubupdater.New(githubupdater.Config{
		Repository:    repository,
		Token:         strings.TrimSpace(os.Getenv("SOHA_APP_UPDATE_TOKEN")),
		ChecksumAsset: "checksums.txt",
	})
	if err != nil {
		return fmt.Errorf("configure updater: %w", err)
	}
	if err := target.Init(updater.Config{
		CurrentVersion: runtimeAPI.version,
		Providers:      []updater.Provider{checksumRequiredProvider{Provider: provider}},
		Window: &updater.BuiltinWindow{Options: updater.WindowOptions{
			Title: "Soha 更新",
		}},
	}); err != nil {
		return fmt.Errorf("configure updater: %w", err)
	}
	runtimeAPI.updater = target
	runtimeAPI.startAutomaticChecks(ctx)
	return nil
}
