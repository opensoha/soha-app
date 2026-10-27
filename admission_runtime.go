package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/opensoha/soha-app/internal/endpointservice"
)

func (runtimeAPI *appRuntime) handleAdmission(writer http.ResponseWriter, request *http.Request, action string) {
	if runtimeAPI.networkAdmissionCall == nil {
		writeError(writer, http.StatusServiceUnavailable, "network_service_unavailable", "Soha 网络服务不可用")
		return
	}
	var input *endpointservice.AdmissionInput
	if action != "admission_status" && action != "admission_check" {
		input = &endpointservice.AdmissionInput{}
		if err := decodeRequestJSON(request, input); err != nil || input.ProfileID == "" || len(input.ProfileID) > 128 || action != "admission_prepare" && input.AdapterID != "" {
			writeError(writer, http.StatusBadRequest, "invalid_admission_request", "准入配置选择无效")
			return
		}
	}
	ctx, cancel := context.WithTimeout(request.Context(), 120*time.Second)
	defer cancel()
	serviceAction, serviceInput := action, input
	if action == "admission_open" {
		serviceAction, serviceInput = "admission_status", nil
	}
	status, err := runtimeAPI.networkAdmissionCall(ctx, serviceAction, serviceInput)
	if err == nil && action == "admission_open" {
		path := ""
		for _, profile := range status.Profiles {
			if profile.ID == input.ProfileID && profile.State == "installation_required" {
				path = profile.ArtifactPath
			}
		}
		if runtimeAPI.openAdmissionProfile == nil || path == "" {
			err = errors.New("EAP profile has no pending installation")
		} else {
			err = runtimeAPI.openAdmissionProfile(ctx, path)
		}
	}
	if err != nil {
		appLog.Warn("endpoint admission request failed", "component", "network", "event", "app.network.admission.failed", "action", action, "error_type", logErrorType(err))
		writeError(writer, http.StatusConflict, "admission_operation_failed", "准入操作未完成，请检查配置安装、证书有效期和 Soha 网络服务")
		return
	}
	writeRuntimeJSON(writer, http.StatusOK, status)
}

func openNativeAdmissionProfile(ctx context.Context, path string) error {
	if runtime.GOOS != "darwin" || !filepath.IsAbs(path) || !strings.HasPrefix(filepath.Base(path), "Soha-EAP-") || filepath.Ext(path) != ".mobileconfig" {
		return errors.New("EAP installation handoff is unavailable")
	}
	entry, err := os.Lstat(path)
	if err != nil || !entry.Mode().IsRegular() {
		return errors.New("EAP installation profile is unavailable")
	}
	return exec.CommandContext(ctx, "/usr/bin/open", path).Run()
}
