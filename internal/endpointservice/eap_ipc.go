package endpointservice

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
)

func runAdmissionIPCAction(ctx context.Context, manager *Manager, request IPCRequest) (*AdmissionStatus, error) {
	if request.Connect != nil || request.Mihomo != nil {
		return nil, errors.New("EAP action has unrelated parameters")
	}
	admission := manager.options.Admission
	if admission == nil {
		status := &AdmissionStatus{Profiles: []AdmissionProfileStatus{}, Adapters: []EAPAdapter{}}
		if request.Action == "admission_status" && request.Admission == nil {
			return status, nil
		}
		return status, errors.New("EAP is unavailable in this service build")
	}
	var err error
	switch request.Action {
	case "admission_status":
		if request.Admission != nil {
			return nil, errors.New("EAP status has no parameters")
		}
	case "admission_prepare":
		if request.Admission == nil || !identifierPattern.MatchString(request.Admission.ProfileID) || request.Admission.AdapterID == "" || len(request.Admission.AdapterID) > 128 {
			return nil, errors.New("EAP selection is invalid")
		}
		err = admission.Prepare(ctx, *request.Admission)
	case "admission_check":
		if request.Admission != nil {
			return nil, errors.New("EAP readback has no parameters")
		}
		err = admission.Check(ctx)
	case "admission_connect", "admission_remove":
		if request.Admission == nil || !identifierPattern.MatchString(request.Admission.ProfileID) || request.Admission.AdapterID != "" {
			return nil, errors.New("EAP profile reference is invalid")
		}
		if request.Action == "admission_connect" {
			err = admission.Connect(ctx, request.Admission.ProfileID)
		} else {
			err = admission.Remove(ctx, request.Admission.ProfileID)
		}
	default:
		return nil, errors.New("EAP action is unsupported")
	}
	status, statusErr := admission.Status(ctx)
	return &status, errors.Join(err, statusErr)
}

func CallAdmissionIPC(ctx context.Context, action string, input *AdmissionInput) (AdmissionStatus, error) {
	connection, err := dialIPC(ctx)
	if err != nil {
		return AdmissionStatus{}, err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	requestID := randomID()
	raw, err := json.Marshal(IPCRequest{Version: IPCVersion, RequestID: requestID, Action: action, Admission: input})
	if err != nil {
		return AdmissionStatus{}, err
	}
	if err := writeIPCFrame(connection, raw); err != nil {
		return AdmissionStatus{}, err
	}
	raw, err = readIPCFrame(connection)
	if err != nil {
		return AdmissionStatus{}, err
	}
	var response IPCResponse
	if err := decodeStrict(raw, &response); err != nil || response.Version != IPCVersion || response.RequestID != requestID || !validIPCStatus(response.Status) || response.Mihomo != nil || response.Admission == nil || !validIPCAdmissionStatus(*response.Admission) {
		return AdmissionStatus{}, errors.New("EAP IPC response is invalid")
	}
	if !response.OK {
		if response.ErrorCode == "" || response.ErrorMessage == "" {
			return AdmissionStatus{}, errors.New("EAP IPC error response is invalid")
		}
		return *response.Admission, &IPCError{Code: response.ErrorCode, Message: response.ErrorMessage}
	}
	return *response.Admission, nil
}

func validIPCAdmissionStatus(status AdmissionStatus) bool {
	if len(status.Profiles) > 64 || len(status.Adapters) > 128 || len(status.Diagnostic) > 128 {
		return false
	}
	seen := map[string]bool{}
	for _, profile := range status.Profiles {
		if !identifierPattern.MatchString(profile.ID) || !identifierPattern.MatchString(profile.SiteID) || seen[profile.ID] || profile.AccessMedium != "wifi" && profile.AccessMedium != "wired" || len(profile.SSID) > 32 || len(profile.AdapterID) > 128 || !slicesContains([]string{"available", "installation_required", "activation_pending", "installed", "drift", "authorization_expired"}, profile.State) {
			return false
		}
		if profile.ArtifactPath != "" && (!filepath.IsAbs(profile.ArtifactPath) || len(profile.ArtifactPath) > 2048 || !strings.HasPrefix(filepath.Base(profile.ArtifactPath), "Soha-EAP-") || filepath.Ext(profile.ArtifactPath) != ".mobileconfig") {
			return false
		}
		seen[profile.ID] = true
	}
	seen = map[string]bool{}
	for _, adapter := range status.Adapters {
		if adapter.ID == "" || len(adapter.ID) > 128 || seen[adapter.ID] || adapter.Name == "" || len(adapter.Name) > 128 || len(adapter.MACAddress) > 32 || adapter.Medium != "wifi" && adapter.Medium != "wired" || adapter.EthernetPosition < 0 || adapter.EthernetPosition > 128 {
			return false
		}
		seen[adapter.ID] = true
	}
	return true
}
