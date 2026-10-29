package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opensoha/soha-app/internal/endpointservice"
)

func TestAdmissionRuntimeUsesOnlyServiceArtifactAndRejectsRendererConfiguration(t *testing.T) {
	var calls int
	opened := ""
	status := endpointservice.AdmissionStatus{Supported: true, Profiles: []endpointservice.AdmissionProfileStatus{{ID: "profile-1", SiteID: "site-1", AccessMedium: "wifi", State: "installation_required", ArtifactPath: "/Users/example/Soha-EAP-owned.mobileconfig"}}}
	api := &appRuntime{networkAdmissionCall: func(_ context.Context, action string, input *endpointservice.AdmissionInput) (endpointservice.AdmissionStatus, error) {
		calls++
		if action != "admission_status" || input != nil {
			t.Fatal("open forwarded renderer parameters to the service")
		}
		return status, nil
	}, openAdmissionProfile: func(_ context.Context, path string) error { opened = path; return nil }}
	for _, body := range []string{`{"profileId":"profile-1","path":"/etc/hosts"}`, `{"profileId":"profile-1","caCertificates":["untrusted"]}`, `{"profileId":"profile-1","adapterId":"arbitrary"}`} {
		response := httptest.NewRecorder()
		api.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/app/v1/network/admission/open", strings.NewReader(body)))
		if response.Code != http.StatusBadRequest || calls != 0 || opened != "" {
			t.Fatalf("renderer input reached the system: %d %q", response.Code, opened)
		}
	}
	response := httptest.NewRecorder()
	api.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/app/v1/network/admission/open", strings.NewReader(`{"profileId":"profile-1"}`)))
	if response.Code != http.StatusOK || opened != status.Profiles[0].ArtifactPath {
		t.Fatalf("handoff = %d, %q", response.Code, opened)
	}
	opened = ""
	status.Profiles[0].State = "authorization_expired"
	response = httptest.NewRecorder()
	api.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/app/v1/network/admission/open", strings.NewReader(`{"profileId":"profile-1"}`)))
	if response.Code != http.StatusConflict || opened != "" {
		t.Fatal("expired profile was opened for installation")
	}
}
