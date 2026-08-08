package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAppRuntimeReportsInfoAndRejectsUnconfiguredUpdates(t *testing.T) {
	runtimeAPI := &appRuntime{version: "0.1.0"}

	infoResponse := httptest.NewRecorder()
	runtimeAPI.ServeHTTP(infoResponse, httptest.NewRequest(http.MethodGet, "/app/v1/info", nil))
	if infoResponse.Code != http.StatusOK {
		t.Fatalf("unexpected info status: %d", infoResponse.Code)
	}
	var info appInfo
	if err := json.NewDecoder(infoResponse.Body).Decode(&info); err != nil {
		t.Fatal(err)
	}
	if info.Name != "Soha" || info.Version != "0.1.0" || info.UpdateSupported {
		t.Fatalf("unexpected info: %#v", info)
	}

	updateResponse := httptest.NewRecorder()
	runtimeAPI.ServeHTTP(updateResponse, httptest.NewRequest(http.MethodPost, "/app/v1/updates/check", nil))
	if updateResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("unexpected update status: %d", updateResponse.Code)
	}
}
