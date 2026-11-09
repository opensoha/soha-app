package main

import (
	"context"
	"errors"
	"github.com/opensoha/soha-app/internal/endpointservice"
	api "github.com/opensoha/soha-contracts/gen/go/sohaapi"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAppRuntimeProxyTypedBridgeAndFailureRedaction(t *testing.T) {
	var got string
	runtimeAPI := &appRuntime{networkProxyCall: func(ctx context.Context, action string, input *endpointservice.ProxyAction, rules *api.NetworkProxyRulesInput) (endpointservice.ProxyWorkbench, error) {
		got = action
		if deadline, ok := ctx.Deadline(); !ok || deadline.After(time.Now().Add(30*time.Second)) {
			t.Fatal("native proxy call is unbounded")
		}
		if action == "proxy_action" && (input == nil || input.Kind != "stop") {
			t.Fatal("typed proxy action lost")
		}
		if action == "proxy_rules" && (rules == nil || rules.ExpectedPersonalRevision != 2) {
			t.Fatal("CAS revisions lost")
		}
		return endpointservice.ProxyWorkbench{Engine: "mihomo", State: "stopped"}, nil
	}}
	for _, tc := range []struct{ method, path, body, action string }{{"GET", "/app/v1/network/proxy", "", "proxy_status"}, {"POST", "/app/v1/network/proxy/actions", `{"kind":"stop"}`, "proxy_action"}, {"PUT", "/app/v1/network/proxy/rules", `{"expectedOrgRevision":1,"expectedPersonalRevision":2,"rules":[]}`, "proxy_rules"}} {
		response := httptest.NewRecorder()
		runtimeAPI.ServeHTTP(response, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
		if response.Code != http.StatusOK || got != tc.action || !strings.Contains(response.Body.String(), `"engine":"mihomo"`) {
			t.Fatalf("bridge %s: %d %s", tc.action, response.Code, response.Body.String())
		}
	}
	response := httptest.NewRecorder()
	runtimeAPI.ServeHTTP(response, httptest.NewRequest("POST", "/app/v1/network/proxy/actions", strings.NewReader(`{"kind":"stop","sourceUrl":"https://upstream-secret"}`)))
	if response.Code != http.StatusBadRequest {
		t.Fatal("unknown privileged proxy input accepted")
	}
	runtimeAPI.networkProxyCall = func(context.Context, string, *endpointservice.ProxyAction, *api.NetworkProxyRulesInput) (endpointservice.ProxyWorkbench, error) {
		return endpointservice.ProxyWorkbench{}, errors.New("upstream-secret credential content")
	}
	response = httptest.NewRecorder()
	runtimeAPI.ServeHTTP(response, httptest.NewRequest("GET", "/app/v1/network/proxy", nil))
	if response.Code != http.StatusConflict || strings.Contains(response.Body.String(), "upstream-secret") {
		t.Fatal("proxy error leaked service details")
	}
	runtimeAPI.networkDisabled = true
	runtimeAPI.networkProxyCall = func(context.Context, string, *endpointservice.ProxyAction, *api.NetworkProxyRulesInput) (endpointservice.ProxyWorkbench, error) {
		t.Fatal("disabled instance touched network service")
		return endpointservice.ProxyWorkbench{}, nil
	}
	if _, err := runtimeAPI.ProxyStatus(context.Background()); err == nil {
		t.Fatal("native method ignored disabled instance")
	}
	if _, err := runtimeAPI.ProxyAction(context.Background(), endpointservice.ProxyAction{Kind: "start"}); err == nil {
		t.Fatal("native action ignored disabled instance")
	}
	if _, err := runtimeAPI.ProxyRules(context.Background(), api.NetworkProxyRulesInput{}); err == nil {
		t.Fatal("native rules ignored disabled instance")
	}
}
