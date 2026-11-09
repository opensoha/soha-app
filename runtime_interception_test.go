package main

import (
	"context"
	"errors"
	"github.com/opensoha/soha-app/internal/endpointservice"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAppRuntimeInterceptionBridgeUsesTypedIntentAndRedactsErrors(t *testing.T) {
	calls := 0
	r := &appRuntime{networkInterceptionCall: func(ctx context.Context, intent *endpointservice.InterceptionIntent) (endpointservice.InterceptionStatus, error) {
		calls++
		if deadline, ok := ctx.Deadline(); !ok || deadline.After(time.Now().Add(30*time.Second)) {
			t.Fatal("unbounded native call")
		}
		if intent != nil && (intent.RequestID != "request-a" || intent.ExpectedGeneration != 3 || !intent.SystemProxy || intent.TUN) {
			t.Fatal("native intent changed")
		}
		return endpointservice.InterceptionStatus{Generation: 4, DesiredSystemProxy: true, State: "preparing", ObservedAt: time.Now()}, nil
	}}
	r.nativeScopeKnown = true
	r.nativeScope = endpointservice.NativeUIScope{ServerURL: "https://control.example.test", UserID: "principal-a", Epoch: "fixture-runtime-epoch", Generation: 1, Authenticated: true}
	r.networkUIScopeCall = func(context.Context, endpointservice.NativeUIScope) (endpointservice.InterceptionStatus, error) {
		return endpointservice.InterceptionStatus{State: "inactive", ObservedAt: time.Now()}, nil
	}
	for _, tc := range []struct{ method, body string }{{"GET", ""}, {"POST", `{"requestId":"request-a","expectedGeneration":3,"systemProxy":true,"tun":false}`}} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(tc.method, "/app/v1/network/proxy/interception", strings.NewReader(tc.body)))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"desiredSystemProxy":true`) {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/app/v1/network/proxy/interception", strings.NewReader(`{"requestId":"x","pid":42}`)))
	if w.Code != http.StatusBadRequest || calls != 2 {
		t.Fatal("renderer platform field accepted", w.Code, calls)
	}
	r.networkInterceptionCall = func(context.Context, *endpointservice.InterceptionIntent) (endpointservice.InterceptionStatus, error) {
		return endpointservice.InterceptionStatus{}, errors.New("private PAC credential baseline")
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/app/v1/network/proxy/interception", nil))
	if w.Code != http.StatusConflict || strings.Contains(w.Body.String(), "credential") {
		t.Fatal("native details leaked", w.Body.String())
	}
	r.networkDisabled = true
	r.networkInterceptionCall = func(context.Context, *endpointservice.InterceptionIntent) (endpointservice.InterceptionStatus, error) {
		t.Fatal("disabled instance called native service")
		return endpointservice.InterceptionStatus{}, nil
	}
	if _, err := r.GetLocalProxyInterception(); err == nil {
		t.Fatal("disabled host export succeeded")
	}
}

func TestAppRuntimeInterceptionScopeRejectsLateLocalUpdates(t *testing.T) {
	r := &appRuntime{networkDisabled: true}
	scope := endpointservice.NativeUIScope{ServerURL: "https://ui.example.test", UserID: "user-a", Epoch: "fixture-runtime-epoch-a", Generation: 2, Authenticated: true}
	if err := r.setNativeUIScope(context.Background(), scope); err != nil {
		t.Fatal(err)
	}
	old := scope
	old.Generation--
	if err := r.setNativeUIScope(context.Background(), old); err == nil || r.nativeScope != scope {
		t.Fatal("late generation changed root scope")
	}
	replacement := scope
	replacement.Epoch = "fixture-runtime-epoch-b"
	replacement.Generation = 1
	if err := r.setNativeUIScope(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	scope.Generation = 100
	if err := r.setNativeUIScope(context.Background(), scope); err == nil || r.nativeScope != replacement {
		t.Fatal("retired epoch changed root scope")
	}
}
func TestAppRuntimeInterceptionRequiresCurrentHostAndRechecksAfterSync(t *testing.T) {
	r := &appRuntime{networkInterceptionCall: func(context.Context, *endpointservice.InterceptionIntent) (endpointservice.InterceptionStatus, error) {
		t.Fatal("untrusted scope reached intent")
		return endpointservice.InterceptionStatus{}, nil
	}}
	intent := endpointservice.InterceptionIntent{RequestID: "enable", SystemProxy: true}
	if _, err := r.localInterception(context.Background(), &intent); err == nil {
		t.Fatal("missing host authorized")
	}
	r.nativeScopeKnown = true
	r.nativeScope = endpointservice.NativeUIScope{ServerURL: "https://ui.example.test", UserID: "user-a", Epoch: "fixture-runtime-epoch", Generation: 1, Authenticated: true}
	r.networkUIScopeCall = func(context.Context, endpointservice.NativeUIScope) (endpointservice.InterceptionStatus, error) {
		r.nativeScopeMu.Lock()
		r.nativeScope.Generation++
		r.nativeScope.Authenticated = false
		r.nativeScopeMu.Unlock()
		return endpointservice.InterceptionStatus{}, nil
	}
	if _, err := r.localInterception(context.Background(), &intent); err == nil {
		t.Fatal("scope changed during sync authorized")
	}
	calls := 0
	r.networkInterceptionCall = func(context.Context, *endpointservice.InterceptionIntent) (endpointservice.InterceptionStatus, error) {
		calls++
		return endpointservice.InterceptionStatus{}, nil
	}
	stop := endpointservice.InterceptionIntent{RequestID: "stop"}
	if _, err := r.localInterception(context.Background(), &stop); err != nil || calls != 1 {
		t.Fatal("logout prevented safe stop", err)
	}
}
