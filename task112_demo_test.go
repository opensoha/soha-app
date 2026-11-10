//go:build task112_demo

package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

type task112Transport func(*http.Request) (*http.Response, error)

func (f task112Transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTask112DemoIsolation(t *testing.T) {
	t.Setenv("SOHA_APP_PROFILE", "task112-demo")
	t.Setenv("SOHA_APP_NATIVE_NETWORK", "disabled")
	t.Setenv("SOHA_SERVER_URL", task112DemoServer)
	t.Setenv("SOHA_TASK112_DEMO_KEY", "123456789012345678901234")
	if err := validateTask112Demo(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"SOHA_APP_PROFILE", "SOHA_APP_NATIVE_NETWORK", "SOHA_SERVER_URL", "SOHA_TASK112_DEMO_KEY"} {
		old := os.Getenv(name)
		t.Setenv(name, "invalid")
		if validateTask112Demo() == nil {
			t.Errorf("accepted invalid %s", name)
		}
		t.Setenv(name, old)
	}
	called := false
	handler := wrapTask112Demo(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })).(*task112DemoHandler)
	handler.proxy.Transport = task112Transport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != task112DemoServer+"/app/v1/network/status?x=1" {
			t.Errorf("target: %s", r.URL)
		}
		if r.Header.Get("X-Soha-Demo-Key") != "123456789012345678901234" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Origin") != "" || r.Header.Get("X-Other") != "" {
			t.Errorf("unexpected headers: %v", r.Header)
		}
		return nil, errors.New("simulator unavailable")
	})
	req := httptest.NewRequest(http.MethodPost, "http://untrusted/app/v1/network/status?x=1", strings.NewReader("{}"))
	req.Header.Set("Authorization", "secret")
	req.Header.Set("Cookie", "secret")
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("X-Other", "secret")
	req.Header.Set("Content-Type", "application/json")
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	if called || out.Code != http.StatusBadGateway {
		t.Fatalf("network fell through: called=%v status=%d", called, out.Code)
	}
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/app/v1/info", nil))
	if !called {
		t.Fatal("non-network request did not reach runtime")
	}
}
