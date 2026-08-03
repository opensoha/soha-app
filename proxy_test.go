package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAppHandlerRoutesOnlySohaAPI(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Origin") != "" {
			t.Fatal("browser Origin header reached the upstream server")
		}
		if request.URL.RequestURI() != "/api/v1/auth/login?source=endpoint" {
			t.Fatalf("unexpected upstream URI: %s", request.URL.RequestURI())
		}
		writer.Header().Set("Set-Cookie", "soha_refresh_token=token; Path=/api/v1/auth; HttpOnly")
		_, _ = io.WriteString(writer, `{"data":{"status":"ok"}}`)
	}))
	defer upstream.Close()

	static := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "static:"+request.URL.Path)
	})
	handler, err := newAppHandler(static, upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	loginRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login?source=endpoint", strings.NewReader(`{"login":"admin"}`))
	loginRequest.Header.Set("Origin", "http://wails.localhost")
	loginResponse := httptest.NewRecorder()
	handler.ServeHTTP(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusOK || len(loginResponse.Result().Cookies()) != 1 {
		t.Fatalf("unexpected login response: status=%d cookies=%d", loginResponse.Code, len(loginResponse.Result().Cookies()))
	}

	staticResponse := httptest.NewRecorder()
	handler.ServeHTTP(staticResponse, httptest.NewRequest(http.MethodGet, "/login", nil))
	if staticResponse.Body.String() != "static:/login" {
		t.Fatalf("unexpected static response: %q", staticResponse.Body.String())
	}
}

func TestAppHandlerRejectsUnsafeServerURLs(t *testing.T) {
	for _, serverURL := range []string{"", "ftp://example.com", "https://user:pass@example.com", "https://example.com?token=secret"} {
		if _, err := newAppHandler(http.NotFoundHandler(), serverURL); err == nil {
			t.Fatalf("expected %q to be rejected", serverURL)
		}
	}
}
