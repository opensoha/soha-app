package main

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	runtimeAPI := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "runtime:"+request.URL.Path)
	})
	handler, err := newAppHandler(static, runtimeAPI, upstream.URL)
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

	runtimeResponse := httptest.NewRecorder()
	handler.ServeHTTP(runtimeResponse, httptest.NewRequest(http.MethodGet, "/app/v1/info", nil))
	if runtimeResponse.Body.String() != "runtime:/app/v1/info" {
		t.Fatalf("unexpected runtime response: %q", runtimeResponse.Body.String())
	}
}

func TestAppHandlerStreamsSSEWithoutBuffering(t *testing.T) {
	releaseUpstream := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		writer.Header().Set("Cache-Control", "no-cache")
		writer.Header().Set("X-Accel-Buffering", "no")
		_, _ = io.WriteString(writer, "data: {\"type\":\"message.delta\"}\n\n")
		writer.(http.Flusher).Flush()
		<-releaseUpstream
		_, _ = io.WriteString(writer, "data: {\"type\":\"message.done\"}\n\n")
	}))
	defer upstream.Close()

	handler, err := newAppHandler(http.NotFoundHandler(), http.NotFoundHandler(), upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	appServer := httptest.NewServer(handler)
	defer appServer.Close()
	defer close(releaseUpstream)

	responseChannel := make(chan *http.Response, 1)
	errorChannel := make(chan error, 1)
	go func() {
		response, err := http.Get(appServer.URL + "/api/v1/copilot/sessions/session-1/messages/stream") //nolint:gosec -- local test server
		if err != nil {
			errorChannel <- err
			return
		}
		responseChannel <- response
	}()

	var response *http.Response
	select {
	case response = <-responseChannel:
	case err := <-errorChannel:
		t.Fatalf("stream request failed: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("proxy buffered SSE response headers")
	}
	defer func() { _ = response.Body.Close() }()
	if response.Header.Get("Content-Type") != "text/event-stream" || response.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("unexpected SSE headers: %#v", response.Header)
	}

	frameChannel := make(chan string, 1)
	go func() {
		frame, readErr := bufio.NewReader(response.Body).ReadString('\n')
		if readErr != nil {
			errorChannel <- readErr
			return
		}
		frameChannel <- frame
	}()
	select {
	case frame := <-frameChannel:
		if frame != "data: {\"type\":\"message.delta\"}\n" {
			t.Fatalf("unexpected first SSE frame: %q", frame)
		}
	case err := <-errorChannel:
		t.Fatalf("read first SSE frame: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("proxy buffered the first SSE frame")
	}
}

func TestAppHandlerRejectsUnsafeServerURLs(t *testing.T) {
	for _, serverURL := range []string{"", "ftp://example.com", "https://user:pass@example.com", "https://example.com?token=secret"} {
		if _, err := newAppHandler(http.NotFoundHandler(), http.NotFoundHandler(), serverURL); err == nil {
			t.Fatalf("expected %q to be rejected", serverURL)
		}
	}
}
