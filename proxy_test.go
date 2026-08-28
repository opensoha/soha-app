package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAppHandlerRoutesOnlySohaAPI(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Origin") != "" {
			t.Fatal("browser Origin header reached the upstream server")
		}
		if request.Header.Get("Forwarded") != "" || request.Header.Get("X-Forwarded-Proto") != "http" {
			t.Fatalf("untrusted forwarding headers were not rebuilt: %v", request.Header)
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
	handler, err := newTestAppHost(static, upstream.URL, nil, false, "runtime", AppInfo{})
	if err != nil {
		t.Fatal(err)
	}
	handler.setRuntimeAPI(runtimeAPI)

	loginRequest := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/auth/login?source=endpoint",
		strings.NewReader(`{"login":"admin"}`),
	)
	loginRequest.Header.Set("Origin", "wails://localhost")
	loginRequest.Header.Set("Forwarded", "for=attacker")
	loginRequest.Header.Set("X-Forwarded-Proto", "https")
	loginResponse := httptest.NewRecorder()
	handler.ServeHTTP(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusOK || len(loginResponse.Result().Cookies()) != 1 {
		t.Fatalf("unexpected login response: status=%d cookies=%d", loginResponse.Code, len(loginResponse.Result().Cookies()))
	}
	if loginResponse.Header().Get("X-Request-ID") == "" {
		t.Fatal("proxied response is missing X-Request-ID")
	}

	staticResponse := httptest.NewRecorder()
	handler.ServeHTTP(staticResponse, httptest.NewRequest(http.MethodGet, "/login", nil))
	if staticResponse.Body.String() != "static:/login" {
		t.Fatalf("unexpected static response: %q", staticResponse.Body.String())
	}
	if staticResponse.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("static response is missing Content-Security-Policy")
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

	handler, err := newTestAppHost(http.NotFoundHandler(), upstream.URL, nil, false, "runtime", AppInfo{})
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

func TestStaticSecurityHeadersOnlyRelaxForFrontendDevServer(t *testing.T) {
	production := make(http.Header)
	setStaticSecurityHeaders(production)
	productionCSP := production.Get("Content-Security-Policy")
	if strings.Contains(productionCSP, "script-src 'self' 'unsafe-inline'") ||
		strings.Contains(productionCSP, "script-src 'self' 'unsafe-eval'") {
		t.Fatalf("production CSP permits unsafe scripts: %q", productionCSP)
	}

	t.Setenv("FRONTEND_DEVSERVER_URL", "http://localhost:9245")
	development := make(http.Header)
	setStaticSecurityHeaders(development)
	developmentCSP := development.Get("Content-Security-Policy")
	for _, required := range []string{"'unsafe-inline'", "'unsafe-eval'", "ws:", "wss:"} {
		if !strings.Contains(developmentCSP, required) {
			t.Fatalf("development CSP %q is missing %q", developmentCSP, required)
		}
	}
}

func TestAppHandlerRejectsUnsafeServerURLs(t *testing.T) {
	serverURLs := []string{
		"",
		"ftp://example.com",
		"http://example.com",
		"http://localhost:8080",
		"https://user:pass@example.com",
		"https://example.com?token=secret",
	}
	for _, serverURL := range serverURLs {
		t.Run(serverURL, func(t *testing.T) {
			t.Parallel()
			if _, err := newTestAppHandler(http.NotFoundHandler(), serverURL); err == nil {
				t.Fatalf("expected %q to be rejected", serverURL)
			}
		})
	}
}

func TestAppHandlerBlocksUpstreamRedirect(t *testing.T) {
	for _, location := range []string{"", "https://identity.example.com/login"} {
		t.Run(location, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				if location != "" {
					writer.Header().Set("Location", location)
				}
				writer.Header().Set("Set-Cookie", "soha_refresh_token=secret; Path=/; HttpOnly")
				writer.WriteHeader(http.StatusTemporaryRedirect)
			}))
			defer upstream.Close()
			handler, err := newTestAppHandler(http.NotFoundHandler(), upstream.URL)
			if err != nil {
				t.Fatal(err)
			}

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil))
			if response.Code != http.StatusBadGateway {
				t.Fatalf("redirect response status = %d", response.Code)
			}
			if response.Header().Get("Location") != "" || len(response.Result().Cookies()) != 0 {
				t.Fatal("blocked redirect leaked Location or Set-Cookie")
			}
		})
	}
}

func TestProxyRejectionEventDistinguishesAuthenticationFailures(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		statusCode int
		want       string
	}{
		{name: "password login", method: http.MethodPost, path: "/api/v1/auth/login", statusCode: http.StatusUnauthorized, want: "auth_login_rejected"},
		{name: "refresh", method: http.MethodPost, path: "/api/v1/auth/refresh", statusCode: http.StatusForbidden, want: "session_refresh_rejected"},
		{name: "desktop exchange", method: http.MethodPost, path: "/api/v1/auth/desktop/attempts/attempt-1/exchange", statusCode: http.StatusUnauthorized, want: "desktop_auth_exchange_rejected"},
		{name: "protected API", method: http.MethodGet, path: "/api/v1/auth/profile", statusCode: http.StatusForbidden, want: "api_authorization_rejected"},
		{name: "server failure", method: http.MethodPost, path: "/api/v1/auth/login", statusCode: http.StatusInternalServerError},
		{name: "success", method: http.MethodPost, path: "/api/v1/auth/login", statusCode: http.StatusOK},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			if got := proxyRejectionEvent(request, test.statusCode); got != test.want {
				t.Fatalf("proxyRejectionEvent() = %q, want %q", got, test.want)
			}
		})
	}
	if got := proxyRejectionEvent(nil, http.StatusUnauthorized); got != "" {
		t.Fatalf("proxyRejectionEvent(nil) = %q, want empty", got)
	}
}

func TestAppHostConnectionStates(t *testing.T) {
	tests := []struct {
		name   string
		server func(t *testing.T) string
		want   connectionStatus
	}{
		{
			name: "online",
			server: func(t *testing.T) string {
				return newHealthyServer(t, nil).URL
			},
			want: connectionOnline,
		},
		{
			name: "online with large branding",
			server: func(t *testing.T) string {
				server := newHealthyServer(t, func(writer http.ResponseWriter, request *http.Request) bool {
					if request.URL.Path != "/api/v1/auth/login-options" {
						return false
					}
					_, _ = io.WriteString(writer, `{"data":{"branding":{"loginLogoUrl":"data:image/png;base64,`+
						strings.Repeat("a", 128<<10)+`"},"verification":{"sliderEnabled":true}}}`)
					return true
				})
				return server.URL
			},
			want: connectionOnline,
		},
		{
			name: "oversized login options",
			server: func(t *testing.T) string {
				server := newHealthyServer(t, func(writer http.ResponseWriter, request *http.Request) bool {
					if request.URL.Path != "/api/v1/auth/login-options" {
						return false
					}
					_, _ = io.WriteString(writer, `{"data":{"branding":{"loginLogoUrl":"`+
						strings.Repeat("a", connectionProbeMaxResponseSize)+`"},"verification":{"sliderEnabled":true}}}`)
					return true
				})
				return server.URL
			},
			want: connectionIncompatible,
		},
		{
			name: "not ready",
			server: func(t *testing.T) string {
				server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
					writer.WriteHeader(http.StatusServiceUnavailable)
					_, _ = io.WriteString(writer, `{"status":"degraded"}`)
				}))
				t.Cleanup(server.Close)
				return server.URL
			},
			want: connectionNotReady,
		},
		{
			name: "not ready with empty body",
			server: func(t *testing.T) string {
				server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
					writer.WriteHeader(http.StatusServiceUnavailable)
				}))
				t.Cleanup(server.Close)
				return server.URL
			},
			want: connectionNotReady,
		},
		{
			name: "not ready with invalid body",
			server: func(t *testing.T) string {
				server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
					writer.WriteHeader(http.StatusServiceUnavailable)
					_, _ = io.WriteString(writer, `{`)
				}))
				t.Cleanup(server.Close)
				return server.URL
			},
			want: connectionNotReady,
		},
		{
			name: "login options not ready with invalid body",
			server: func(t *testing.T) string {
				server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					switch request.URL.Path {
					case "/api/v1/healthz":
						_, _ = io.WriteString(writer, `{"status":"ok"}`)
					case "/api/v1/readyz":
						_, _ = io.WriteString(writer, `{"status":"ready"}`)
					default:
						writer.WriteHeader(http.StatusServiceUnavailable)
						_, _ = io.WriteString(writer, `{`)
					}
				}))
				t.Cleanup(server.Close)
				return server.URL
			},
			want: connectionNotReady,
		},
		{
			name: "readiness not ready",
			server: func(t *testing.T) string {
				server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					if request.URL.Path == "/api/v1/healthz" {
						_, _ = io.WriteString(writer, `{"status":"ok"}`)
						return
					}
					writer.WriteHeader(http.StatusServiceUnavailable)
				}))
				t.Cleanup(server.Close)
				return server.URL
			},
			want: connectionNotReady,
		},
		{
			name: "health upstream failure",
			server: func(t *testing.T) string {
				server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
					writer.WriteHeader(http.StatusBadGateway)
				}))
				t.Cleanup(server.Close)
				return server.URL
			},
			want: connectionOffline,
		},
		{
			name: "login options upstream failure",
			server: func(t *testing.T) string {
				server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					switch request.URL.Path {
					case "/api/v1/healthz":
						_, _ = io.WriteString(writer, `{"status":"ok"}`)
					case "/api/v1/readyz":
						_, _ = io.WriteString(writer, `{"status":"ready"}`)
					default:
						writer.WriteHeader(http.StatusBadGateway)
					}
				}))
				t.Cleanup(server.Close)
				return server.URL
			},
			want: connectionOffline,
		},
		{
			name: "incompatible",
			server: func(t *testing.T) string {
				server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
					_, _ = io.WriteString(writer, `{"unexpected":true}`)
				}))
				t.Cleanup(server.Close)
				return server.URL
			},
			want: connectionIncompatible,
		},
		{
			name: "TLS error",
			server: func(t *testing.T) string {
				server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
					_, _ = io.WriteString(writer, `{"status":"ok"}`)
				}))
				t.Cleanup(server.Close)
				return server.URL
			},
			want: connectionTLSError,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			serverURL := test.server(t)
			host, err := newTestAppHost(http.NotFoundHandler(), defaultServerURL, nil, false, "test", AppInfo{})
			if err != nil {
				t.Fatal(err)
			}
			check := host.checkServer(t.Context(), serverURL)
			if check.Status != test.want {
				t.Fatalf("connection status = %q, want %q (code=%q)", check.Status, test.want, check.Code)
			}
		})
	}
}

func TestAppHostSwitchDoesNotLeakOldCredentials(t *testing.T) {
	var logoutAuthorization string
	var logoutCookie string
	serverA := newHealthyServer(t, func(writer http.ResponseWriter, request *http.Request) bool {
		if request.URL.Path != "/api/v1/auth/logout" {
			return false
		}
		logoutAuthorization = request.Header.Get("Authorization")
		logoutCookie = request.Header.Get("Cookie")
		_, _ = io.WriteString(writer, `{"status":"ok"}`)
		return true
	})

	var mu sync.Mutex
	protectedCredentials := [][2]string{}
	serverB := newHealthyServer(t, func(writer http.ResponseWriter, request *http.Request) bool {
		switch request.URL.Path {
		case "/api/v1/auth/login":
			mu.Lock()
			protectedCredentials = append(protectedCredentials, [2]string{
				request.Header.Get("Authorization"), request.Header.Get("Cookie"),
			})
			mu.Unlock()
			writer.Header().Set("Set-Cookie", "soha_refresh_token=new; Path=/api/v1/auth; HttpOnly")
			_, _ = io.WriteString(writer, `{"data":{"tokens":{"accessToken":"new"}}}`)
			return true
		case "/api/v1/protected":
			mu.Lock()
			protectedCredentials = append(protectedCredentials, [2]string{
				request.Header.Get("Authorization"), request.Header.Get("Cookie"),
			})
			mu.Unlock()
			_, _ = io.WriteString(writer, `{"data":{"ok":true}}`)
			return true
		default:
			return false
		}
	})

	store := newConfigStore(filepath.Join(t.TempDir(), "config.json"))
	ring := newMemoryKeyring()
	host, err := newAppHost(http.NotFoundHandler(), serverA.URL, store, false, "default", AppInfo{}, ring)
	if err != nil {
		t.Fatal(err)
	}

	prepare := newJSONRequest(http.MethodPost, hostPrefix+"/connections/switch", `{"serverUrl":"`+serverB.URL+`"}`)
	prepare.Header.Set("Authorization", "Bearer old-access")
	if err := ring.Set(sessionKeyringService, refreshCredentialAccount(host.target.Load()), "old-refresh"); err != nil {
		t.Fatal(err)
	}
	prepareResponse := httptest.NewRecorder()
	host.ServeHTTP(prepareResponse, prepare)
	if prepareResponse.Code != http.StatusOK {
		t.Fatalf("prepare switch status = %d body=%s", prepareResponse.Code, prepareResponse.Body.String())
	}
	if logoutAuthorization != "Bearer old-access" || logoutCookie != "soha_refresh_token=old-refresh" {
		t.Fatalf("old server logout credentials = %q / %q", logoutAuthorization, logoutCookie)
	}
	if _, err := ring.Get(sessionKeyringService, refreshCredentialAccount(host.target.Load())); !errors.Is(err, errTestKeyringNotFound) {
		t.Fatal("server switch retained the old refresh credential")
	}
	if len(prepareResponse.Result().Cookies()) < 2 {
		t.Fatal("prepare switch did not clear authentication cookies")
	}

	blocked := httptest.NewRecorder()
	host.ServeHTTP(blocked, httptest.NewRequest(http.MethodGet, "/api/v1/protected", nil))
	if blocked.Code != http.StatusServiceUnavailable {
		t.Fatalf("request during switch status = %d", blocked.Code)
	}

	var prepared struct {
		Data pendingSwitch `json:"data"`
	}
	if err := json.Unmarshal(prepareResponse.Body.Bytes(), &prepared); err != nil {
		t.Fatal(err)
	}
	activate := newJSONRequest(
		http.MethodPost,
		hostPrefix+"/connections/activate",
		`{"activationToken":"`+prepared.Data.ActivationToken+`"}`,
	)
	activateResponse := httptest.NewRecorder()
	host.ServeHTTP(activateResponse, activate)
	if activateResponse.Code != http.StatusOK {
		t.Fatalf("activate switch status = %d body=%s", activateResponse.Code, activateResponse.Body.String())
	}

	oldCredentialRequest := httptest.NewRequest(http.MethodGet, "/api/v1/protected", nil)
	oldCredentialRequest.Header.Set("Authorization", "Bearer old-access")
	oldCredentialRequest.Header.Set("Cookie", "soha_refresh_token=old-refresh")
	host.ServeHTTP(httptest.NewRecorder(), oldCredentialRequest)

	loginRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{}`))
	loginRequest.Header.Set("Origin", "wails://localhost")
	loginRequest.Header.Set("Authorization", "Bearer old-access")
	loginRequest.Header.Set("Cookie", "soha_refresh_token=old-refresh")
	host.ServeHTTP(httptest.NewRecorder(), loginRequest)

	freshCredentialRequest := httptest.NewRequest(http.MethodGet, "/api/v1/protected", nil)
	freshCredentialRequest.Header.Set("Authorization", "Bearer new-access")
	freshCredentialRequest.Header.Set("Cookie", "soha_refresh_token=new-refresh")
	host.ServeHTTP(httptest.NewRecorder(), freshCredentialRequest)

	mu.Lock()
	defer mu.Unlock()
	want := [][2]string{{"", ""}, {"", ""}, {"Bearer new-access", "soha_refresh_token=new-refresh"}}
	if len(protectedCredentials) != len(want) {
		t.Fatalf("captured credentials = %#v", protectedCredentials)
	}
	for index := range want {
		if protectedCredentials[index] != want[index] {
			t.Fatalf("credentials[%d] = %#v, want %#v", index, protectedCredentials[index], want[index])
		}
	}
}

func TestAppHostRejectsConcurrentSwitchPreparation(t *testing.T) {
	probeReached := make(chan struct{}, 2)
	releaseProbe := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseProbe) }) }
	defer release()

	serverA := newHealthyServer(t, nil)
	serverB := newHealthyServer(t, func(writer http.ResponseWriter, request *http.Request) bool {
		if request.URL.Path != "/api/v1/auth/login-options" {
			return false
		}
		probeReached <- struct{}{}
		<-releaseProbe
		_, _ = io.WriteString(writer, `{"data":{"verification":{"sliderEnabled":false},"localPasswordLoginEnabled":true}}`)
		return true
	})
	store := newConfigStore(filepath.Join(t.TempDir(), "config.json"))
	host, err := newTestAppHost(http.NotFoundHandler(), serverA.URL, store, false, "default", AppInfo{})
	if err != nil {
		t.Fatal(err)
	}

	responses := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() {
			response := httptest.NewRecorder()
			host.ServeHTTP(response, newJSONRequest(
				http.MethodPost,
				hostPrefix+"/connections/switch",
				`{"serverUrl":"`+serverB.URL+`"}`,
			))
			responses <- response
		}()
	}
	for range 2 {
		select {
		case <-probeReached:
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent switch did not reach the connection probe")
		}
	}
	release()

	var prepared *httptest.ResponseRecorder
	conflicts := 0
	for range 2 {
		select {
		case response := <-responses:
			switch response.Code {
			case http.StatusOK:
				prepared = response
			case http.StatusConflict:
				conflicts++
				if !strings.Contains(response.Body.String(), `"code":"server_switch_pending"`) {
					t.Fatalf("unexpected conflict response: %s", response.Body.String())
				}
			default:
				t.Fatalf("unexpected prepare response: %d %s", response.Code, response.Body.String())
			}
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent switch did not complete")
		}
	}
	if prepared == nil || conflicts != 1 {
		t.Fatalf("concurrent switch prepared=%v conflicts=%d", prepared != nil, conflicts)
	}

	var pending struct {
		Data pendingSwitch `json:"data"`
	}
	if err := json.Unmarshal(prepared.Body.Bytes(), &pending); err != nil {
		t.Fatal(err)
	}
	activateResponse := httptest.NewRecorder()
	host.ServeHTTP(activateResponse, newJSONRequest(
		http.MethodPost,
		hostPrefix+"/connections/activate",
		`{"activationToken":"`+pending.Data.ActivationToken+`"}`,
	))
	if activateResponse.Code != http.StatusOK {
		t.Fatalf("activate concurrent switch status = %d body=%s", activateResponse.Code, activateResponse.Body.String())
	}
}

func TestAppHostRejectsSwitchWhenTargetChangesDuringProbe(t *testing.T) {
	probeReached := make(chan struct{})
	releaseProbe := make(chan struct{})
	serverA := newHealthyServer(t, nil)
	serverB := newHealthyServer(t, nil)
	serverC := newHealthyServer(t, func(writer http.ResponseWriter, request *http.Request) bool {
		if request.URL.Path != "/api/v1/healthz" {
			return false
		}
		close(probeReached)
		<-releaseProbe
		_, _ = io.WriteString(writer, `{"status":"ok","postgres":"ok"}`)
		return true
	})
	store := newConfigStore(filepath.Join(t.TempDir(), "config.json"))
	host, err := newTestAppHost(http.NotFoundHandler(), serverA.URL, store, false, "default", AppInfo{})
	if err != nil {
		t.Fatal(err)
	}

	targetB, err := url.Parse(serverB.URL)
	if err != nil {
		t.Fatal(err)
	}
	host.pendingMu.Lock()
	host.pending = targetB
	host.pendingCode = "activate-b"
	host.pendingMu.Unlock()

	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		host.ServeHTTP(response, newJSONRequest(
			http.MethodPost,
			hostPrefix+"/connections/switch",
			`{"serverUrl":"`+serverC.URL+`"}`,
		))
		close(done)
	}()
	select {
	case <-probeReached:
	case <-time.After(2 * time.Second):
		t.Fatal("switch did not reach the connection probe")
	}

	activateResponse := httptest.NewRecorder()
	host.ServeHTTP(activateResponse, newJSONRequest(
		http.MethodPost,
		hostPrefix+"/connections/activate",
		`{"activationToken":"activate-b"}`,
	))
	if activateResponse.Code != http.StatusOK {
		t.Fatalf("activate first switch status = %d body=%s", activateResponse.Code, activateResponse.Body.String())
	}
	close(releaseProbe)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stale switch did not complete")
	}

	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"code":"server_switch_pending"`) {
		t.Fatalf("stale switch response = %d %s", response.Code, response.Body.String())
	}
	if host.target.Load().String() != serverB.URL || host.hasPendingSwitch() {
		t.Fatalf("stale switch changed target=%s pending=%v", host.target.Load(), host.hasPendingSwitch())
	}
}

func TestAppHostSwitchContinuesWhenOldServerIsOffline(t *testing.T) {
	serverA := newHealthyServer(t, nil)
	serverAURL := serverA.URL
	serverA.Close()

	var receivedAuthorization string
	var receivedCookie string
	serverB := newHealthyServer(t, func(writer http.ResponseWriter, request *http.Request) bool {
		if request.URL.Path != "/api/v1/protected" {
			return false
		}
		receivedAuthorization = request.Header.Get("Authorization")
		receivedCookie = request.Header.Get("Cookie")
		_, _ = io.WriteString(writer, `{"data":{"ok":true}}`)
		return true
	})

	store := newConfigStore(filepath.Join(t.TempDir(), "config.json"))
	host, err := newTestAppHost(http.NotFoundHandler(), serverAURL, store, false, "default", AppInfo{})
	if err != nil {
		t.Fatal(err)
	}
	prepare := newJSONRequest(http.MethodPost, hostPrefix+"/connections/switch", `{"serverUrl":"`+serverB.URL+`"}`)
	prepare.Header.Set("Authorization", "Bearer old-access")
	prepare.Header.Set("Cookie", "soha_refresh_token=old-refresh")
	prepareResponse := httptest.NewRecorder()
	host.ServeHTTP(prepareResponse, prepare)
	if prepareResponse.Code != http.StatusOK {
		t.Fatalf("prepare switch with offline old server status = %d body=%s", prepareResponse.Code, prepareResponse.Body.String())
	}

	var prepared struct {
		Data pendingSwitch `json:"data"`
	}
	if err := json.Unmarshal(prepareResponse.Body.Bytes(), &prepared); err != nil {
		t.Fatal(err)
	}
	activateResponse := httptest.NewRecorder()
	host.ServeHTTP(activateResponse, newJSONRequest(
		http.MethodPost,
		hostPrefix+"/connections/activate",
		`{"activationToken":"`+prepared.Data.ActivationToken+`"}`,
	))
	if activateResponse.Code != http.StatusOK {
		t.Fatalf("activate switch status = %d body=%s", activateResponse.Code, activateResponse.Body.String())
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/protected", nil)
	request.Header.Set("Authorization", "Bearer old-access")
	request.Header.Set("Cookie", "soha_refresh_token=old-refresh")
	response := httptest.NewRecorder()
	host.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("new server request status = %d body=%s", response.Code, response.Body.String())
	}
	if receivedAuthorization != "" || receivedCookie != "" {
		t.Fatalf("old credentials reached new server: authorization=%q cookie=%q", receivedAuthorization, receivedCookie)
	}
}

func TestAppHostActivationFailureRollsBackPendingSwitch(t *testing.T) {
	var receivedCredentials [2]string
	serverA := newHealthyServer(t, func(writer http.ResponseWriter, request *http.Request) bool {
		switch request.URL.Path {
		case "/api/v1/auth/logout":
			_, _ = io.WriteString(writer, `{"data":{"status":"ok"}}`)
			return true
		case "/api/v1/protected":
			receivedCredentials = [2]string{
				request.Header.Get("Authorization"),
				request.Header.Get("Cookie"),
			}
			_, _ = io.WriteString(writer, `{"data":{"ok":true}}`)
			return true
		default:
			return false
		}
	})
	serverB := newHealthyServer(t, nil)

	blockedDirectory := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockedDirectory, []byte("blocked"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := newConfigStore(filepath.Join(blockedDirectory, "config.json"))
	host, err := newTestAppHost(http.NotFoundHandler(), serverA.URL, store, false, "default", AppInfo{})
	if err != nil {
		t.Fatal(err)
	}

	prepareResponse := httptest.NewRecorder()
	host.ServeHTTP(prepareResponse, newJSONRequest(
		http.MethodPost,
		hostPrefix+"/connections/switch",
		`{"serverUrl":"`+serverB.URL+`"}`,
	))
	if prepareResponse.Code != http.StatusOK {
		t.Fatalf("prepare switch status = %d body=%s", prepareResponse.Code, prepareResponse.Body.String())
	}
	var prepared struct {
		Data pendingSwitch `json:"data"`
	}
	if err := json.Unmarshal(prepareResponse.Body.Bytes(), &prepared); err != nil {
		t.Fatal(err)
	}

	activateResponse := httptest.NewRecorder()
	host.ServeHTTP(activateResponse, newJSONRequest(
		http.MethodPost,
		hostPrefix+"/connections/activate",
		`{"activationToken":"`+prepared.Data.ActivationToken+`"}`,
	))
	if activateResponse.Code != http.StatusInternalServerError ||
		!strings.Contains(activateResponse.Body.String(), `"code":"configuration_write_failed"`) {
		t.Fatalf("activate switch response = %d %s", activateResponse.Code, activateResponse.Body.String())
	}
	if len(activateResponse.Result().Cookies()) < 2 {
		t.Fatal("failed activation did not repeat authentication cookie deletion")
	}
	if host.hasPendingSwitch() {
		t.Fatal("failed activation left the API proxy blocked by a pending switch")
	}
	if host.target.Load().String() != serverA.URL || !host.credentialsBlocked.Load() {
		t.Fatalf("failed activation target=%q blocked=%v", host.target.Load(), host.credentialsBlocked.Load())
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/protected", nil)
	request.Header.Set("Authorization", "Bearer old-access")
	request.Header.Set("Cookie", "soha_refresh_token=old-refresh")
	response := httptest.NewRecorder()
	host.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("old target after rollback status = %d body=%s", response.Code, response.Body.String())
	}
	if receivedCredentials != [2]string{} {
		t.Fatalf("old credentials survived failed activation: %#v", receivedCredentials)
	}
}

func TestAppHostLateLoginResponseCannotUnblockNewServer(t *testing.T) {
	loginStarted := make(chan struct{})
	releaseLogin := make(chan struct{})
	serverA := newHealthyServer(t, func(writer http.ResponseWriter, request *http.Request) bool {
		switch request.URL.Path {
		case "/api/v1/auth/login":
			close(loginStarted)
			<-releaseLogin
			writer.Header().Set("Set-Cookie", "soha_refresh_token=old-refresh; Path=/api/v1/auth; HttpOnly")
			_, _ = io.WriteString(writer, `{"data":{"tokens":{"accessToken":"old"}}}`)
			return true
		case "/api/v1/auth/logout":
			_, _ = io.WriteString(writer, `{"data":{"status":"ok"}}`)
			return true
		default:
			return false
		}
	})

	var received [2]string
	serverB := newHealthyServer(t, func(writer http.ResponseWriter, request *http.Request) bool {
		if request.URL.Path != "/api/v1/protected" {
			return false
		}
		received = [2]string{request.Header.Get("Authorization"), request.Header.Get("Cookie")}
		_, _ = io.WriteString(writer, `{"data":{"ok":true}}`)
		return true
	})

	store := newConfigStore(filepath.Join(t.TempDir(), "config.json"))
	host, err := newTestAppHost(http.NotFoundHandler(), serverA.URL, store, false, "default", AppInfo{})
	if err != nil {
		t.Fatal(err)
	}
	loginDone := make(chan struct{})
	go func() {
		defer close(loginDone)
		request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{}`))
		request.Header.Set("Origin", "wails://localhost")
		host.ServeHTTP(httptest.NewRecorder(), request)
	}()
	<-loginStarted

	prepareResponse := httptest.NewRecorder()
	host.ServeHTTP(prepareResponse, newJSONRequest(http.MethodPost, hostPrefix+"/connections/switch", `{"serverUrl":"`+serverB.URL+`"}`))
	if prepareResponse.Code != http.StatusOK {
		t.Fatalf("prepare switch status = %d body=%s", prepareResponse.Code, prepareResponse.Body.String())
	}
	var prepared struct {
		Data pendingSwitch `json:"data"`
	}
	if err := json.Unmarshal(prepareResponse.Body.Bytes(), &prepared); err != nil {
		t.Fatal(err)
	}
	activateResponse := httptest.NewRecorder()
	host.ServeHTTP(activateResponse, newJSONRequest(
		http.MethodPost,
		hostPrefix+"/connections/activate",
		`{"activationToken":"`+prepared.Data.ActivationToken+`"}`,
	))
	if activateResponse.Code != http.StatusOK {
		t.Fatalf("activate switch status = %d body=%s", activateResponse.Code, activateResponse.Body.String())
	}

	close(releaseLogin)
	<-loginDone
	request := httptest.NewRequest(http.MethodGet, "/api/v1/protected", nil)
	request.Header.Set("Authorization", "Bearer old-access")
	request.Header.Set("Cookie", "soha_refresh_token=old-refresh")
	host.ServeHTTP(httptest.NewRecorder(), request)
	if received != [2]string{} {
		t.Fatalf("late old login unblocked credentials: %#v", received)
	}
	config, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if config.ServerURL != serverB.URL || !config.CredentialsBlocked {
		t.Fatalf("persisted switch state = %#v", config)
	}
}

func TestAppHostRejectsLateAPIResponseAfterServerSwitch(t *testing.T) {
	apiStarted := make(chan struct{})
	releaseAPI := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseAPI) }) }
	defer release()

	serverA := newHealthyServer(t, func(writer http.ResponseWriter, request *http.Request) bool {
		switch request.URL.Path {
		case "/api/v1/protected":
			close(apiStarted)
			<-releaseAPI
			_, _ = io.WriteString(writer, `{"data":{"server":"old-response-sensitive-marker"}}`)
			return true
		case "/api/v1/auth/logout":
			_, _ = io.WriteString(writer, `{"data":{"status":"ok"}}`)
			return true
		default:
			return false
		}
	})
	serverB := newHealthyServer(t, func(writer http.ResponseWriter, request *http.Request) bool {
		if request.URL.Path != "/api/v1/protected" {
			return false
		}
		_, _ = io.WriteString(writer, `{"data":{"server":"new"}}`)
		return true
	})

	store := newConfigStore(filepath.Join(t.TempDir(), "config.json"))
	host, err := newTestAppHost(http.NotFoundHandler(), serverA.URL, store, false, "default", AppInfo{})
	if err != nil {
		t.Fatal(err)
	}
	lateResponse := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		host.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/protected", nil))
		lateResponse <- response
	}()
	select {
	case <-apiStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("old server API request did not start")
	}

	prepareResponse := httptest.NewRecorder()
	host.ServeHTTP(prepareResponse, newJSONRequest(
		http.MethodPost,
		hostPrefix+"/connections/switch",
		`{"serverUrl":"`+serverB.URL+`"}`,
	))
	if prepareResponse.Code != http.StatusOK {
		t.Fatalf("prepare switch status = %d body=%s", prepareResponse.Code, prepareResponse.Body.String())
	}
	var prepared struct {
		Data pendingSwitch `json:"data"`
	}
	if err := json.Unmarshal(prepareResponse.Body.Bytes(), &prepared); err != nil {
		t.Fatal(err)
	}
	activateResponse := httptest.NewRecorder()
	host.ServeHTTP(activateResponse, newJSONRequest(
		http.MethodPost,
		hostPrefix+"/connections/activate",
		`{"activationToken":"`+prepared.Data.ActivationToken+`"}`,
	))
	if activateResponse.Code != http.StatusOK {
		t.Fatalf("activate switch status = %d body=%s", activateResponse.Code, activateResponse.Body.String())
	}

	release()
	select {
	case response := <-lateResponse:
		if response.Code != http.StatusBadGateway ||
			!strings.Contains(response.Body.String(), `"code":"upstream_unavailable"`) {
			t.Fatalf("late old response = %d %s", response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), "old-response-sensitive-marker") {
			t.Fatalf("late old response body leaked: %s", response.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("late old server API request did not finish")
	}

	currentResponse := httptest.NewRecorder()
	host.ServeHTTP(currentResponse, httptest.NewRequest(http.MethodGet, "/api/v1/protected", nil))
	if currentResponse.Code != http.StatusOK ||
		!strings.Contains(currentResponse.Body.String(), `"server":"new"`) {
		t.Fatalf("new server response = %d %s", currentResponse.Code, currentResponse.Body.String())
	}
}

func TestAppHostOpenLogDirectory(t *testing.T) {
	host, err := newTestAppHost(http.NotFoundHandler(), defaultServerURL, nil, false, "test", AppInfo{})
	if err != nil {
		t.Fatal(err)
	}
	opened := 0
	host.setOpenLogDirectory(func() error {
		opened++
		return nil
	})
	response := httptest.NewRecorder()
	host.ServeHTTP(response, newJSONRequest(http.MethodPost, hostPrefix+"/logs/open", `{}`))
	if response.Code != http.StatusOK || opened != 1 || !strings.Contains(response.Body.String(), `"status":"ok"`) {
		t.Fatalf("open logs response = %d %q, calls=%d", response.Code, response.Body.String(), opened)
	}

	host.setOpenLogDirectory(func() error { return errors.New("unavailable") })
	response = httptest.NewRecorder()
	host.ServeHTTP(response, newJSONRequest(http.MethodPost, hostPrefix+"/logs/open", `{}`))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"code":"native_action_unavailable"`) {
		t.Fatalf("unavailable open logs response = %d %q", response.Code, response.Body.String())
	}

	response = httptest.NewRecorder()
	host.ServeHTTP(response, newJSONRequest(http.MethodPost, hostPrefix+"/logs/open", `{"unexpected":true}`))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid open logs request status = %d", response.Code)
	}
}

func TestAppHostRejectsUntrustedMutationOrigin(t *testing.T) {
	host, err := newTestAppHost(http.NotFoundHandler(), defaultServerURL, nil, false, "test", AppInfo{})
	if err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{
		"",
		"https://attacker.example.com",
		"wails://localhost:443",
		"http://wails.localhost:8080",
		"wails://localhost.attacker.example",
		"http://user@wails.localhost",
		"null",
	} {
		t.Run(origin, func(t *testing.T) {
			request := newJSONRequest(http.MethodPost, hostPrefix+"/session/clear", `{}`)
			request.Header.Set("Origin", origin)
			response := httptest.NewRecorder()
			host.ServeHTTP(response, request)
			if response.Code != http.StatusForbidden {
				t.Fatalf("untrusted mutation origin %q status = %d", origin, response.Code)
			}
		})
	}

	apiMutation := httptest.NewRecorder()
	host.ServeHTTP(
		apiMutation,
		httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{}`)),
	)
	if apiMutation.Code != http.StatusForbidden {
		t.Fatalf("API mutation without Origin status = %d", apiMutation.Code)
	}

	for _, windowID := range []string{"0", "-1", "invalid", "1 "} {
		request := newJSONRequest(http.MethodPost, hostPrefix+"/session/clear", `{}`)
		request.Header.Del("Origin")
		request.Header.Set("X-Wails-Window-Id", windowID)
		response := httptest.NewRecorder()
		host.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("invalid Wails window ID %q status = %d", windowID, response.Code)
		}
	}

	untrustedWithWindow := newJSONRequest(http.MethodPost, hostPrefix+"/session/clear", `{}`)
	untrustedWithWindow.Header.Set("Origin", "https://attacker.example.com")
	untrustedWithWindow.Header.Set("X-Wails-Window-Id", "1")
	untrustedResponse := httptest.NewRecorder()
	host.ServeHTTP(untrustedResponse, untrustedWithWindow)
	if untrustedResponse.Code != http.StatusForbidden {
		t.Fatalf("untrusted Origin with Wails window ID status = %d", untrustedResponse.Code)
	}

	t.Setenv("FRONTEND_DEVSERVER_URL", "http://127.0.0.1:9245")
	for _, origin := range []string{"http://127.0.0.1:9245", "wails://localhost:9245", "http://wails.localhost:9245"} {
		request := newJSONRequest(http.MethodPost, hostPrefix+"/session/clear", `{}`)
		request.Header.Set("Origin", origin)
		response := httptest.NewRecorder()
		host.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("trusted development origin %q status = %d body=%s", origin, response.Code, response.Body.String())
		}
	}
}

func TestAppHostAcceptsNativeWailsMutationsWithoutOrigin(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upstreamCalls++
		if request.URL.Path != "/api/v1/auth/login" {
			t.Fatalf("unexpected upstream path: %s", request.URL.Path)
		}
		writer.Header().Set("Set-Cookie", "soha_refresh_token=native-refresh; Path=/api/v1/auth; HttpOnly")
		_, _ = io.WriteString(writer, `{"data":{"status":"ok"}}`)
	}))
	defer upstream.Close()
	host, err := newTestAppHost(http.NotFoundHandler(), upstream.URL, nil, false, "test", AppInfo{})
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{hostPrefix + "/session/clear", "/api/v1/auth/login"} {
		request := newJSONRequest(http.MethodPost, path, `{}`)
		request.Header.Del("Origin")
		request.Header.Set("X-Wails-Window-Id", "1")
		response := httptest.NewRecorder()
		host.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("native Wails mutation %s status = %d body=%s", path, response.Code, response.Body.String())
		}
	}
	if upstreamCalls != 1 {
		t.Fatalf("upstream calls = %d, want 1", upstreamCalls)
	}
}

func TestAppHostSessionClearPersistsBlockAndExpiresAuthCookies(t *testing.T) {
	store := newConfigStore(filepath.Join(t.TempDir(), "config.json"))
	ring := newMemoryKeyring()
	host, err := newAppHost(http.NotFoundHandler(), defaultServerURL, store, false, "default", AppInfo{}, ring)
	if err != nil {
		t.Fatal(err)
	}
	host.credentialsBlocked.Store(false)
	if err := ring.Set(sessionKeyringService, refreshCredentialAccount(host.target.Load()), "stored-refresh"); err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	host.ServeHTTP(response, newJSONRequest(http.MethodPost, hostPrefix+"/session/clear", `{}`))
	if response.Code != http.StatusOK || !host.credentialsBlocked.Load() {
		t.Fatalf("clear session response=%d blocked=%v", response.Code, host.credentialsBlocked.Load())
	}
	config, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if config.ServerURL != defaultServerURL || !config.CredentialsBlocked {
		t.Fatalf("persisted cleared session = %#v", config)
	}
	if _, err := ring.Get(sessionKeyringService, refreshCredentialAccount(host.target.Load())); !errors.Is(err, errTestKeyringNotFound) {
		t.Fatal("session clear retained the refresh credential")
	}

	want := map[string]bool{
		"soha_refresh_token|/api/v1/auth": true,
		"soha_refresh_token|/":            true,
		"soha_protocol_access_token|/":    true,
	}
	for _, cookie := range response.Result().Cookies() {
		key := cookie.Name + "|" + cookie.Path
		if !want[key] || cookie.Value != "" || cookie.MaxAge >= 0 || cookie.Secure {
			t.Fatalf("unexpected cleared cookie: %#v", cookie)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Fatalf("authentication cookies were not cleared: %#v", want)
	}
}

func TestClearAuthCookieHeadersMarksHTTPSCookiesSecure(t *testing.T) {
	header := make(http.Header)
	clearAuthCookieHeaders(header, true)
	response := &http.Response{Header: header}
	if len(response.Cookies()) != 3 {
		t.Fatalf("cleared HTTPS cookies = %d", len(response.Cookies()))
	}
	for _, cookie := range response.Cookies() {
		if !cookie.Secure || cookie.MaxAge >= 0 {
			t.Fatalf("insecure HTTPS cookie deletion: %#v", cookie)
		}
	}
}

func newHealthyServer(
	t *testing.T,
	extra func(writer http.ResponseWriter, request *http.Request) bool,
) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if extra != nil && extra(writer, request) {
			return
		}
		switch request.URL.Path {
		case "/api/v1/healthz":
			_, _ = io.WriteString(writer, `{"status":"ok","postgres":"ok"}`)
		case "/api/v1/readyz":
			_, _ = io.WriteString(writer, `{"status":"ready"}`)
		case "/api/v1/auth/login-options":
			_, _ = io.WriteString(writer, `{"data":{"verification":{"sliderEnabled":false},"localPasswordLoginEnabled":true}}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func newJSONRequest(method string, path string, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "wails://localhost")
	return request
}
