package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAppHostDesktopAuthCompletesThroughSystemBrowser(t *testing.T) {
	const (
		attemptID    = "attempt-123"
		callbackCode = "callback-code"
	)
	var redirectURI string
	var codeChallenge string
	var exchangedVerifier string

	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/auth/desktop/attempts":
			var input struct {
				ProviderID          string `json:"providerId"`
				RedirectURI         string `json:"redirectUri"`
				CodeChallenge       string `json:"codeChallenge"`
				CodeChallengeMethod string `json:"codeChallengeMethod"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Fatal(err)
			}
			if input.ProviderID != "oidc-main" || input.CodeChallengeMethod != "S256" {
				t.Fatalf("unexpected create payload: %#v", input)
			}
			redirectURI = input.RedirectURI
			codeChallenge = input.CodeChallenge
			writer.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(writer, `{"data":{"attemptId":"`+attemptID+`","authorizationUrl":"`+upstreamURL(request)+`/api/v1/auth/desktop/attempts/`+attemptID+`/start","expiresAt":"2099-01-01T00:00:00Z"}}`)
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/auth/desktop/attempts/"+attemptID+"/start":
			http.Redirect(writer, request, redirectURI+"?attempt="+attemptID+"&code="+callbackCode, http.StatusTemporaryRedirect)
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/auth/desktop/attempts/"+attemptID+"/exchange":
			var input struct {
				Code         string `json:"code"`
				CodeVerifier string `json:"codeVerifier"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Fatal(err)
			}
			exchangedVerifier = input.CodeVerifier
			if input.Code != callbackCode || desktopCodeChallenge(input.CodeVerifier) != codeChallenge {
				t.Fatalf("invalid exchange payload: %#v", input)
			}
			writer.Header().Add("Set-Cookie", "soha_refresh_token=refresh; Path=/wrong; Domain=example.com; SameSite=Strict")
			writer.Header().Add("Set-Cookie", "soha_protocol_access_token=access; Path=/wrong; SameSite=None")
			writer.Header().Add("Set-Cookie", "untrusted_cookie=must-not-reach-webview; Path=/")
			writer.Header().Set("X-Request-ID", "request-1")
			_, _ = io.WriteString(writer, `{"data":{"user":{"userId":"user-1","userName":"Ada","email":"ada@example.com"},"tokens":{"accessToken":"access-token","refreshToken":"must-not-reach-renderer","tokenType":"Bearer"}}}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer upstream.Close()

	ring := newMemoryKeyring()
	host, err := newAppHost(http.NotFoundHandler(), upstream.URL, nil, false, "test", AppInfo{}, ring)
	if err != nil {
		t.Fatal(err)
	}
	host.credentialsBlocked.Store(true)
	var openedURL string
	host.setOpenBrowserURL(func(rawURL string) error {
		openedURL = rawURL
		response, err := http.Get(rawURL)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("browser callback status = %d", response.StatusCode)
		}
		return nil
	})

	response := httptest.NewRecorder()
	host.ServeHTTP(response, newJSONRequest(http.MethodPost, hostPrefix+"/auth/desktop/start", `{"providerId":"oidc-main"}`))
	if response.Code != http.StatusOK {
		t.Fatalf("desktop auth status = %d body=%s", response.Code, response.Body.String())
	}
	if openedURL != upstream.URL+"/api/v1/auth/desktop/attempts/"+attemptID+"/start" {
		t.Fatalf("opened URL = %q", openedURL)
	}
	callbackURL, err := url.Parse(redirectURI)
	if err != nil || callbackURL.Hostname() != "127.0.0.1" || !strings.HasPrefix(callbackURL.Path, "/callback/") {
		t.Fatalf("redirect URI = %q, error = %v", redirectURI, err)
	}
	if codeChallenge == "" || exchangedVerifier == "" || desktopCodeChallenge(exchangedVerifier) != codeChallenge {
		t.Fatal("PKCE verifier was not bound to the exchange")
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 2 || response.Header().Get("X-Request-ID") != "request-1" {
		t.Fatalf("desktop auth cookies/request ID = %d / %q", len(cookies), response.Header().Get("X-Request-ID"))
	}
	wantCookiePaths := map[string]string{
		"soha_refresh_token":         "/api/v1/auth",
		"soha_protocol_access_token": "/",
	}
	for _, cookie := range cookies {
		if cookie.Path != wantCookiePaths[cookie.Name] || cookie.Domain != "" || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
			t.Fatalf("unsanitized desktop auth cookie: %#v", cookie)
		}
		delete(wantCookiePaths, cookie.Name)
	}
	if len(wantCookiePaths) != 0 {
		t.Fatalf("missing desktop auth cookies: %#v", wantCookiePaths)
	}
	if !strings.Contains(response.Body.String(), `"accessToken":"access-token"`) || host.credentialsBlocked.Load() {
		t.Fatalf("desktop auth response did not establish the session: %s", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "refreshToken") || strings.Contains(response.Body.String(), "must-not-reach-renderer") {
		t.Fatalf("desktop auth response exposed the refresh token: %s", response.Body.String())
	}
	if stored, err := ring.Get(sessionKeyringService, refreshCredentialAccount(host.target.Load())); err != nil || stored != "refresh" {
		t.Fatal("desktop auth did not persist its refresh credential")
	}
}

func TestValidateDesktopAuthorizationURL(t *testing.T) {
	target, err := url.Parse("https://soha.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		raw  string
		ok   bool
	}{
		{name: "exact server start URL", raw: "https://soha.example.com/api/v1/auth/desktop/attempts/attempt-1/start", ok: true},
		{name: "different origin", raw: "https://attacker.example/api/v1/auth/desktop/attempts/attempt-1/start"},
		{name: "downgraded scheme", raw: "http://soha.example.com/api/v1/auth/desktop/attempts/attempt-1/start"},
		{name: "different attempt", raw: "https://soha.example.com/api/v1/auth/desktop/attempts/attempt-2/start"},
		{name: "query", raw: "https://soha.example.com/api/v1/auth/desktop/attempts/attempt-1/start?next=evil"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := validateDesktopAuthorizationURL(target, "attempt-1", test.raw)
			if (err == nil) != test.ok {
				t.Fatalf("validateDesktopAuthorizationURL() error = %v, want ok=%v", err, test.ok)
			}
		})
	}
}

func TestDesktopCallbackRejectsWrongAttemptWithoutCompleting(t *testing.T) {
	callbacks := make(chan desktopAuthCallback, 1)
	handler := newDesktopCallbackHandler("/callback/random-path-token", "attempt-1", callbacks)
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/callback/random-path-token?attempt=attempt-2&code=code-1", nil)
	request.RemoteAddr = "127.0.0.1:45123"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || len(callbacks) != 0 {
		t.Fatalf("wrong-attempt callback status=%d callbacks=%d", response.Code, len(callbacks))
	}
}

func TestDesktopCallbackAcceptsOnlyOnceAfterDelivery(t *testing.T) {
	callbacks := make(chan desktopAuthCallback, 1)
	handler := newDesktopCallbackHandler("/callback/random-path-token", "attempt-1", callbacks)
	newRequest := func() *http.Request {
		request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/callback/random-path-token?attempt=attempt-1&code=code-1", nil)
		request.RemoteAddr = "127.0.0.1:45123"
		return request
	}

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, newRequest())
	if first.Code != http.StatusOK {
		t.Fatalf("first callback status=%d body=%s", first.Code, first.Body.String())
	}
	<-callbacks
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, newRequest())
	if second.Code != http.StatusConflict || len(callbacks) != 0 {
		t.Fatalf("replayed callback status=%d callbacks=%d", second.Code, len(callbacks))
	}
}

func TestDesktopAuthResponseErrorDoesNotExposeUpstreamDetails(t *testing.T) {
	err := desktopAuthResponseError(
		http.StatusUnauthorized,
		[]byte(`{"error":{"code":"internal_provider_error","message":"secret=idp-token"}}`),
		"desktop_auth_exchange_failed",
		"Unable to complete desktop login",
	)
	if err.Status != http.StatusUnauthorized || err.Code != "desktop_auth_exchange_failed" || err.Message != "Unable to complete desktop login" {
		t.Fatalf("desktop auth error exposed upstream details: %#v", err)
	}
}

func TestSanitizeDesktopAuthCookiesRejectsDuplicateSessionCookie(t *testing.T) {
	_, err := sanitizeDesktopAuthCookies([]string{
		"soha_refresh_token=first; Path=/api/v1/auth",
		"soha_refresh_token=second; Path=/api/v1/auth",
	}, false)
	if err == nil {
		t.Fatal("duplicate desktop auth cookie was accepted")
	}
}

func TestSanitizeDesktopAuthCookiesRequiresCompleteSession(t *testing.T) {
	_, err := sanitizeDesktopAuthCookies([]string{"soha_refresh_token=refresh; Path=/api/v1/auth"}, false)
	if err == nil {
		t.Fatal("incomplete desktop auth cookies were accepted")
	}
}

func TestSanitizeDesktopAuthCookiesRequiresSecureHTTPSCookies(t *testing.T) {
	values := []string{
		"soha_refresh_token=refresh; Path=/api/v1/auth; HttpOnly",
		"soha_protocol_access_token=access; Path=/; HttpOnly",
	}
	if _, err := sanitizeDesktopAuthCookies(values, true); err == nil {
		t.Fatal("insecure HTTPS desktop auth cookies were accepted")
	}
	for index := range values {
		values[index] += "; Secure"
	}
	cookies, err := sanitizeDesktopAuthCookies(values, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range cookies {
		cookie, err := http.ParseSetCookie(value)
		if err != nil || !cookie.Secure {
			t.Fatalf("secure desktop auth cookie = %q, error = %v", value, err)
		}
	}
}

func TestDesktopCallbackRejectsNonLoopbackRemote(t *testing.T) {
	callbacks := make(chan desktopAuthCallback, 1)
	handler := newDesktopCallbackHandler("/callback/random-path-token", "attempt-1", callbacks)
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/callback/random-path-token?attempt=attempt-1&code=code-1", nil)
	request.RemoteAddr = "192.0.2.1:45123"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || len(callbacks) != 0 {
		t.Fatalf("non-loopback callback status=%d callbacks=%d", response.Code, len(callbacks))
	}
}

func TestAppHostDesktopAuthBrowserFailureClosesLoopbackListener(t *testing.T) {
	redirects := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var input struct {
			RedirectURI string `json:"redirectUri"`
		}
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			t.Fatal(err)
		}
		redirects <- input.RedirectURI
		writer.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(writer, `{"data":{"attemptId":"attempt-browser","authorizationUrl":"`+upstreamURL(request)+`/api/v1/auth/desktop/attempts/attempt-browser/start","expiresAt":"2099-01-01T00:00:00Z"}}`)
	}))
	defer upstream.Close()
	host, err := newTestAppHost(http.NotFoundHandler(), upstream.URL, nil, false, "test", AppInfo{})
	if err != nil {
		t.Fatal(err)
	}
	host.setOpenBrowserURL(func(string) error { return context.Canceled })

	response := httptest.NewRecorder()
	host.ServeHTTP(response, newJSONRequest(http.MethodPost, hostPrefix+"/auth/desktop/start", `{"providerId":"oidc-main"}`))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"code":"desktop_auth_browser_unavailable"`) {
		t.Fatalf("browser failure response=%d %s", response.Code, response.Body.String())
	}
	redirectURI := <-redirects
	if callbackResponse, err := http.Get(redirectURI); err == nil {
		_ = callbackResponse.Body.Close()
		t.Fatal("loopback listener still accepted callbacks after browser failure")
	}
}

func TestAppHostDesktopAuthCancellationClosesLoopbackListener(t *testing.T) {
	redirects := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var input struct {
			RedirectURI string `json:"redirectUri"`
		}
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			t.Fatal(err)
		}
		redirects <- input.RedirectURI
		writer.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(writer, `{"data":{"attemptId":"attempt-cancel","authorizationUrl":"`+upstreamURL(request)+`/api/v1/auth/desktop/attempts/attempt-cancel/start","expiresAt":"2099-01-01T00:00:00Z"}}`)
	}))
	defer upstream.Close()
	host, err := newTestAppHost(http.NotFoundHandler(), upstream.URL, nil, false, "test", AppInfo{})
	if err != nil {
		t.Fatal(err)
	}
	opened := make(chan struct{})
	host.setOpenBrowserURL(func(string) error {
		close(opened)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	request := newJSONRequest(http.MethodPost, hostPrefix+"/auth/desktop/start", `{"providerId":"oidc-main"}`).WithContext(ctx)
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		host.ServeHTTP(response, request)
	}()
	<-opened
	redirectURI := <-redirects
	concurrentResponse := httptest.NewRecorder()
	host.ServeHTTP(concurrentResponse, newJSONRequest(http.MethodPost, hostPrefix+"/auth/desktop/start", `{"providerId":"oidc-main"}`))
	if concurrentResponse.Code != http.StatusConflict || !strings.Contains(concurrentResponse.Body.String(), `"code":"desktop_auth_in_progress"`) {
		t.Fatalf("concurrent desktop auth response=%d %s", concurrentResponse.Code, concurrentResponse.Body.String())
	}
	cancel()
	<-done

	if response.Code != http.StatusRequestTimeout || !strings.Contains(response.Body.String(), `"code":"desktop_auth_cancelled"`) {
		t.Fatalf("cancelled desktop auth response=%d %s", response.Code, response.Body.String())
	}
	if callbackResponse, err := http.Get(redirectURI); err == nil {
		_ = callbackResponse.Body.Close()
		t.Fatal("loopback listener still accepted callbacks after cancellation")
	}
	if !host.desktopAuthMu.TryLock() {
		t.Fatal("desktop auth lock remained held after cancellation")
	}
	host.desktopAuthMu.Unlock()
}

func TestAppHostDesktopAuthTimeoutClosesLoopbackListener(t *testing.T) {
	redirects := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var input struct {
			RedirectURI string `json:"redirectUri"`
		}
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			t.Fatal(err)
		}
		redirects <- input.RedirectURI
		writer.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(writer, `{"data":{"attemptId":"attempt-timeout","authorizationUrl":"`+upstreamURL(request)+`/api/v1/auth/desktop/attempts/attempt-timeout/start","expiresAt":"2099-01-01T00:00:00Z"}}`)
	}))
	defer upstream.Close()
	host, err := newTestAppHost(http.NotFoundHandler(), upstream.URL, nil, false, "test", AppInfo{})
	if err != nil {
		t.Fatal(err)
	}
	host.desktopAuthTimeout = 20 * time.Millisecond
	host.setOpenBrowserURL(func(string) error { return nil })

	response := httptest.NewRecorder()
	host.ServeHTTP(response, newJSONRequest(http.MethodPost, hostPrefix+"/auth/desktop/start", `{"providerId":"oidc-main"}`))
	if response.Code != http.StatusRequestTimeout || !strings.Contains(response.Body.String(), `"code":"desktop_auth_timeout"`) {
		t.Fatalf("timed out desktop auth response=%d %s", response.Code, response.Body.String())
	}
	redirectURI := <-redirects
	if callbackResponse, err := http.Get(redirectURI); err == nil {
		_ = callbackResponse.Body.Close()
		t.Fatal("loopback listener still accepted callbacks after timeout")
	}
	if !host.desktopAuthMu.TryLock() {
		t.Fatal("desktop auth lock remained held after timeout")
	}
	host.desktopAuthMu.Unlock()
}

func upstreamURL(request *http.Request) string {
	return "http://" + request.Host
}
