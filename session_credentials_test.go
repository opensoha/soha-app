package main

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/zalando/go-keyring"
)

var errTestKeyringNotFound = keyring.ErrNotFound

type memoryKeyring struct {
	mu        sync.Mutex
	values    map[string]string
	err       error
	deleteErr error
}

func newMemoryKeyring() *memoryKeyring {
	return &memoryKeyring{values: map[string]string{}}
}

func TestRefreshTokenFromSetCookiesRequiresSecureHTTPSCookies(t *testing.T) {
	tests := []struct {
		name          string
		values        []string
		requireSecure bool
		wantToken     string
		wantError     bool
	}{
		{
			name:      "loopback HTTP accepts non-Secure refresh cookie",
			values:    []string{refreshCookieName + "=refresh; Path=/api/v1/auth; HttpOnly"},
			wantToken: "refresh",
		},
		{
			name:          "HTTPS rejects non-Secure refresh cookie",
			values:        []string{refreshCookieName + "=refresh; Path=/api/v1/auth; HttpOnly"},
			requireSecure: true,
			wantError:     true,
		},
		{
			name: "HTTPS rejects non-Secure protocol cookie",
			values: []string{
				refreshCookieName + "=refresh; Path=/api/v1/auth; HttpOnly; Secure",
				protocolAccessCookieName + "=access; Path=/; HttpOnly",
			},
			requireSecure: true,
			wantError:     true,
		},
		{
			name: "HTTPS accepts Secure auth cookies",
			values: []string{
				refreshCookieName + "=refresh; Path=/api/v1/auth; HttpOnly; Secure",
				protocolAccessCookieName + "=access; Path=/; HttpOnly; Secure",
			},
			requireSecure: true,
			wantToken:     "refresh",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token, err := refreshTokenFromSetCookies(test.values, test.requireSecure)
			if (err != nil) != test.wantError || token != test.wantToken {
				t.Fatalf("refresh token = %q, error = %v", token, err)
			}
		})
	}
}

func (m *memoryKeyring) Set(service, user, password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.values[service+"\x00"+user] = password
	return nil
}

func (m *memoryKeyring) Get(service, user string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return "", m.err
	}
	value, ok := m.values[service+"\x00"+user]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return value, nil
}

func (m *memoryKeyring) Delete(service, user string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	if m.deleteErr != nil {
		return m.deleteErr
	}
	key := service + "\x00" + user
	if _, ok := m.values[key]; !ok {
		return keyring.ErrNotFound
	}
	delete(m.values, key)
	return nil
}

func (m *memoryKeyring) DeleteAll(service string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	for key := range m.values {
		if strings.HasPrefix(key, service+"\x00") {
			delete(m.values, key)
		}
	}
	return nil
}

func newTestAppHost(
	static http.Handler,
	rawServerURL string,
	config *configStore,
	locked bool,
	source string,
	info AppInfo,
) (*appHost, error) {
	return newAppHost(static, rawServerURL, config, locked, source, info, newMemoryKeyring())
}

func newTestAppHandler(static http.Handler, rawServerURL string) (http.Handler, error) {
	return newTestAppHost(static, rawServerURL, nil, false, "runtime", AppInfo{})
}

func TestAppHostPersistsRefreshCredentialAcrossRestart(t *testing.T) {
	ring := newMemoryKeyring()
	var mu sync.Mutex
	receivedRefreshCookies := []string{}
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/auth/login":
			writer.Header().Set("Set-Cookie", refreshCookieName+"=test-refresh-1; Path=/api/v1/auth; HttpOnly")
			_, _ = io.WriteString(writer, `{"data":{"user":{"userId":"user-1","userName":"Ada","email":"ada@example.com"},"tokens":{"accessToken":"access-1","refreshToken":"test-refresh-1","tokenType":"Bearer"}}}`)
		case "/api/v1/auth/refresh":
			mu.Lock()
			receivedRefreshCookies = append(receivedRefreshCookies, request.Header.Get("Cookie"))
			mu.Unlock()
			writer.Header().Set("Set-Cookie", refreshCookieName+"=test-refresh-2; Path=/api/v1/auth; HttpOnly")
			_, _ = io.WriteString(writer, `{"data":{"user":{"userId":"user-1","userName":"Ada","email":"ada@example.com"},"tokens":{"accessToken":"access-2","refreshToken":"test-refresh-2","tokenType":"Bearer"}}}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer upstream.Close()

	host, err := newAppHost(http.NotFoundHandler(), upstream.URL, nil, false, "test", AppInfo{}, ring)
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{}`))
	login.Header.Set("Origin", "wails://localhost")
	loginResponse := httptest.NewRecorder()
	host.ServeHTTP(loginResponse, login)
	if loginResponse.Code != http.StatusOK || strings.Contains(loginResponse.Body.String(), "refreshToken") ||
		strings.Contains(loginResponse.Body.String(), "test-refresh") {
		t.Fatal("password login did not redact the refresh credential")
	}

	for range 2 {
		restarted, err := newAppHost(http.NotFoundHandler(), upstream.URL, nil, false, "test", AppInfo{}, ring)
		if err != nil {
			t.Fatal(err)
		}
		refresh := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(`{}`))
		refresh.Header.Set("Origin", "wails://localhost")
		response := httptest.NewRecorder()
		restarted.ServeHTTP(response, refresh)
		if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "refreshToken") ||
			strings.Contains(response.Body.String(), "test-refresh") {
			t.Fatal("restart refresh did not return a redacted session")
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(receivedRefreshCookies) != 2 ||
		receivedRefreshCookies[0] != refreshCookieName+"=test-refresh-1" ||
		receivedRefreshCookies[1] != refreshCookieName+"=test-refresh-2" {
		t.Fatal("restart refresh did not inject and rotate the stored credential")
	}
}

func TestAppHostRefreshRejectionClearsStoredCredential(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			ring := newMemoryKeyring()
			var receivedCookie string
			upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				receivedCookie = request.Header.Get("Cookie")
				writer.WriteHeader(status)
				_, _ = io.WriteString(writer, `{"error":{"code":"unauthorized","message":"expired"}}`)
			}))
			defer upstream.Close()
			store := newConfigStore(filepath.Join(t.TempDir(), "config.json"))
			host, err := newAppHost(http.NotFoundHandler(), upstream.URL, store, false, "test", AppInfo{}, ring)
			if err != nil {
				t.Fatal(err)
			}
			if err := ring.Set(sessionKeyringService, refreshCredentialAccount(host.target.Load()), "expired-refresh"); err != nil {
				t.Fatal(err)
			}

			request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(`{}`))
			request.Header.Set("Origin", "wails://localhost")
			response := httptest.NewRecorder()
			host.ServeHTTP(response, request)
			if response.Code != status || receivedCookie != refreshCookieName+"=expired-refresh" ||
				!host.credentialsBlocked.Load() {
				t.Fatal("rejected refresh did not block the persisted session")
			}
			if _, err := ring.Get(sessionKeyringService, refreshCredentialAccount(host.target.Load())); !errors.Is(err, keyring.ErrNotFound) {
				t.Fatal("rejected refresh retained the stored credential")
			}
			config, err := store.Load()
			if err != nil || !config.CredentialsBlocked {
				t.Fatal("rejected refresh did not persist the blocked session state")
			}
			if len(response.Result().Cookies()) < 2 {
				t.Fatal("rejected refresh did not clear WebView authentication cookies")
			}
		})
	}
}

func TestAppHostMissingRefreshCredentialDoesNotSendCookie(t *testing.T) {
	ring := newMemoryKeyring()
	var receivedCookie string
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		receivedCookie = request.Header.Get("Cookie")
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(writer, `{"error":{"code":"unauthorized"}}`)
	}))
	defer upstream.Close()
	host, err := newAppHost(http.NotFoundHandler(), upstream.URL, nil, false, "test", AppInfo{}, ring)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(`{}`))
	request.Header.Set("Origin", "wails://localhost")
	response := httptest.NewRecorder()
	host.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || receivedCookie != "" || !host.credentialsBlocked.Load() {
		t.Fatal("missing credential refresh did not remain cookie-free and fail closed")
	}
}

func TestAppHostLogoutUsesAndClearsStoredRefreshCredential(t *testing.T) {
	ring := newMemoryKeyring()
	var receivedCookie string
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		receivedCookie = request.Header.Get("Cookie")
		_, _ = io.WriteString(writer, `{"status":"ok"}`)
	}))
	defer upstream.Close()
	store := newConfigStore(filepath.Join(t.TempDir(), "config.json"))
	host, err := newAppHost(http.NotFoundHandler(), upstream.URL, store, false, "test", AppInfo{}, ring)
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Set(sessionKeyringService, refreshCredentialAccount(host.target.Load()), "logout-refresh"); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", strings.NewReader(`{}`))
	request.Header.Set("Origin", "wails://localhost")
	response := httptest.NewRecorder()
	host.ServeHTTP(response, request)
	if response.Code != http.StatusOK || receivedCookie != refreshCookieName+"=logout-refresh" ||
		!host.credentialsBlocked.Load() {
		t.Fatal("logout did not use and block the stored credential")
	}
	if _, err := ring.Get(sessionKeyringService, refreshCredentialAccount(host.target.Load())); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatal("logout retained the stored credential")
	}
	config, err := store.Load()
	if err != nil || !config.CredentialsBlocked || len(response.Result().Cookies()) < 2 {
		t.Fatal("logout did not persist and return complete local session cleanup")
	}
}

func TestAppHostCredentialDeleteFailureRemainsBlocked(t *testing.T) {
	ring := newMemoryKeyring()
	store := newConfigStore(filepath.Join(t.TempDir(), "config.json"))
	host, err := newAppHost(http.NotFoundHandler(), defaultServerURL, store, false, "test", AppInfo{}, ring)
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Set(sessionKeyringService, refreshCredentialAccount(host.target.Load()), "retained-refresh"); err != nil {
		t.Fatal(err)
	}
	ring.deleteErr = errors.New("delete unavailable")
	var logs bytes.Buffer
	previousLogOutput := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previousLogOutput)

	response := httptest.NewRecorder()
	host.ServeHTTP(response, newJSONRequest(http.MethodPost, hostPrefix+"/session/clear", `{}`))
	config, loadErr := store.Load()
	if response.Code != http.StatusOK || !host.credentialsBlocked.Load() || loadErr != nil || !config.CredentialsBlocked ||
		len(response.Result().Cookies()) < 2 {
		t.Fatal("delete failure bypassed local session blocking")
	}
	if !strings.Contains(logs.String(), "session_credential_delete_failed") || strings.Contains(logs.String(), "retained-refresh") {
		t.Fatal("delete failure logging was missing or exposed the credential")
	}
}

func TestAppHostCredentialStoreUnavailableFailsClosed(t *testing.T) {
	ring := newMemoryKeyring()
	ring.err = errors.New("credential store unavailable")
	var refreshCookie string
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/auth/login":
			writer.Header().Set("Set-Cookie", refreshCookieName+"=unavailable-refresh; Path=/api/v1/auth; HttpOnly")
			_, _ = io.WriteString(writer, `{"data":{"user":{"userId":"user-1","userName":"Ada","email":"ada@example.com"},"tokens":{"accessToken":"access-1","refreshToken":"unavailable-refresh"}}}`)
		case "/api/v1/auth/refresh":
			refreshCookie = request.Header.Get("Cookie")
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(writer, `{"error":{"code":"unauthorized"}}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer upstream.Close()
	host, err := newAppHost(http.NotFoundHandler(), upstream.URL, nil, false, "test", AppInfo{}, ring)
	if err != nil {
		t.Fatal(err)
	}

	login := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{}`))
	login.Header.Set("Origin", "wails://localhost")
	loginResponse := httptest.NewRecorder()
	host.ServeHTTP(loginResponse, login)
	if loginResponse.Code != http.StatusOK || strings.Contains(loginResponse.Body.String(), "refreshToken") ||
		strings.Contains(loginResponse.Body.String(), "unavailable-refresh") {
		t.Fatal("credential-store failure leaked or rejected the active login")
	}

	refresh := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(`{}`))
	refresh.Header.Set("Origin", "wails://localhost")
	refreshResponse := httptest.NewRecorder()
	host.ServeHTTP(refreshResponse, refresh)
	if refreshResponse.Code != http.StatusUnauthorized || refreshCookie != "" || !host.credentialsBlocked.Load() {
		t.Fatal("credential-store failure did not fail closed on restart refresh")
	}
}

func TestAppHostLateRefreshRejectionDoesNotClearNewCredential(t *testing.T) {
	ring := newMemoryKeyring()
	host, err := newAppHost(http.NotFoundHandler(), defaultServerURL, nil, false, "test", AppInfo{}, ring)
	if err != nil {
		t.Fatal(err)
	}
	target := host.target.Load()
	if err := ring.Set(sessionKeyringService, refreshCredentialAccount(target), "new-refresh"); err != nil {
		t.Fatal(err)
	}
	host.blockSession(target, "old-refresh")
	if host.credentialsBlocked.Load() {
		t.Fatal("late rejection blocked a newer session")
	}
	if stored, err := ring.Get(sessionKeyringService, refreshCredentialAccount(target)); err != nil || stored != "new-refresh" {
		t.Fatal("late rejection deleted a newer refresh credential")
	}
}

func TestAppHostLateRefreshSuccessDoesNotOverwriteNewCredential(t *testing.T) {
	ring := newMemoryKeyring()
	host, err := newAppHost(http.NotFoundHandler(), defaultServerURL, nil, false, "test", AppInfo{}, ring)
	if err != nil {
		t.Fatal(err)
	}
	target := host.target.Load()
	if err := ring.Set(sessionKeyringService, refreshCredentialAccount(target), "new-refresh"); err != nil {
		t.Fatal(err)
	}
	if host.markRefreshed(target, "old-refresh", "rotated-old-refresh") {
		t.Fatal("late refresh response was accepted after a newer login")
	}
	if stored, err := ring.Get(sessionKeyringService, refreshCredentialAccount(target)); err != nil || stored != "new-refresh" {
		t.Fatal("late refresh response overwrote the newer credential")
	}

	host.credentialsBlocked.Store(true)
	if host.markRefreshed(target, "new-refresh", "rotated-refresh") {
		t.Fatal("late refresh response reactivated a cleared session")
	}
}

func TestAppHostRejectsLateHTTPRefreshAfterNewLogin(t *testing.T) {
	ring := newMemoryKeyring()
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	var receivedRefreshCookie string
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/auth/refresh":
			receivedRefreshCookie = request.Header.Get("Cookie")
			close(refreshStarted)
			<-releaseRefresh
			writer.Header().Set("Set-Cookie", refreshCookieName+"=late-rotated-refresh; Path=/api/v1/auth; HttpOnly")
			_, _ = io.WriteString(writer, `{"data":{"user":{"userId":"user-1","userName":"Ada","email":"ada@example.com"},"tokens":{"accessToken":"late-access","refreshToken":"late-rotated-refresh"}}}`)
		case "/api/v1/auth/login":
			writer.Header().Set("Set-Cookie", refreshCookieName+"=new-login-refresh; Path=/api/v1/auth; HttpOnly")
			_, _ = io.WriteString(writer, `{"data":{"user":{"userId":"user-1","userName":"Ada","email":"ada@example.com"},"tokens":{"accessToken":"new-access","refreshToken":"new-login-refresh"}}}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer upstream.Close()
	host, err := newAppHost(http.NotFoundHandler(), upstream.URL, nil, false, "test", AppInfo{}, ring)
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Set(sessionKeyringService, refreshCredentialAccount(host.target.Load()), "old-refresh"); err != nil {
		t.Fatal(err)
	}

	refreshResponse := httptest.NewRecorder()
	refreshDone := make(chan struct{})
	go func() {
		defer close(refreshDone)
		request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(`{}`))
		request.Header.Set("Origin", "wails://localhost")
		host.ServeHTTP(refreshResponse, request)
	}()
	<-refreshStarted

	login := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{}`))
	login.Header.Set("Origin", "wails://localhost")
	loginResponse := httptest.NewRecorder()
	host.ServeHTTP(loginResponse, login)
	if loginResponse.Code != http.StatusOK {
		t.Fatalf("new login status = %d", loginResponse.Code)
	}
	close(releaseRefresh)
	<-refreshDone

	if receivedRefreshCookie != refreshCookieName+"=old-refresh" || refreshResponse.Code != http.StatusBadGateway ||
		strings.Contains(refreshResponse.Body.String(), "late-rotated-refresh") {
		t.Fatal("late HTTP refresh response was not rejected")
	}
	if stored, err := ring.Get(sessionKeyringService, refreshCredentialAccount(host.target.Load())); err != nil || stored != "new-login-refresh" {
		t.Fatal("late HTTP refresh response overwrote the new login credential")
	}
}
