package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type scopeTestSink struct {
	host *appHost
	seen []nativeUIScope
}

func (s *scopeTestSink) ServeHTTP(http.ResponseWriter, *http.Request) {}
func (s *scopeTestSink) setNativeUIScope(ctx context.Context, scope nativeUIScope) error {
	if _, ok := ctx.Deadline(); !ok {
		panic("scope notification has no deadline")
	}
	// Re-entering proves the callback does not hold the host authentication lock.
	_ = s.host.nativeUIScopeSnapshot()
	s.seen = append(s.seen, scope)
	return errors.New("isolated sink failure")
}

func TestNativeUIScopeVerifiedResponses(t *testing.T) {
	var user atomic.Value
	user.Store("account-A")
	var status atomic.Int64
	status.Store(http.StatusOK)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", refreshCookieName+"=private-refresh; HttpOnly; Path=/api/v1/auth")
		w.WriteHeader(int(status.Load()))
		fmt.Fprintf(w, `{"data":{"user":{"userId":%q},"tokens":{"accessToken":"private-access","refreshToken":"private-refresh"}}}`, user.Load().(string))
	}))
	defer upstream.Close()
	host, err := newAppHost(http.NotFoundHandler(), upstream.URL, nil, false, "test", AppInfo{}, newMemoryKeyring())
	if err != nil {
		t.Fatal(err)
	}
	sink := &scopeTestSink{host: host}
	host.setRuntimeAPI(sink)
	initial := host.nativeUIScopeSnapshot()
	if initial.Authenticated || initial.UserID != "" || initial.Epoch == "" || initial.Generation == 0 {
		t.Fatalf("unverified startup scope: %+v", initial)
	}
	call := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		host.ServeHTTP(w, newJSONRequest(http.MethodPost, path, `{}`))
		return w
	}
	if w := call("/api/v1/auth/login"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	authenticated := host.nativeUIScopeSnapshot()
	if !authenticated.Authenticated || authenticated.UserID != user.Load().(string) || authenticated.ServerURL != upstream.URL || authenticated.Generation <= initial.Generation {
		t.Fatalf("scope: %+v", authenticated)
	}
	if w := call("/api/v1/auth/refresh"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if scope := host.nativeUIScopeSnapshot(); scope != authenticated {
		t.Fatalf("normal refresh changed identity: %+v", scope)
	}
	user.Store("account-B")
	if w := call("/api/v1/auth/refresh"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if scope := host.nativeUIScopeSnapshot(); scope.UserID != user.Load().(string) || scope.Generation <= authenticated.Generation {
		t.Fatalf("changed user: %+v", scope)
	}
	user.Store(" ")
	if w := call("/api/v1/auth/refresh"); w.Code != 200 {
		t.Fatal("invalid native user broke ordinary auth", w.Code)
	}
	if host.nativeUIScopeSnapshot().Authenticated || host.credentialsBlocked.Load() {
		t.Fatal("invalid user must only disable native scope")
	}
	user.Store("account-B")
	if w := call("/api/v1/auth/login"); w.Code != 200 {
		t.Fatal(w.Code)
	}
	status.Store(http.StatusInternalServerError)
	if w := call("/api/v1/auth/logout"); w.Code != 500 {
		t.Fatal(w.Code)
	}
	if host.nativeUIScopeSnapshot().Authenticated || !host.credentialsBlocked.Load() {
		t.Fatal("failed remote logout preserved local identity")
	}
	status.Store(http.StatusOK)
	if w := call("/api/v1/auth/login"); w.Code != 200 {
		t.Fatal(w.Code)
	}
	status.Store(http.StatusForbidden)
	if w := call("/api/v1/auth/refresh"); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if host.nativeUIScopeSnapshot().Authenticated {
		t.Fatal("refresh rejection kept native identity")
	}
	encoded, _ := json.Marshal(authenticated)
	if strings.Contains(string(encoded), "private-") || strings.Contains(string(encoded), "token") {
		t.Fatal("snapshot leaked credentials")
	}
	if len(sink.seen) == 0 {
		t.Fatal("sink was not notified")
	}
}

func TestNativeUIScopeLateSameTargetAuthCannotRestoreCredentials(t *testing.T) {
	for _, path := range []string{"/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/auth/desktop/attempts/late/exchange"} {
		t.Run(path, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(started)
				<-release
				w.Header().Add("Set-Cookie", refreshCookieName+"=late-refresh; HttpOnly; Path=/api/v1/auth")
				io.WriteString(w, `{"data":{"user":{"userId":"old-account"},"tokens":{"accessToken":"late-access"}}}`)
			}))
			defer upstream.Close()
			var releaseOnce sync.Once
			releaseHandler := func() { releaseOnce.Do(func() { close(release) }) }
			defer releaseHandler()
			ring := newMemoryKeyring()
			host, err := newAppHost(http.NotFoundHandler(), upstream.URL, nil, false, "test", AppInfo{}, ring)
			if err != nil {
				t.Fatal(err)
			}
			target := host.target.Load()
			if !host.markAuthenticated(target, "first-refresh", "old-account", host.nativeUIScopeSnapshot().Generation) {
				t.Fatal("initial auth")
			}
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				w := httptest.NewRecorder()
				host.ServeHTTP(w, newJSONRequest(http.MethodPost, path, `{}`))
				done <- w
			}()
			<-started
			host.blockSession(target, "")
			if !host.markAuthenticated(target, "new-refresh", "new-account", host.nativeUIScopeSnapshot().Generation) {
				t.Fatal("new auth")
			}
			releaseHandler()
			if w := <-done; w.Code != http.StatusBadGateway {
				t.Fatalf("late response status %d", w.Code)
			}
			if s := host.nativeUIScopeSnapshot(); !s.Authenticated || s.UserID != "new-account" {
				t.Fatalf("late identity restored: %+v", s)
			}
			if token, _ := ring.Get(sessionKeyringService, refreshCredentialAccount(target)); token != "new-refresh" {
				t.Fatal("late response overwrote credential")
			}
		})
	}
}

func TestNativeUIScopeSwitchPrepareAndSaveFailure(t *testing.T) {
	for _, sameTarget := range []bool{true, false} {
		t.Run(fmt.Sprint(sameTarget), func(t *testing.T) {
			first := newHealthyServer(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path == "/api/v1/auth/logout" {
					w.WriteHeader(500)
					return true
				}
				return false
			})
			next := newHealthyServer(t, nil)
			switchURL := next.URL
			if sameTarget {
				switchURL = first.URL
			}
			blocked := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(blocked, []byte("x"), 0600); err != nil {
				t.Fatal(err)
			}
			host, err := newAppHost(http.NotFoundHandler(), first.URL, newConfigStore(filepath.Join(blocked, "config")), false, "test", AppInfo{}, newMemoryKeyring())
			if err != nil {
				t.Fatal(err)
			}
			oldTarget := host.target.Load()
			oldGeneration := host.nativeUIScopeSnapshot().Generation
			if !host.markAuthenticated(oldTarget, "initial", "account-A", oldGeneration) {
				t.Fatal("auth")
			}
			oldGeneration = host.nativeUIScopeSnapshot().Generation
			w := httptest.NewRecorder()
			host.ServeHTTP(w, newJSONRequest(http.MethodPost, hostPrefix+"/connections/switch", `{"serverUrl":"`+switchURL+`"}`))
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			if s := host.nativeUIScopeSnapshot(); s.Authenticated || s.Generation <= oldGeneration {
				t.Fatalf("prepare did not invalidate: %+v", s)
			}
			if host.markAuthenticated(oldTarget, "late", "account-A", oldGeneration) {
				t.Fatal("late prepare response accepted")
			}
			var response struct {
				Data pendingSwitch `json:"data"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			w = httptest.NewRecorder()
			host.ServeHTTP(w, newJSONRequest(http.MethodPost, hostPrefix+"/connections/activate", `{"activationToken":"`+response.Data.ActivationToken+`"}`))
			if w.Code != 500 || host.nativeUIScopeSnapshot().Authenticated || !host.credentialsBlocked.Load() {
				t.Fatal("save failure restored old session", w.Code)
			}
		})
	}
}

func TestVerifiedAuthUserIDRejectsInvalidIdentity(t *testing.T) {
	for _, body := range []string{`{}`, `{"data":{"user":null}}`, `{"data":{"user":{"userId":12}}}`, `{"data":{"user":{"userId":" "}}}`, `{"data":{"user":{"userId":"a\nb"}}}`} {
		if verifiedAuthUserID([]byte(body)) != "" {
			t.Fatal("accepted invalid user", body)
		}
	}
}

func TestNativeUIScopeLateProviderCannotRestoreAfterLogout(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var redirect string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/exchange") {
			close(started)
			<-release
			w.Header().Add("Set-Cookie", refreshCookieName+"=late-provider; HttpOnly; Path=/api/v1/auth")
			w.Header().Add("Set-Cookie", protocolAccessCookieName+"=late-access; HttpOnly; Path=/")
			io.WriteString(w, `{"data":{"user":{"userId":"old-account"},"tokens":{"accessToken":"late-access"}}}`)
		} else {
			var input struct {
				Redirect string `json:"redirectUri"`
			}
			json.NewDecoder(r.Body).Decode(&input)
			redirect = input.Redirect
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"data":{"attemptId":"attempt-late","authorizationUrl":"%s/api/v1/auth/desktop/attempts/attempt-late/start","expiresAt":%q}}`, upstreamURL(r), time.Now().Add(time.Minute).UTC().Format(time.RFC3339))
		}
	}))
	defer upstream.Close()
	ring := newMemoryKeyring()
	host, err := newAppHost(http.NotFoundHandler(), upstream.URL, nil, false, "test", AppInfo{}, ring)
	if err != nil {
		t.Fatal(err)
	}
	host.setOpenBrowserURL(func(string) error {
		response, err := http.Get(redirect + "?attempt=attempt-late&code=code")
		if err == nil {
			response.Body.Close()
		}
		return err
	})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		host.ServeHTTP(w, newJSONRequest(http.MethodPost, hostPrefix+"/auth/desktop/start", `{"providerId":"provider"}`))
		done <- w
	}()
	<-started
	host.blockSession(host.target.Load(), "")
	close(release)
	if w := <-done; w.Code != http.StatusConflict {
		t.Fatal("late provider accepted", w.Code, w.Body.String())
	}
	if host.nativeUIScopeSnapshot().Authenticated || !host.credentialsBlocked.Load() {
		t.Fatal("provider restored logged-out identity")
	}
	if _, err := ring.Get(sessionKeyringService, refreshCredentialAccount(host.target.Load())); !errors.Is(err, errTestKeyringNotFound) {
		t.Fatal("late provider wrote credential", err)
	}
}
