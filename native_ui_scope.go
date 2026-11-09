package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/opensoha/soha-app/internal/endpointservice"
)

type nativeUIScope = endpointservice.NativeUIScope
type nativeUIScopeSink interface {
	setNativeUIScope(context.Context, nativeUIScope) error
}
type authGenerationContextKey struct{}
type authResponseScope struct {
	generation uint64
	userID     string
}

var nativeEpochOnce sync.Once
var nativeEpoch string
var nativeEpochError error

func nativeUIProcessEpoch() (string, error) {
	nativeEpochOnce.Do(func() { nativeEpoch, nativeEpochError = randomToken(24) })
	return nativeEpoch, nativeEpochError
}

func authRequestGeneration(request *http.Request) uint64 {
	generation, _ := request.Context().Value(authGenerationContextKey{}).(uint64)
	return generation
}

func verifiedAuthUserID(body []byte) string {
	var envelope struct {
		Data struct {
			User struct {
				UserID string `json:"userId"`
			} `json:"user"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return ""
	}
	id := envelope.Data.User.UserID
	if id == "" || len(id) > 128 || !utf8.ValidString(id) || strings.TrimSpace(id) != id || strings.IndexFunc(id, unicode.IsControl) >= 0 {
		return ""
	}
	return id
}

// sessionMu owns scope and the credential generation as one authentication state.
func (h *appHost) invalidateNativeUIScopeLocked() {
	h.nativeScope.Generation++
	h.nativeScope.UserID = ""
	h.nativeScope.Authenticated = false
}

func (h *appHost) setAuthenticatedNativeUIScopeLocked(target *url.URL, userID string) {
	h.nativeScope.ServerURL = target.String()
	h.nativeScope.UserID = userID
	h.nativeScope.Authenticated = userID != ""
}

func (h *appHost) nativeUIScopeSnapshot() nativeUIScope {
	h.sessionMu.Lock()
	defer h.sessionMu.Unlock()
	return h.nativeScope
}

// The runtime may perform IPC: never call it while holding any host lock.
func (h *appHost) publishNativeUIScope() {
	scope := h.nativeUIScopeSnapshot()
	h.nativeMu.RLock()
	sink, ok := h.runtimeAPI.(nativeUIScopeSink)
	h.nativeMu.RUnlock()
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := sink.setNativeUIScope(ctx, scope); err != nil {
		appLog.Warn("native UI scope notification failed", "component", "session", "event", "app.session.native_scope_failed", "error_type", logErrorType(err))
	}
}
