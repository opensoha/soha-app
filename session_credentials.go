package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/zalando/go-keyring"
)

const (
	sessionKeyringService    = "com.opensoha.app.session"
	refreshCookieName        = "soha_refresh_token"
	protocolAccessCookieName = "soha_protocol_access_token"
)

type systemKeyring struct{}

func (systemKeyring) Set(service, user, password string) error {
	return keyring.Set(service, user, password)
}

func (systemKeyring) Get(service, user string) (string, error) {
	return keyring.Get(service, user)
}

func (systemKeyring) Delete(service, user string) error {
	return keyring.Delete(service, user)
}

func (systemKeyring) DeleteAll(service string) error {
	return keyring.DeleteAll(service)
}

func refreshCredentialAccount(target *url.URL) string {
	if target == nil {
		return ""
	}
	return target.String()
}

func targetRequiresSecureCookies(target *url.URL) bool {
	return target != nil && target.Scheme == "https"
}

func refreshTokenFromSetCookies(values []string, requireSecure bool) (string, error) {
	var token string
	for _, value := range values {
		cookie, err := http.ParseSetCookie(value)
		if err != nil {
			if strings.HasPrefix(value, refreshCookieName+"=") ||
				strings.HasPrefix(value, protocolAccessCookieName+"=") {
				return "", errContractMismatch
			}
			continue
		}
		if requireSecure &&
			(cookie.Name == refreshCookieName || cookie.Name == protocolAccessCookieName) && !cookie.Secure {
			return "", errContractMismatch
		}
		if cookie.Name != refreshCookieName {
			continue
		}
		if token != "" || cookie.Value == "" || cookie.MaxAge < 0 {
			return "", errContractMismatch
		}
		token = cookie.Value
	}
	if token == "" {
		return "", errContractMismatch
	}
	return token, nil
}

func requestRefreshToken(request *http.Request) string {
	if request == nil {
		return ""
	}
	cookie, err := request.Cookie(refreshCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (h *appHost) injectStoredRefreshCredential(request *http.Request, target *url.URL) {
	if request == nil || target == nil || requestRefreshToken(request) != "" {
		return
	}
	h.sessionMu.Lock()
	defer h.sessionMu.Unlock()
	if h.credentialsBlocked.Load() || target != h.target.Load() || h.credentialKeyring == nil {
		return
	}
	token, err := h.credentialKeyring.Get(sessionKeyringService, refreshCredentialAccount(target))
	if errors.Is(err, keyring.ErrNotFound) {
		return
	}
	if err != nil {
		appLog.Warn("session credential read failed", "component", "session", "event", "app.session.credential_read_failed", "error", err, "error_type", logErrorType(err))
		return
	}
	if token != "" {
		request.AddCookie(&http.Cookie{Name: refreshCookieName, Value: token})
	}
}

func (h *appHost) replaceRefreshCredentialLocked(target *url.URL, token string) {
	if h.credentialKeyring == nil || target == nil || token == "" {
		return
	}
	account := refreshCredentialAccount(target)
	if err := h.credentialKeyring.Set(sessionKeyringService, account, token); err == nil {
		return
	} else {
		appLog.Warn("session credential write failed", "component", "session", "event", "app.session.credential_write_failed", "error", err, "error_type", logErrorType(err))
	}
	if err := h.credentialKeyring.Delete(sessionKeyringService, account); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		appLog.Warn("session credential cleanup failed", "component", "session", "event", "app.session.credential_cleanup_failed", "error", err, "error_type", logErrorType(err))
	}
}

func (h *appHost) deleteRefreshCredentialLocked(target *url.URL) {
	if h.credentialKeyring == nil || target == nil {
		return
	}
	if err := h.credentialKeyring.Delete(sessionKeyringService, refreshCredentialAccount(target)); err != nil &&
		!errors.Is(err, keyring.ErrNotFound) {
		appLog.Warn("session credential deletion failed", "component", "session", "event", "app.session.credential_delete_failed", "error", err, "error_type", logErrorType(err))
	}
}

func (h *appHost) deleteRefreshCredential(target *url.URL) {
	h.sessionMu.Lock()
	h.deleteRefreshCredentialLocked(target)
	h.sessionMu.Unlock()
}

func (h *appHost) blockSession(target *url.URL, rejectedToken string) {
	if target == nil {
		return
	}
	h.sessionMu.Lock()
	defer h.sessionMu.Unlock()
	if target != h.target.Load() {
		return
	}
	if rejectedToken != "" && h.credentialKeyring != nil {
		stored, err := h.credentialKeyring.Get(sessionKeyringService, refreshCredentialAccount(target))
		if err == nil && stored != "" && !constantTimeEqual(stored, rejectedToken) {
			return
		}
		if err != nil && !errors.Is(err, keyring.ErrNotFound) {
			appLog.Warn("session credential read failed", "component", "session", "event", "app.session.credential_read_failed", "error", err, "error_type", logErrorType(err))
		}
	}
	h.deleteRefreshCredentialLocked(target)
	if h.config != nil {
		if err := h.config.Save(target.String(), true); err != nil {
			appLog.Error("cleared session state persistence failed", "component", "session", "event", "app.session.clear_persist_failed", "error", err, "error_type", logErrorType(err))
		}
	}
	h.credentialsBlocked.Store(true)
}

func (h *appHost) markRefreshed(requestTarget *url.URL, previousToken, nextToken string) bool {
	if requestTarget == nil || requestTarget != h.target.Load() {
		return false
	}
	h.sessionMu.Lock()
	defer h.sessionMu.Unlock()
	if requestTarget != h.target.Load() || h.credentialsBlocked.Load() {
		return false
	}
	if previousToken != "" && h.credentialKeyring != nil {
		stored, err := h.credentialKeyring.Get(sessionKeyringService, refreshCredentialAccount(requestTarget))
		if err == nil && stored != "" && !constantTimeEqual(stored, previousToken) {
			return false
		}
		if err != nil && !errors.Is(err, keyring.ErrNotFound) {
			appLog.Warn("session credential read failed", "component", "session", "event", "app.session.credential_read_failed", "error", err, "error_type", logErrorType(err))
		}
	}
	h.persistAuthenticatedLocked(requestTarget, nextToken)
	return true
}

func redactAuthRefreshToken(response *http.Response) error {
	if response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return errContractMismatch
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, desktopAuthMaxResponseBytes+1))
	_ = response.Body.Close()
	if err != nil || len(body) == 0 || len(body) > desktopAuthMaxResponseBytes {
		return errContractMismatch
	}

	var envelope map[string]json.RawMessage
	if json.Unmarshal(body, &envelope) != nil {
		return errContractMismatch
	}
	dataValue, ok := envelope["data"]
	if ok {
		var data map[string]json.RawMessage
		if json.Unmarshal(dataValue, &data) != nil {
			return errContractMismatch
		}
		if tokensValue, hasTokens := data["tokens"]; hasTokens {
			var tokens map[string]json.RawMessage
			if json.Unmarshal(tokensValue, &tokens) != nil {
				return errContractMismatch
			}
			if _, hasRefreshToken := tokens["refreshToken"]; hasRefreshToken {
				delete(tokens, "refreshToken")
				data["tokens"], err = json.Marshal(tokens)
				if err != nil {
					return errContractMismatch
				}
				envelope["data"], err = json.Marshal(data)
				if err != nil {
					return errContractMismatch
				}
				body, err = json.Marshal(envelope)
				if err != nil {
					return errContractMismatch
				}
			}
		}
	}

	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	response.Header.Set("Content-Length", strconv.Itoa(len(body)))
	response.Header.Del("Content-Encoding")
	return nil
}
