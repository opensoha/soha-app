package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

const (
	defaultDesktopAuthTimeout   = 10 * time.Minute
	desktopAuthMaxResponseBytes = 1 << 20
)

type desktopAuthStartRequest struct {
	ProviderID string `json:"providerId"`
}

type desktopAuthAttempt struct {
	AttemptID        string    `json:"attemptId"`
	AuthorizationURL string    `json:"authorizationUrl"`
	ExpiresAt        time.Time `json:"expiresAt"`
}

type desktopAuthCallback struct {
	AttemptID string
	Code      string
}

type desktopAuthExchange struct {
	Body      []byte
	Cookies   []string
	RequestID string
}

type desktopAuthError struct {
	Status  int
	Code    string
	Message string
}

func (e *desktopAuthError) Error() string { return e.Code }

func (h *appHost) handleDesktopAuth(writer http.ResponseWriter, request *http.Request) {
	if !validateHostMutation(writer, request) {
		return
	}
	var input desktopAuthStartRequest
	if err := decodeRequestJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", "A desktop login provider is required")
		return
	}
	providerID := strings.TrimSpace(input.ProviderID)
	if providerID == "" || providerID != input.ProviderID || len(providerID) > 128 {
		writeError(writer, http.StatusBadRequest, "invalid_request", "A desktop login provider is required")
		return
	}
	if !h.desktopAuthMu.TryLock() {
		writeError(writer, http.StatusConflict, "desktop_auth_in_progress", "Another desktop login is already in progress")
		return
	}
	defer h.desktopAuthMu.Unlock()
	if h.hasPendingSwitch() {
		writeError(writer, http.StatusServiceUnavailable, "server_switch_pending", "Server switch is pending")
		return
	}

	target := h.target.Load()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "desktop_auth_listener_unavailable", "Unable to start the desktop login callback")
		return
	}
	callbackPathToken, err := randomToken(24)
	if err != nil {
		_ = listener.Close()
		writeError(writer, http.StatusServiceUnavailable, "desktop_auth_unavailable", "Unable to prepare desktop login")
		return
	}
	codeVerifier, err := randomToken(32)
	if err != nil {
		_ = listener.Close()
		writeError(writer, http.StatusServiceUnavailable, "desktop_auth_unavailable", "Unable to prepare desktop login")
		return
	}
	callbackPath := "/callback/" + callbackPathToken
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d%s", listener.Addr().(*net.TCPAddr).Port, callbackPath)
	attempt, actionErr := h.createDesktopAuthAttempt(request.Context(), target, providerID, redirectURI, codeVerifier)
	if actionErr != nil {
		_ = listener.Close()
		writeDesktopAuthError(writer, actionErr)
		return
	}
	authorizationURL, err := validateDesktopAuthorizationURL(target, attempt.AttemptID, attempt.AuthorizationURL)
	if err != nil {
		_ = listener.Close()
		writeError(writer, http.StatusBadGateway, "desktop_auth_contract_mismatch", "Soha Server returned an invalid desktop login URL")
		return
	}

	callbacks := make(chan desktopAuthCallback, 1)
	serveErrors := make(chan error, 1)
	callbackServer := &http.Server{
		Handler:           newDesktopCallbackHandler(callbackPath, attempt.AttemptID, callbacks),
		ReadHeaderTimeout: 3 * time.Second,
		IdleTimeout:       3 * time.Second,
	}
	go func() {
		if err := callbackServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErrors <- err
		}
	}()
	defer func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = callbackServer.Shutdown(shutdownContext)
	}()

	h.nativeMu.RLock()
	openBrowser := h.openBrowserURL
	h.nativeMu.RUnlock()
	if openBrowser == nil || openBrowser(authorizationURL) != nil {
		writeError(writer, http.StatusServiceUnavailable, "desktop_auth_browser_unavailable", "Unable to open the system browser")
		return
	}

	wait := time.Until(attempt.ExpiresAt)
	if wait <= 0 || wait > h.desktopAuthTimeout {
		wait = h.desktopAuthTimeout
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case callback := <-callbacks:
		if target != h.target.Load() {
			writeError(writer, http.StatusConflict, "desktop_auth_server_changed", "Soha Server changed during desktop login")
			return
		}
		exchange, actionErr := h.exchangeDesktopAuth(request.Context(), target, callback, codeVerifier)
		if actionErr != nil {
			writeDesktopAuthError(writer, actionErr)
			return
		}
		refreshToken, err := refreshTokenFromSetCookies(exchange.Cookies, targetRequiresSecureCookies(target))
		if err != nil {
			writeError(writer, http.StatusBadGateway, "desktop_auth_contract_mismatch", "Invalid Soha Server desktop login response")
			return
		}
		if !h.markAuthenticated(target, refreshToken) {
			writeError(writer, http.StatusConflict, "desktop_auth_server_changed", "Soha Server changed during desktop login")
			return
		}
		for _, cookie := range exchange.Cookies {
			writer.Header().Add("Set-Cookie", cookie)
		}
		if exchange.RequestID != "" {
			writer.Header().Set("X-Request-ID", exchange.RequestID)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(exchange.Body)
	case <-timer.C:
		writeError(writer, http.StatusRequestTimeout, "desktop_auth_timeout", "Desktop login timed out")
	case <-request.Context().Done():
		writeError(writer, http.StatusRequestTimeout, "desktop_auth_cancelled", "Desktop login was cancelled")
	case <-serveErrors:
		writeError(writer, http.StatusServiceUnavailable, "desktop_auth_listener_unavailable", "Desktop login callback stopped unexpectedly")
	}
}

func (h *appHost) createDesktopAuthAttempt(
	ctx context.Context,
	target *url.URL,
	providerID string,
	redirectURI string,
	codeVerifier string,
) (desktopAuthAttempt, *desktopAuthError) {
	payload, err := json.Marshal(map[string]string{
		"providerId":          providerID,
		"redirectUri":         redirectURI,
		"codeChallenge":       desktopCodeChallenge(codeVerifier),
		"codeChallengeMethod": "S256",
	})
	if err != nil {
		return desktopAuthAttempt{}, newDesktopAuthError(http.StatusInternalServerError, "desktop_auth_unavailable", "Unable to prepare desktop login")
	}
	requestURL := *target
	requestURL.Path = "/api/v1/auth/desktop/attempts"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader(payload))
	if err != nil {
		return desktopAuthAttempt{}, newDesktopAuthError(http.StatusInternalServerError, "desktop_auth_unavailable", "Unable to prepare desktop login")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", newRequestID())
	response, err := h.client.Do(request)
	if err != nil {
		return desktopAuthAttempt{}, newDesktopAuthError(http.StatusBadGateway, "upstream_unavailable", "Soha Server is unavailable")
	}
	defer response.Body.Close()
	body, err := readDesktopAuthBody(response.Body)
	if err != nil {
		return desktopAuthAttempt{}, newDesktopAuthError(http.StatusBadGateway, "desktop_auth_contract_mismatch", "Invalid Soha Server desktop login response")
	}
	if response.StatusCode != http.StatusCreated {
		return desktopAuthAttempt{}, desktopAuthResponseError(response.StatusCode, body, "desktop_auth_create_failed", "Unable to create desktop login")
	}
	var envelope struct {
		Data desktopAuthAttempt `json:"data"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Data.AttemptID == "" || envelope.Data.AuthorizationURL == "" || envelope.Data.ExpiresAt.IsZero() {
		return desktopAuthAttempt{}, newDesktopAuthError(http.StatusBadGateway, "desktop_auth_contract_mismatch", "Invalid Soha Server desktop login response")
	}
	return envelope.Data, nil
}

func (h *appHost) exchangeDesktopAuth(
	ctx context.Context,
	target *url.URL,
	callback desktopAuthCallback,
	codeVerifier string,
) (desktopAuthExchange, *desktopAuthError) {
	payload, err := json.Marshal(map[string]string{"code": callback.Code, "codeVerifier": codeVerifier})
	if err != nil {
		return desktopAuthExchange{}, newDesktopAuthError(http.StatusInternalServerError, "desktop_auth_unavailable", "Unable to complete desktop login")
	}
	requestURL := *target
	requestURL.Path = "/api/v1/auth/desktop/attempts/" + url.PathEscape(callback.AttemptID) + "/exchange"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader(payload))
	if err != nil {
		return desktopAuthExchange{}, newDesktopAuthError(http.StatusInternalServerError, "desktop_auth_unavailable", "Unable to complete desktop login")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", newRequestID())
	response, err := h.client.Do(request)
	if err != nil {
		return desktopAuthExchange{}, newDesktopAuthError(http.StatusBadGateway, "upstream_unavailable", "Soha Server is unavailable")
	}
	defer response.Body.Close()
	body, err := readDesktopAuthBody(response.Body)
	if err != nil {
		return desktopAuthExchange{}, newDesktopAuthError(http.StatusBadGateway, "desktop_auth_contract_mismatch", "Invalid Soha Server desktop login response")
	}
	if response.StatusCode != http.StatusOK {
		return desktopAuthExchange{}, desktopAuthResponseError(response.StatusCode, body, "desktop_auth_exchange_failed", "Unable to complete desktop login")
	}
	var envelope struct {
		Data struct {
			User   json.RawMessage `json:"user"`
			Tokens struct {
				AccessToken string `json:"accessToken"`
			} `json:"tokens"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &envelope) != nil || len(envelope.Data.User) == 0 || envelope.Data.Tokens.AccessToken == "" {
		return desktopAuthExchange{}, newDesktopAuthError(http.StatusBadGateway, "desktop_auth_contract_mismatch", "Invalid Soha Server desktop login response")
	}
	body, err = json.Marshal(envelope)
	if err != nil {
		return desktopAuthExchange{}, newDesktopAuthError(http.StatusBadGateway, "desktop_auth_contract_mismatch", "Invalid Soha Server desktop login response")
	}
	cookies, err := sanitizeDesktopAuthCookies(
		response.Header.Values("Set-Cookie"),
		targetRequiresSecureCookies(target),
	)
	if err != nil {
		return desktopAuthExchange{}, newDesktopAuthError(http.StatusBadGateway, "desktop_auth_contract_mismatch", "Invalid Soha Server desktop login response")
	}
	return desktopAuthExchange{
		Body:      body,
		Cookies:   cookies,
		RequestID: response.Header.Get("X-Request-ID"),
	}, nil
}

func newDesktopCallbackHandler(path, attemptID string, callbacks chan<- desktopAuthCallback) http.Handler {
	var received atomic.Bool
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		remoteHost, _, err := net.SplitHostPort(request.RemoteAddr)
		if request.Method != http.MethodGet || request.URL.Path != path || err != nil || remoteHost != "127.0.0.1" {
			http.Error(writer, "Invalid desktop login callback", http.StatusBadRequest)
			return
		}
		query, err := url.ParseQuery(request.URL.RawQuery)
		if err != nil || len(query) != 2 || len(query["attempt"]) != 1 || len(query["code"]) != 1 {
			http.Error(writer, "Invalid desktop login callback", http.StatusBadRequest)
			return
		}
		callback := desktopAuthCallback{AttemptID: query.Get("attempt"), Code: query.Get("code")}
		if !constantTimeEqual(callback.AttemptID, attemptID) || callback.Code == "" || len(callback.Code) > 512 {
			http.Error(writer, "Invalid desktop login callback", http.StatusBadRequest)
			return
		}
		if !received.CompareAndSwap(false, true) {
			http.Error(writer, "Desktop login callback was already received", http.StatusConflict)
			return
		}
		select {
		case callbacks <- callback:
			writer.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(writer, "Authentication complete. You may return to Soha.")
		default:
			http.Error(writer, "Desktop login callback was already received", http.StatusConflict)
		}
	})
}

func sanitizeDesktopAuthCookies(values []string, requireSecure bool) ([]string, error) {
	expectedPaths := map[string]string{
		refreshCookieName:        "/api/v1/auth",
		protocolAccessCookieName: "/",
	}
	seen := make(map[string]bool, len(expectedPaths))
	cookies := make([]string, 0, len(expectedPaths))
	for _, value := range values {
		cookie, err := http.ParseSetCookie(value)
		if err != nil {
			return nil, err
		}
		path, allowed := expectedPaths[cookie.Name]
		if !allowed {
			continue
		}
		if seen[cookie.Name] || cookie.Value == "" {
			return nil, errors.New("invalid desktop auth cookie")
		}
		if requireSecure && !cookie.Secure {
			return nil, errors.New("insecure desktop auth cookie")
		}
		seen[cookie.Name] = true
		cookie.Path = path
		cookie.Domain = ""
		cookie.HttpOnly = true
		cookie.SameSite = http.SameSiteLaxMode
		cookie.Partitioned = false
		cookie.Raw = ""
		cookie.Unparsed = nil
		cookies = append(cookies, cookie.String())
	}
	if len(seen) != len(expectedPaths) {
		return nil, errors.New("missing desktop auth cookie")
	}
	return cookies, nil
}

func validateDesktopAuthorizationURL(target *url.URL, attemptID, rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	expectedPath := "/api/v1/auth/desktop/attempts/" + url.PathEscape(attemptID) + "/start"
	if err != nil || target == nil || attemptID == "" || len(attemptID) > 128 || parsed.Scheme != target.Scheme ||
		parsed.Host != target.Host || parsed.User != nil || parsed.Opaque != "" || parsed.EscapedPath() != expectedPath ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", errors.New("invalid desktop authorization URL")
	}
	return parsed.String(), nil
}

func desktopCodeChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func readDesktopAuthBody(reader io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, desktopAuthMaxResponseBytes+1))
	if err != nil || len(body) == 0 || len(body) > desktopAuthMaxResponseBytes {
		return nil, errors.New("invalid desktop auth response")
	}
	return body, nil
}

func desktopAuthResponseError(status int, _ []byte, fallbackCode, fallbackMessage string) *desktopAuthError {
	if status < http.StatusBadRequest || status > 599 {
		status = http.StatusBadGateway
	}
	return newDesktopAuthError(status, fallbackCode, fallbackMessage)
}

func newDesktopAuthError(status int, code, message string) *desktopAuthError {
	return &desktopAuthError{Status: status, Code: code, Message: message}
}

func writeDesktopAuthError(writer http.ResponseWriter, err *desktopAuthError) {
	writeError(writer, err.Status, err.Code, err.Message)
}
