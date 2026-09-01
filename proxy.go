package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zalando/go-keyring"
)

const (
	apiPrefix                      = "/api/v1"
	hostPrefix                     = "/app/v1"
	wailsRequestBodyHeader         = "X-Soha-App-Body"
	maxWailsRequestBodySize        = 64 << 10
	connectionProbeMaxResponseSize = 1 << 20
	proxyJSONMaxRequestSize        = 1 << 20
)

var errContractMismatch = errors.New("server response contract mismatch")

type connectionStatus string

const (
	connectionOnline       connectionStatus = "online"
	connectionNotReady     connectionStatus = "not_ready"
	connectionOffline      connectionStatus = "offline"
	connectionTLSError     connectionStatus = "tls_error"
	connectionIncompatible connectionStatus = "incompatible"
)

type connectionCheck struct {
	Status    connectionStatus `json:"status"`
	ServerURL string           `json:"serverUrl"`
	Code      string           `json:"code,omitempty"`
}

type AppInfo struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	Platform        string `json:"platform"`
	Arch            string `json:"arch"`
	LogDirectory    string `json:"logDirectory"`
	UpdateSupported bool   `json:"updateSupported"`
	UpdateState     string `json:"updateState,omitempty"`
}

type hostState struct {
	ServerURL            string  `json:"serverUrl"`
	ConfigurationSource  string  `json:"configurationSource"`
	ManagedByEnvironment bool    `json:"managedByEnvironment"`
	App                  AppInfo `json:"app"`
}

type appHost struct {
	static             http.Handler
	proxy              *httputil.ReverseProxy
	target             atomic.Pointer[url.URL]
	client             *http.Client
	config             *configStore
	locked             bool
	appInfo            AppInfo
	stateMu            sync.RWMutex
	source             string
	pendingMu          sync.Mutex
	pending            *url.URL
	pendingCode        string
	sessionMu          sync.Mutex
	credentialsBlocked atomic.Bool
	credentialKeyring  keyring.Keyring
	desktopAuthMu      sync.Mutex
	desktopAuthTimeout time.Duration
	rendererReady      sync.Once
	nativeMu           sync.RWMutex
	openLogDirectory   func() error
	openBrowserURL     func(string) error
	runtimeAPI         http.Handler
}

type proxyTargetContextKey struct{}

func newAppHost(
	static http.Handler,
	rawServerURL string,
	config *configStore,
	locked bool,
	source string,
	info AppInfo,
	credentialKeyring keyring.Keyring,
) (*appHost, error) {
	normalized, err := normalizeServerURL(rawServerURL)
	if err != nil {
		return nil, fmt.Errorf("invalid SOHA_SERVER_URL: %w", err)
	}
	target, err := url.Parse(normalized)
	if err != nil {
		return nil, fmt.Errorf("parse normalized server URL: %w", err)
	}

	host := &appHost{
		static:             static,
		client:             newHostHTTPClient(),
		config:             config,
		locked:             locked,
		appInfo:            info,
		source:             source,
		credentialKeyring:  credentialKeyring,
		desktopAuthTimeout: defaultDesktopAuthTimeout,
	}
	host.target.Store(target)
	host.proxy = host.newReverseProxy()
	return host, nil
}

func newHostHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 6 * time.Second
	transport.TLSHandshakeTimeout = 6 * time.Second
	return &http.Client{
		Transport: transport,
		Timeout:   8 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (h *appHost) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	isAppRequest := request.URL.Path == apiPrefix || strings.HasPrefix(request.URL.Path, apiPrefix+"/") ||
		request.URL.Path == hostPrefix || strings.HasPrefix(request.URL.Path, hostPrefix+"/")
	if isAppRequest {
		requestID := newRequestID()
		request.Header.Set("X-Request-ID", requestID)
		writer.Header().Set("X-Request-ID", requestID)
		if err := restoreWailsRequestBody(request); err != nil {
			writeError(writer, http.StatusBadRequest, "invalid_request_body", "Request body is invalid")
			return
		}
	}
	switch {
	case request.URL.Path == hostPrefix+"/state":
		h.handleState(writer, request)
	case request.URL.Path == hostPrefix+"/connections/check":
		h.handleConnectionCheck(writer, request)
	case request.URL.Path == hostPrefix+"/connections/switch":
		h.handleConnectionSwitch(writer, request)
	case request.URL.Path == hostPrefix+"/connections/activate":
		h.handleConnectionActivate(writer, request)
	case request.URL.Path == hostPrefix+"/session/clear":
		h.handleSessionClear(writer, request)
	case request.URL.Path == hostPrefix+"/logs/open":
		h.handleOpenLogDirectory(writer, request)
	case request.URL.Path == hostPrefix+"/browser/open":
		h.handleOpenBrowser(writer, request)
	case request.URL.Path == hostPrefix+"/auth/desktop/start":
		h.handleDesktopAuth(writer, request)
	case request.URL.Path == hostPrefix || strings.HasPrefix(request.URL.Path, hostPrefix+"/"):
		if !isTrustedAppRequest(request) {
			writeError(writer, http.StatusForbidden, "untrusted_origin", "Request origin is not allowed")
			return
		}
		if h.runtimeAPI == nil {
			writeError(writer, http.StatusNotFound, "runtime_not_found", "Desktop runtime endpoint is unavailable")
			return
		}
		h.runtimeAPI.ServeHTTP(writer, request)
	case request.URL.Path == apiPrefix || strings.HasPrefix(request.URL.Path, apiPrefix+"/"):
		h.handleAPI(writer, request)
	default:
		setStaticSecurityHeaders(writer.Header())
		h.static.ServeHTTP(writer, request)
	}
}

func restoreWailsRequestBody(request *http.Request) error {
	encoded := request.Header.Get(wailsRequestBodyHeader)
	if encoded == "" {
		return nil
	}
	request.Header.Del(wailsRequestBodyHeader)
	if len(encoded) > maxWailsRequestBodySize*3 {
		return errors.New("encoded request body is too large")
	}
	body, err := url.PathUnescape(encoded)
	if err != nil {
		return fmt.Errorf("decode request body: %w", err)
	}
	if len(body) > maxWailsRequestBodySize {
		return errors.New("request body is too large")
	}
	request.Body = io.NopCloser(strings.NewReader(body))
	request.ContentLength = int64(len(body))
	return nil
}

func (h *appHost) setOpenLogDirectory(open func() error) {
	h.nativeMu.Lock()
	h.openLogDirectory = open
	h.nativeMu.Unlock()
}

func (h *appHost) setOpenBrowserURL(open func(string) error) {
	h.nativeMu.Lock()
	h.openBrowserURL = open
	h.nativeMu.Unlock()
}

func (h *appHost) setRuntimeAPI(runtimeAPI http.Handler) {
	h.runtimeAPI = runtimeAPI
}

func (h *appHost) currentState() hostState {
	h.stateMu.RLock()
	source := h.source
	h.stateMu.RUnlock()
	return hostState{
		ServerURL:            h.target.Load().String(),
		ConfigurationSource:  source,
		ManagedByEnvironment: h.locked,
		App:                  h.appInfo,
	}
}

func (h *appHost) hasPendingSwitch() bool {
	h.pendingMu.Lock()
	defer h.pendingMu.Unlock()
	return h.pending != nil
}

func (h *appHost) handleAPI(writer http.ResponseWriter, request *http.Request) {
	if !isTrustedAppRequest(request) {
		writeError(writer, http.StatusForbidden, "untrusted_origin", "Request origin is not allowed")
		return
	}
	if h.hasPendingSwitch() {
		writeError(writer, http.StatusServiceUnavailable, "server_switch_pending", "Server switch is pending")
		return
	}
	mediaType, _, _ := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if request.Body != nil && mediaType == "application/json" {
		payload, err := io.ReadAll(io.LimitReader(request.Body, proxyJSONMaxRequestSize+1))
		if err != nil {
			writeError(writer, http.StatusBadRequest, "invalid_request", "Unable to read request body")
			return
		}
		if len(payload) > proxyJSONMaxRequestSize {
			writeError(writer, http.StatusRequestEntityTooLarge, "payload_too_large", "Request body exceeds the desktop limit")
			return
		}
		_ = request.Body.Close()
		request.Body = io.NopCloser(bytes.NewReader(payload))
		request.ContentLength = int64(len(payload))
		request.TransferEncoding = nil
	}
	request = request.WithContext(context.WithValue(request.Context(), proxyTargetContextKey{}, h.target.Load()))
	h.proxy.ServeHTTP(writer, request)
}

func (h *appHost) handleState(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeMethodNotAllowed(writer, http.MethodGet)
		return
	}
	if request.Header.Get("X-Wails-Window-Id") != "" {
		h.rendererReady.Do(func() {
			appLog.Info("renderer ready", "component", "renderer", "event", "app.renderer.ready")
		})
	}
	writeData(writer, http.StatusOK, h.currentState())
}

type serverURLRequest struct {
	ServerURL string `json:"serverUrl"`
}

func (h *appHost) handleConnectionCheck(writer http.ResponseWriter, request *http.Request) {
	if !validateHostMutation(writer, request) {
		return
	}
	var input serverURLRequest
	if err := decodeRequestJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", "A valid server URL is required")
		return
	}
	check := h.checkServer(request.Context(), input.ServerURL)
	writeData(writer, http.StatusOK, check)
}

type pendingSwitch struct {
	ActivationToken string          `json:"activationToken"`
	Connection      connectionCheck `json:"connection"`
}

func (h *appHost) handleConnectionSwitch(writer http.ResponseWriter, request *http.Request) {
	if !validateHostMutation(writer, request) {
		return
	}
	if h.locked {
		writeError(writer, http.StatusConflict, "configuration_managed", "Server URL is managed by the environment")
		return
	}
	if h.config == nil {
		writeError(writer, http.StatusNotImplemented, "configuration_unavailable", "Server configuration is unavailable")
		return
	}
	oldTarget := h.target.Load()

	var input serverURLRequest
	if err := decodeRequestJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", "A valid server URL is required")
		return
	}
	check := h.checkServer(request.Context(), input.ServerURL)
	if check.Status != connectionOnline {
		writeData(writer, http.StatusUnprocessableEntity, check)
		return
	}
	target, err := url.Parse(check.ServerURL)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_server_url", "Server URL is invalid")
		return
	}
	activationToken, err := randomToken(24)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "host_unavailable", "Unable to prepare server switch")
		return
	}

	h.pendingMu.Lock()
	if h.pending != nil || oldTarget != h.target.Load() {
		h.pendingMu.Unlock()
		writeError(writer, http.StatusConflict, "server_switch_pending", "A server switch is already pending")
		return
	}
	h.pending = target
	h.pendingCode = activationToken
	h.pendingMu.Unlock()
	h.logoutOldServer(request, oldTarget)
	h.deleteRefreshCredential(oldTarget)
	clearAuthCookies(writer, targetRequiresSecureCookies(oldTarget))
	writeData(writer, http.StatusOK, pendingSwitch{
		ActivationToken: activationToken,
		Connection:      check,
	})
}

type activationRequest struct {
	ActivationToken string `json:"activationToken"`
}

func (h *appHost) handleConnectionActivate(writer http.ResponseWriter, request *http.Request) {
	if !validateHostMutation(writer, request) {
		return
	}
	var input activationRequest
	if err := decodeRequestJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", "Activation token is required")
		return
	}

	h.pendingMu.Lock()
	defer h.pendingMu.Unlock()
	if h.pending == nil || !constantTimeEqual(input.ActivationToken, h.pendingCode) {
		writeError(writer, http.StatusConflict, "switch_not_pending", "No matching server switch is pending")
		return
	}
	h.sessionMu.Lock()
	defer h.sessionMu.Unlock()
	oldTarget := h.target.Load()
	if err := h.config.Save(h.pending.String(), true); err != nil {
		h.credentialsBlocked.Store(true)
		h.pending = nil
		h.pendingCode = ""
		clearAuthCookies(writer, targetRequiresSecureCookies(oldTarget))
		writeError(writer, http.StatusInternalServerError, "configuration_write_failed", "Unable to save server configuration")
		return
	}
	h.credentialsBlocked.Store(true)
	h.target.Store(h.pending)
	h.pending = nil
	h.pendingCode = ""
	h.stateMu.Lock()
	h.source = "saved"
	h.stateMu.Unlock()
	clearAuthCookies(writer, targetRequiresSecureCookies(oldTarget))
	writeData(writer, http.StatusOK, h.currentState())
}

func (h *appHost) handleSessionClear(writer http.ResponseWriter, request *http.Request) {
	if !validateHostMutation(writer, request) {
		return
	}
	h.blockSession(h.target.Load(), "")
	clearAuthCookies(writer, targetRequiresSecureCookies(h.target.Load()))
	writeData(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *appHost) handleOpenLogDirectory(writer http.ResponseWriter, request *http.Request) {
	if !validateHostMutation(writer, request) {
		return
	}
	var input struct{}
	if err := decodeRequestJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", "Request body must be an empty JSON object")
		return
	}
	h.nativeMu.RLock()
	open := h.openLogDirectory
	h.nativeMu.RUnlock()
	if open == nil || open() != nil {
		writeError(writer, http.StatusServiceUnavailable, "native_action_unavailable", "Unable to open the log directory")
		return
	}
	writeData(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *appHost) handleOpenBrowser(writer http.ResponseWriter, request *http.Request) {
	if !validateHostMutation(writer, request) {
		return
	}
	var input struct {
		URL string `json:"url"`
	}
	if err := decodeRequestJSON(request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", "A valid browser URL is required")
		return
	}
	rawURL := strings.TrimSpace(input.URL)
	parsed, err := url.Parse(rawURL)
	if err != nil || rawURL != input.URL || len(rawURL) > 4096 || parsed.Opaque != "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.User != nil {
		writeError(writer, http.StatusBadRequest, "invalid_url", "Only absolute HTTP and HTTPS URLs are allowed")
		return
	}
	h.nativeMu.RLock()
	open := h.openBrowserURL
	h.nativeMu.RUnlock()
	if open == nil || open(rawURL) != nil {
		writeError(writer, http.StatusServiceUnavailable, "native_action_unavailable", "Unable to open the browser")
		return
	}
	writeData(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *appHost) checkServer(ctx context.Context, rawServerURL string) connectionCheck {
	normalized, err := normalizeServerURL(rawServerURL)
	if err != nil {
		return connectionCheck{
			Status: connectionIncompatible,
			Code:   "invalid_server_url",
		}
	}
	target, err := url.Parse(normalized)
	if err != nil {
		return connectionCheck{
			Status:    connectionIncompatible,
			ServerURL: normalized,
			Code:      "invalid_server_url",
		}
	}
	check := connectionCheck{Status: connectionOnline, ServerURL: normalized}

	var health struct {
		Status string `json:"status"`
	}
	status, err := h.getJSON(ctx, target, "/api/v1/healthz", &health)
	if status == http.StatusServiceUnavailable {
		check.Status = connectionNotReady
		check.Code = "server_not_ready"
		return check
	}
	if status >= http.StatusInternalServerError {
		check.Status = connectionOffline
		check.Code = "upstream_unavailable"
		return check
	}
	if err != nil {
		check.Status, check.Code = classifyConnectionError(err)
		return check
	}
	if health.Status == "degraded" {
		check.Status = connectionNotReady
		check.Code = "server_not_ready"
		return check
	}
	if status != http.StatusOK || health.Status != "ok" {
		check.Status = connectionIncompatible
		check.Code = "health_contract_mismatch"
		return check
	}

	var readiness struct {
		Status string `json:"status"`
	}
	status, err = h.getJSON(ctx, target, "/api/v1/readyz", &readiness)
	if status == http.StatusServiceUnavailable {
		check.Status = connectionNotReady
		check.Code = "server_not_ready"
		return check
	}
	if status >= http.StatusInternalServerError {
		check.Status = connectionOffline
		check.Code = "upstream_unavailable"
		return check
	}
	if err != nil {
		check.Status, check.Code = classifyConnectionError(err)
		return check
	}
	if status != http.StatusOK || readiness.Status != "ready" {
		check.Status = connectionIncompatible
		check.Code = "readiness_contract_mismatch"
		return check
	}

	var options struct {
		Data struct {
			Verification struct {
				SliderEnabled *bool `json:"sliderEnabled"`
			} `json:"verification"`
		} `json:"data"`
	}
	status, err = h.getJSON(ctx, target, "/api/v1/auth/login-options", &options)
	if status == http.StatusServiceUnavailable {
		check.Status = connectionNotReady
		check.Code = "server_not_ready"
		return check
	}
	if status >= http.StatusInternalServerError {
		check.Status = connectionOffline
		check.Code = "upstream_unavailable"
		return check
	}
	if err != nil {
		check.Status, check.Code = classifyConnectionError(err)
		return check
	}
	if status != http.StatusOK || options.Data.Verification.SliderEnabled == nil {
		check.Status = connectionIncompatible
		check.Code = "login_contract_mismatch"
		return check
	}

	return check
}

func (h *appHost) getJSON(ctx context.Context, target *url.URL, path string, output any) (int, error) {
	requestURL := *target
	requestURL.Path = path
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := h.client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusServiceUnavailable {
		return response.StatusCode, nil
	}

	limited := &io.LimitedReader{R: response.Body, N: connectionProbeMaxResponseSize + 1}
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(output); err != nil {
		return response.StatusCode, errContractMismatch
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return response.StatusCode, errContractMismatch
	}
	if limited.N == 0 {
		return response.StatusCode, errContractMismatch
	}
	return response.StatusCode, nil
}

func (h *appHost) logoutOldServer(incoming *http.Request, target *url.URL) {
	if target == nil {
		return
	}
	requestURL := *target
	requestURL.Path = "/api/v1/auth/logout"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), strings.NewReader("{}"))
	if err != nil {
		return
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if authorization := incoming.Header.Get("Authorization"); authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	if cookie := incoming.Header.Get("Cookie"); cookie != "" {
		request.Header.Set("Cookie", cookie)
	}
	h.injectStoredRefreshCredential(request, target)
	response, err := h.client.Do(request)
	if err == nil {
		_ = response.Body.Close()
	}
}

func (h *appHost) newReverseProxy() *httputil.ReverseProxy {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.TLSHandshakeTimeout = 8 * time.Second
	return &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(proxyRequest *httputil.ProxyRequest) {
			target, _ := proxyRequest.In.Context().Value(proxyTargetContextKey{}).(*url.URL)
			if target == nil {
				target = h.target.Load()
			}
			proxyRequest.SetURL(target)
			proxyRequest.Out.Host = target.Host
			for _, header := range []string{
				"Forwarded",
				"X-Forwarded-For",
				"X-Forwarded-Host",
				"X-Forwarded-Port",
				"X-Forwarded-Proto",
			} {
				proxyRequest.Out.Header.Del(header)
			}
			proxyRequest.SetXForwarded()
			proxyRequest.Out.Header.Set("X-Forwarded-Host", target.Host)
			proxyRequest.Out.Header.Set("X-Forwarded-Proto", target.Scheme)
			proxyRequest.Out.Header.Del("Origin")
			isAuthSessionRequest := proxyRequest.Out.Method == http.MethodPost &&
				(proxyRequest.Out.URL.Path == "/api/v1/auth/login" ||
					proxyRequest.Out.URL.Path == "/api/v1/auth/refresh" ||
					(strings.HasPrefix(proxyRequest.Out.URL.Path, "/api/v1/auth/desktop/attempts/") &&
						strings.HasSuffix(proxyRequest.Out.URL.Path, "/exchange")))
			if isAuthSessionRequest {
				proxyRequest.Out.Header.Set("Accept-Encoding", "identity")
			}
			if h.credentialsBlocked.Load() {
				proxyRequest.Out.Header.Del("Authorization")
				proxyRequest.Out.Header.Del("Cookie")
				return
			}
			if proxyRequest.Out.Method == http.MethodPost &&
				(proxyRequest.Out.URL.Path == "/api/v1/auth/refresh" || proxyRequest.Out.URL.Path == "/api/v1/auth/logout") {
				h.injectStoredRefreshCredential(proxyRequest.Out, target)
			}
		},
		ModifyResponse: h.modifyProxyResponse,
		ErrorHandler: func(writer http.ResponseWriter, request *http.Request, proxyErr error) {
			appLog.Error("Soha server is unavailable", "component", "http_proxy", "event", "app.proxy.upstream_unavailable", "request_id", request.Header.Get("X-Request-ID"), "error", proxyErr, "error_type", logErrorType(proxyErr))
			writeError(writer, http.StatusBadGateway, "upstream_unavailable", "Soha server is unavailable")
		},
	}
}

func (h *appHost) modifyProxyResponse(response *http.Response) error {
	request := response.Request
	if request == nil {
		return errContractMismatch
	}
	requestTarget, _ := request.Context().Value(proxyTargetContextKey{}).(*url.URL)
	if requestTarget == nil || requestTarget != h.target.Load() {
		return errContractMismatch
	}
	if err := rejectUpstreamRedirect(response); err != nil {
		return err
	}
	if event := proxyRejectionEvent(request, response.StatusCode); event != "" {
		appLog.Warn("upstream request rejected", "component", "http_proxy", "event", "app.proxy.rejected", "reason", event, "status", response.StatusCode, "request_id", request.Header.Get("X-Request-ID"))
	}
	isPasswordLogin := request.Method == http.MethodPost && request.URL.Path == "/api/v1/auth/login"
	isRefresh := request.Method == http.MethodPost && request.URL.Path == "/api/v1/auth/refresh"
	isLogout := request.Method == http.MethodPost && request.URL.Path == "/api/v1/auth/logout"
	isDesktopExchange := request.Method == http.MethodPost &&
		strings.HasPrefix(request.URL.Path, "/api/v1/auth/desktop/attempts/") &&
		strings.HasSuffix(request.URL.Path, "/exchange")
	if isRefresh && (response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden) {
		h.blockSession(requestTarget, requestRefreshToken(request))
		clearAuthCookieHeaders(response.Header, targetRequiresSecureCookies(requestTarget))
		return nil
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil
	}
	if isLogout {
		h.blockSession(requestTarget, "")
		clearAuthCookieHeaders(response.Header, targetRequiresSecureCookies(requestTarget))
		return nil
	}
	if isPasswordLogin || isRefresh || isDesktopExchange {
		refreshToken, err := refreshTokenFromSetCookies(
			response.Header.Values("Set-Cookie"),
			targetRequiresSecureCookies(requestTarget),
		)
		if err != nil {
			return err
		}
		if err := redactAuthRefreshToken(response); err != nil {
			return err
		}
		if isRefresh {
			if !h.markRefreshed(requestTarget, requestRefreshToken(request), refreshToken) {
				return errContractMismatch
			}
		} else if !h.markAuthenticated(requestTarget, refreshToken) {
			return errContractMismatch
		}
	}
	return nil
}

func proxyRejectionEvent(request *http.Request, statusCode int) string {
	if request == nil || request.URL == nil ||
		(statusCode != http.StatusUnauthorized && statusCode != http.StatusForbidden) {
		return ""
	}
	if request.Method == http.MethodPost {
		switch request.URL.Path {
		case "/api/v1/auth/login":
			return "auth_login_rejected"
		case "/api/v1/auth/refresh":
			return "session_refresh_rejected"
		}
		if strings.HasPrefix(request.URL.Path, "/api/v1/auth/desktop/attempts/") &&
			strings.HasSuffix(request.URL.Path, "/exchange") {
			return "desktop_auth_exchange_rejected"
		}
	}
	return "api_authorization_rejected"
}

func (h *appHost) markAuthenticated(requestTarget *url.URL, refreshToken string) bool {
	if requestTarget == nil || requestTarget != h.target.Load() {
		return false
	}
	h.sessionMu.Lock()
	defer h.sessionMu.Unlock()
	if requestTarget != h.target.Load() {
		return false
	}
	h.persistAuthenticatedLocked(requestTarget, refreshToken)
	return true
}

func (h *appHost) persistAuthenticatedLocked(requestTarget *url.URL, refreshToken string) {
	h.replaceRefreshCredentialLocked(requestTarget, refreshToken)
	if h.config != nil {
		if err := h.config.Save(requestTarget.String(), false); err != nil {
			appLog.Error("session state persistence failed", "component", "session", "event", "app.session.persist_failed", "error", err, "error_type", logErrorType(err))
		}
	}
	h.credentialsBlocked.Store(false)
}

func rejectUpstreamRedirect(response *http.Response) error {
	if response.StatusCode < http.StatusMultipleChoices || response.StatusCode >= http.StatusBadRequest {
		return nil
	}
	_ = response.Body.Close()
	payload := []byte(`{"error":{"code":"upstream_redirect_blocked","message":"External navigation is blocked in Soha App"}}`)
	response.StatusCode = http.StatusBadGateway
	response.Status = http.StatusText(http.StatusBadGateway)
	response.Body = io.NopCloser(strings.NewReader(string(payload)))
	response.ContentLength = int64(len(payload))
	response.Header.Del("Location")
	response.Header.Del("Set-Cookie")
	response.Header.Set("Content-Type", "application/json")
	response.Header.Set("Content-Length", fmt.Sprintf("%d", len(payload)))
	return nil
}

func classifyConnectionError(err error) (connectionStatus, string) {
	if errors.Is(err, errContractMismatch) {
		return connectionIncompatible, "response_contract_mismatch"
	}
	var certificateInvalid x509.CertificateInvalidError
	var hostnameError x509.HostnameError
	var unknownAuthority x509.UnknownAuthorityError
	var rootsError x509.SystemRootsError
	var recordHeader tls.RecordHeaderError
	if errors.As(err, &certificateInvalid) || errors.As(err, &hostnameError) ||
		errors.As(err, &unknownAuthority) || errors.As(err, &rootsError) || errors.As(err, &recordHeader) {
		return connectionTLSError, "tls_validation_failed"
	}
	return connectionOffline, "server_unreachable"
}

func validateHostMutation(writer http.ResponseWriter, request *http.Request) bool {
	if request.Method != http.MethodPost {
		writeMethodNotAllowed(writer, http.MethodPost)
		return false
	}
	if !isTrustedAppRequest(request) {
		writeError(writer, http.StatusForbidden, "untrusted_origin", "Request origin is not allowed")
		return false
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(writer, http.StatusUnsupportedMediaType, "invalid_content_type", "Content-Type must be application/json")
		return false
	}
	return true
}

func isTrustedAppOrigin(rawOrigin string) bool {
	if rawOrigin == "wails://localhost" || rawOrigin == "http://wails.localhost" {
		return true
	}
	devServer, err := url.Parse(os.Getenv("FRONTEND_DEVSERVER_URL"))
	if err != nil || devServer.Port() == "" {
		return false
	}
	port := devServer.Port()
	devOrigin := devServer.Scheme + "://" + devServer.Host
	return rawOrigin == devOrigin || rawOrigin == "wails://localhost:"+port || rawOrigin == "http://wails.localhost:"+port
}

func isTrustedAppRequest(request *http.Request) bool {
	origin := request.Header.Get("Origin")
	if isTrustedAppOrigin(origin) {
		return true
	}
	if origin != "" {
		return false
	}
	if request.Method == http.MethodGet || request.Method == http.MethodHead {
		return true
	}

	// Wails' native asset transport overwrites this header before invoking the embedded handler.
	windowID, err := strconv.ParseUint(request.Header.Get("X-Wails-Window-Id"), 10, 32)
	return err == nil && windowID > 0
}

func decodeRequestJSON(request *http.Request, output any) error {
	decoder := json.NewDecoder(io.LimitReader(request.Body, 4097))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

func clearAuthCookieHeaders(header http.Header, secure bool) {
	expires := time.Unix(1, 0).UTC()
	for _, cookie := range []http.Cookie{
		{
			Name:     "soha_refresh_token",
			Path:     "/api/v1/auth",
			Secure:   secure,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
			Expires:  expires,
		},
		{
			Name:     "soha_refresh_token",
			Path:     "/",
			Secure:   secure,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
			Expires:  expires,
		},
		{
			Name:     protocolAccessCookieName,
			Path:     "/",
			Secure:   secure,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
			Expires:  expires,
		},
	} {
		header.Add("Set-Cookie", cookie.String())
	}
}

func clearAuthCookies(writer http.ResponseWriter, secure bool) {
	clearAuthCookieHeaders(writer.Header(), secure)
}

func setStaticSecurityHeaders(header http.Header) {
	scriptSource := "script-src 'self'"
	connectSource := "connect-src 'self'"
	if os.Getenv("FRONTEND_DEVSERVER_URL") != "" {
		scriptSource += " 'unsafe-inline' 'unsafe-eval'"
		connectSource += " ws: wss:"
	}
	header.Set("Content-Security-Policy", strings.Join([]string{
		"default-src 'self'",
		scriptSource,
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data: https:",
		"font-src 'self' data:",
		connectSource,
		"frame-src 'none'",
		"object-src 'none'",
		"base-uri 'none'",
		"form-action 'self'",
	}, "; "))
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
}

func writeMethodNotAllowed(writer http.ResponseWriter, allowed string) {
	writer.Header().Set("Allow", allowed)
	writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "Method is not allowed")
}

func writeError(writer http.ResponseWriter, status int, code string, message string) {
	writeJSON(writer, status, map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

func writeData(writer http.ResponseWriter, status int, data any) {
	writeJSON(writer, status, map[string]any{"data": data})
}

func writeJSON(writer http.ResponseWriter, status int, payload any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(payload)
}

func newRequestID() string {
	token, err := randomToken(12)
	if err != nil {
		return "unavailable"
	}
	return token
}

func randomToken(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func constantTimeEqual(left string, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func parseServerURL(rawServerURL string) (*url.URL, error) {
	target, err := url.Parse(rawServerURL)
	if err != nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") {
		return nil, fmt.Errorf("invalid SOHA_SERVER_URL %q", rawServerURL)
	}
	if target.User != nil || target.RawQuery != "" || target.Fragment != "" {
		return nil, fmt.Errorf("SOHA_SERVER_URL must not contain credentials, query, or fragment")
	}
	return target, nil
}
