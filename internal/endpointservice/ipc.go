package endpointservice

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	ec "github.com/opensoha/soha-contracts/endpointcontrol"
	api "github.com/opensoha/soha-contracts/gen/go/sohaapi"
	"github.com/opensoha/soha-contracts/proxypolicy"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"
)

const (
	IPCVersion          = 1
	PipeName            = `\\.\pipe\OpenSoha.Soha.NetworkService`
	maxIPCMessageBytes  = 2 << 20
	ipcOperationTimeout = 125 * time.Second
)

var ErrIPCUnsupported = errors.New("Soha network service is supported on Windows and macOS only")

type IPCRequest struct {
	UIScope       *NativeUIScope              `json:"uiScope,omitempty"`
	Interception  *InterceptionIntent         `json:"interception,omitempty"`
	ExpiresAt     *time.Time                  `json:"expiresAt,omitempty"`
	Proxy         *ProxyAction                `json:"proxy,omitempty"`
	PersonalRules *api.NetworkProxyRulesInput `json:"personalRules,omitempty"`
	Version       int                         `json:"version"`
	RequestID     string                      `json:"requestId"`
	Action        string                      `json:"action"`
	Connect       *ConnectInput               `json:"connect,omitempty"`
	Mihomo        *MihomoAppInput             `json:"mihomo,omitempty"`
	Admission     *AdmissionInput             `json:"admission,omitempty"`
}

type IPCResponse struct {
	Interception *InterceptionStatus `json:"interception,omitempty"`
	Proxy        *ProxyWorkbench     `json:"proxy,omitempty"`
	Version      int                 `json:"version"`
	RequestID    string              `json:"requestId"`
	OK           bool                `json:"ok"`
	Status       Status              `json:"status"`
	Mihomo       *MihomoAppStatus    `json:"mihomo,omitempty"`
	Admission    *AdmissionStatus    `json:"admission,omitempty"`
	ErrorCode    string              `json:"errorCode,omitempty"`
	ErrorMessage string              `json:"errorMessage,omitempty"`
}

type IPCError struct {
	Code    string
	Message string
}

func (err *IPCError) Error() string { return err.Message }

func ServeIPC(ctx context.Context, listener net.Listener, manager *Manager, logger *slog.Logger) error {
	if listener == nil || manager == nil || logger == nil {
		return errors.New("IPC server dependencies are invalid")
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	// ponytail: eight local clients bound memory; add per-user queues only if desktop concurrency needs them.
	slots := make(chan struct{}, 8)
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept endpoint IPC connection: %w", err)
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				serveIPCConnection(ctx, connection, manager, logger)
			}()
		case <-ctx.Done():
			_ = connection.Close()
			return nil
		}
	}
}

func serveIPCConnection(parent context.Context, connection net.Conn, manager *Manager, logger *slog.Logger) {
	defer connection.Close()
	deadline := time.Now().Add(ipcOperationTimeout)
	if parentDeadline, ok := parent.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	_ = connection.SetDeadline(deadline)
	requestCtx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	response := IPCResponse{Version: IPCVersion, Status: manager.Status()}
	raw, err := readIPCFrame(connection)
	if err == nil {
		var request IPCRequest
		if err = decodeStrict(raw, &request); err == nil {
			response.RequestID = request.RequestID
			if request.Version != IPCVersion || !identifierPattern.MatchString(request.RequestID) {
				err = errors.New("invalid IPC envelope")
			} else {
				if request.Action == "interception_status" || request.Action == "interception_set" || request.Action == "interception_ui_scope" {
					if request.Connect != nil || request.Mihomo != nil || request.Admission != nil || request.Proxy != nil || request.PersonalRules != nil || request.ExpiresAt != nil || request.Action == "interception_status" && (request.Interception != nil || request.UIScope != nil) || request.Action == "interception_set" && (request.Interception == nil || request.UIScope != nil) || request.Action == "interception_ui_scope" && (request.UIScope == nil || request.Interception != nil) {
						err = errors.New("invalid native interception parameters")
					} else {
						e, ok := manager.executor.(*CoordinatedExecutor)
						if !ok {
							view := InterceptionStatus{State: interceptionInactive, ObservedAt: time.Now().UTC(), Capabilities: InterceptionCapabilities{ReasonCode: "native_interception_not_configured"}}
							response.Interception = &view
							if request.Action == "interception_set" {
								err = errors.New("native interception unavailable")
							}
						} else if request.Action == "interception_status" {
							view := e.previewInterception(requestCtx, connection)
							response.Interception = &view
						} else {
							peer, authErr := e.authenticateInterception(requestCtx, connection)
							err = authErr
							if err == nil {
								var view InterceptionStatus
								var applyErr error
								if request.Action == "interception_ui_scope" {
									view, applyErr = e.SetNativeUIScope(requestCtx, peer, *request.UIScope)
								} else {
									view, applyErr = e.SetInterception(requestCtx, peer, *request.Interception)
								}
								response.Interception = &view
								err = applyErr
							}
						}
					}
				} else if request.Interception != nil || request.UIScope != nil {
					err = errors.New("native interception requires a dedicated action")
				} else if request.Action == "ui_presence" {
					if request.Connect != nil || request.Mihomo != nil || request.Admission != nil || request.Proxy != nil || request.PersonalRules != nil || request.ExpiresAt != nil {
						err = errors.New("UI presence cannot include renderer parameters")
					} else {
						err = manager.options.UIPresence.Observe(connection, manager.now().UTC())
					}
				} else if strings.HasPrefix(request.Action, "proxy_") {
					now := time.Now()
					if request.ExpiresAt == nil || !request.ExpiresAt.After(now) || request.ExpiresAt.After(now.Add(30*time.Second)) {
						err = errors.New("proxy request expired or unbounded")
					} else {
						actionCtx, actionCancel := context.WithDeadline(requestCtx, *request.ExpiresAt)
						defer actionCancel()
						if request.Connect != nil || request.Mihomo != nil || request.Admission != nil {
							err = errors.New("proxy parameters conflict")
						} else {
							response.Proxy, err = runProxyIPCAction(actionCtx, manager, request)
						}
					}

				} else if request.Proxy != nil || request.PersonalRules != nil || request.ExpiresAt != nil {
					err = errors.New("proxy parameters require proxy action")
				} else if strings.HasPrefix(request.Action, "admission_") {
					response.Admission, err = runAdmissionIPCAction(requestCtx, manager, request)
				} else if request.Admission != nil {
					err = errors.New("admission parameters require an admission action")
				} else {
					response.Status, response.Mihomo, err = runIPCAction(requestCtx, manager, request)
				}
			}
		}
	}
	if err == nil {
		response.OK = true
	} else {
		response.ErrorCode, response.ErrorMessage = "operation_failed", "Network operation failed"
		if errors.Is(err, proxypolicy.ErrRevisionConflict) {
			response.ErrorCode = "rule_revision_conflict"
		}
		if response.RequestID == "" {
			response.ErrorCode, response.ErrorMessage = "invalid_request", "IPC request is invalid"
		}
		logger.Warn("endpoint IPC request failed", "event", "endpoint_ipc.request.failed", "requestId", response.RequestID, "errorCode", response.ErrorCode)
	}
	encoded, encodeErr := json.Marshal(response)
	if encodeErr == nil {
		if len(encoded) > maxIPCMessageBytes {
			response.Proxy = nil
			response.OK = false
			response.ErrorCode = "proxy_response_too_large"
			response.ErrorMessage = "Local proxy response exceeds limit"
			encoded, _ = json.Marshal(response)
		}
		_ = writeIPCFrame(connection, encoded)
	}
}

func runIPCAction(ctx context.Context, manager *Manager, request IPCRequest) (Status, *MihomoAppStatus, error) {
	switch request.Action {
	case "status":
		if request.Connect != nil || request.Mihomo != nil {
			return manager.Status(), nil, errors.New("status request cannot include parameters")
		}
		return manager.Status(), nil, nil
	case "connect":
		if request.Connect == nil || request.Mihomo != nil {
			return manager.Status(), nil, errors.New("connect parameters are required")
		}
		status, err := manager.Connect(ctx, *request.Connect)
		return status, nil, err
	case "disconnect":
		if request.Connect != nil || request.Mihomo != nil {
			return manager.Status(), nil, errors.New("disconnect request cannot include parameters")
		}
		status, err := manager.Disconnect(ctx)
		return status, nil, err
	case "mihomo_status":
		if request.Connect != nil || request.Mihomo != nil {
			return manager.Status(), nil, errors.New("mihomo status request cannot include parameters")
		}
		status, err := manager.MihomoAppStatus()
		return manager.Status(), &status, err
	case "mihomo_configure":
		if request.Connect != nil || request.Mihomo == nil || request.Mihomo.SubscriptionURL == "" || request.Mihomo.SelectedProxy != "" {
			return manager.Status(), nil, errors.New("mihomo subscription parameters are required")
		}
		status, err := manager.ConfigureMihomoApp(ctx, *request.Mihomo)
		return manager.Status(), &status, err
	case "mihomo_select":
		if request.Connect != nil || request.Mihomo == nil || request.Mihomo.SubscriptionURL != "" || request.Mihomo.SelectedProxy == "" {
			return manager.Status(), nil, errors.New("mihomo selection parameters are required")
		}
		status, err := manager.SelectMihomoApp(ctx, request.Mihomo.SelectedProxy)
		return manager.Status(), &status, err
	case "mihomo_refresh":
		if request.Connect != nil || request.Mihomo != nil {
			return manager.Status(), nil, errors.New("mihomo refresh request cannot include parameters")
		}
		status, err := manager.RefreshMihomoApp(ctx)
		return manager.Status(), &status, err
	case "mihomo_clear":
		if request.Connect != nil || request.Mihomo != nil {
			return manager.Status(), nil, errors.New("mihomo clear request cannot include parameters")
		}
		status, err := manager.ClearMihomoApp(ctx)
		return manager.Status(), &status, err
	default:
		return manager.Status(), nil, errors.New("IPC action is not supported")
	}
}

func CallIPC(ctx context.Context, action string, input *ConnectInput) (Status, error) {
	connection, err := dialIPC(ctx)
	if err != nil {
		return Status{}, err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	requestID := randomID()
	raw, err := json.Marshal(IPCRequest{Version: IPCVersion, RequestID: requestID, Action: action, Connect: input})
	if err != nil {
		return Status{}, err
	}
	if err := writeIPCFrame(connection, raw); err != nil {
		return Status{}, fmt.Errorf("write endpoint IPC request: %w", err)
	}
	raw, err = readIPCFrame(connection)
	if err != nil {
		return Status{}, fmt.Errorf("read endpoint IPC response: %w", err)
	}
	var response IPCResponse
	if err := decodeStrict(raw, &response); err != nil || response.Version != IPCVersion || response.RequestID != requestID || !validIPCStatus(response.Status) || response.Mihomo != nil || response.Admission != nil {
		return Status{}, errors.New("endpoint IPC response is invalid")
	}
	if !response.OK {
		if response.ErrorCode == "" || response.ErrorMessage == "" {
			return Status{}, errors.New("endpoint IPC error response is invalid")
		}
		return response.Status, &IPCError{Code: response.ErrorCode, Message: response.ErrorMessage}
	}
	return response.Status, nil
}

func CallMihomoIPC(ctx context.Context, action string, input *MihomoAppInput) (MihomoAppStatus, error) {
	connection, err := dialIPC(ctx)
	if err != nil {
		return MihomoAppStatus{}, err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	requestID := randomID()
	raw, err := json.Marshal(IPCRequest{Version: IPCVersion, RequestID: requestID, Action: action, Mihomo: input})
	if err != nil {
		return MihomoAppStatus{}, err
	}
	if err := writeIPCFrame(connection, raw); err != nil {
		return MihomoAppStatus{}, fmt.Errorf("write endpoint IPC request: %w", err)
	}
	raw, err = readIPCFrame(connection)
	if err != nil {
		return MihomoAppStatus{}, fmt.Errorf("read endpoint IPC response: %w", err)
	}
	var response IPCResponse
	if err := decodeStrict(raw, &response); err != nil || response.Version != IPCVersion || response.RequestID != requestID || !validIPCStatus(response.Status) || response.Mihomo == nil || !validIPCMihomoStatus(*response.Mihomo) || response.Admission != nil {
		return MihomoAppStatus{}, errors.New("endpoint IPC response is invalid")
	}
	if !response.OK {
		if response.ErrorCode == "" || response.ErrorMessage == "" {
			return MihomoAppStatus{}, errors.New("endpoint IPC error response is invalid")
		}
		return *response.Mihomo, &IPCError{Code: response.ErrorCode, Message: response.ErrorMessage}
	}
	return *response.Mihomo, nil
}

func validIPCStatus(status Status) bool {
	validMihomo := status.MihomoMode == "" && status.MihomoProfileID == "" && status.MihomoProfileRevision == 0 || slicesContains([]string{"managed_follow", "app_subscription"}, status.MihomoMode) && identifierPattern.MatchString(status.MihomoProfileID) && status.MihomoProfileRevision > 0
	return slicesContains([]string{StateDisconnected, StateConnecting, StateConnected, StateDegraded}, status.State) && identifierPattern.MatchString(status.RuntimeID) && identifierPattern.MatchString(status.DeviceID) && status.ConfigurationVersion >= 0 && status.PolicyVersion >= 0 && status.MihomoPolicyVersion >= 0 && status.UptimeSeconds >= 0 && validMihomo && validIPCChannelStatus(status.ChannelControls)
}

func validIPCMihomoStatus(status MihomoAppStatus) bool {
	if status.Mode != "app_subscription" || !identifierPattern.MatchString(status.ProfileID) || status.ProfileRevision < 1 || len(status.Proxies) > 2048 {
		return false
	}
	if !status.Configured {
		return status.SelectedProxy == "" && len(status.Proxies) == 0
	}
	if !validMihomoName(status.SelectedProxy) || !slicesContains(status.Proxies, status.SelectedProxy) {
		return false
	}
	seen := map[string]struct{}{}
	for _, proxy := range status.Proxies {
		if !validMihomoName(proxy) {
			return false
		}
		if _, exists := seen[proxy]; exists {
			return false
		}
		seen[proxy] = struct{}{}
	}
	return len(status.Proxies) > 0
}

func readIPCFrame(reader io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > maxIPCMessageBytes {
		return nil, errors.New("IPC message exceeds the safe limit")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func writeIPCFrame(writer io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > maxIPCMessageBytes {
		return errors.New("IPC message exceeds the safe limit")
	}
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	_, err := io.Copy(writer, bytes.NewReader(frame))
	return err
}

func validIPCChannelStatus(s *ChannelStatus) bool {
	if s == nil {
		return true
	}
	if s.PolicyVersion < 0 || len(s.Channels) > 3 {
		return false
	}
	if len(s.Channels) == 0 {
		return s.LastObservedAt.IsZero()
	}
	seen := map[string]bool{}
	for _, c := range s.Channels {
		if !ec.ValidChannel(c) || seen[c.Name] {
			return false
		}
		seen[c.Name] = true
	}
	return len(seen) == 3
}

func runProxyIPCAction(ctx context.Context, manager *Manager, request IPCRequest) (*ProxyWorkbench, error) {
	manager.operationMu.Lock()
	defer manager.operationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	e, ok := manager.executor.(*CoordinatedExecutor)
	if !ok {
		return nil, errors.New("proxy coordinator unavailable")
	}
	switch request.Action {
	case "proxy_status":
		if request.Proxy != nil || request.PersonalRules != nil {
			return nil, errors.New("status forbids parameters")
		}
	case "proxy_action":
		if request.Proxy == nil || request.PersonalRules != nil {
			return nil, errors.New("proxy action required")
		}
	case "proxy_rules":
		if request.PersonalRules == nil || request.Proxy != nil {
			return nil, errors.New("personal rule input required")
		}
	default:
		return nil, errors.New("unknown proxy action")
	}
	if request.Proxy != nil && request.Proxy.Kind == "refresh_subscription" {
		e.mu.Lock()
		managedBundle := e.proxyDesired != nil && e.proxyDesired.BundleID != ""
		e.mu.Unlock()
		if managedBundle {
			if err := manager.syncConfiguration(ctx); err != nil {
				return nil, err
			}
			request.Proxy = &ProxyAction{Kind: "refresh_status"}
		}
	}
	bundledStart := false
	if request.Proxy != nil && (request.Proxy.Kind == "start" || request.Proxy.Kind == "restart") {
		e.mu.Lock()
		bundledStart = e.proxyDesired != nil && e.proxyDesired.BundleID != ""
		e.mu.Unlock()
		if bundledStart {
			if err := manager.syncConfiguration(ctx); err != nil {
				return nil, err
			}
		}
	}
	view, err := e.Proxy(ctx, request.Proxy, request.PersonalRules)
	if err == nil && bundledStart {
		e.mu.Lock()
		configuration, configurationErr := e.proxyConfiguration()
		e.mu.Unlock()
		if configurationErr != nil {
			return nil, configurationErr
		}
		if manager.deliverProjectionReceipt(ctx, ConfigurationDesired{Mihomo: &configuration}, "applied", "") != nil {
			return nil, manager.rejectConfiguration(ctx, "projection_receipt_failed")
		}
		manager.stateMu.Lock()
		if manager.status.ValidUntil.IsZero() || configuration.EnforcementUntil.Before(manager.status.ValidUntil) {
			manager.status.ValidUntil = configuration.EnforcementUntil
		}
		manager.status.State = StateConnected
		manager.status.Diagnostic = ""
		manager.stateMu.Unlock()

	}
	return &view, err
}
func CallProxyIPC(ctx context.Context, action string, input *ProxyAction, rules *api.NetworkProxyRulesInput) (ProxyWorkbench, error) {
	connection, err := dialIPC(ctx)
	if err != nil {
		return ProxyWorkbench{}, err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	id := randomID()
	until := time.Now().Add(30 * time.Second)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(until) {
		until = deadline
	}
	raw, err := json.Marshal(IPCRequest{Version: IPCVersion, RequestID: id, Action: action, Proxy: input, PersonalRules: rules, ExpiresAt: &until})
	if err != nil {
		return ProxyWorkbench{}, err
	}
	if writeIPCFrame(connection, raw) != nil {
		return ProxyWorkbench{}, errors.New("proxy IPC write failed")
	}
	raw, err = readIPCFrame(connection)
	if err != nil {
		return ProxyWorkbench{}, errors.New("proxy IPC read failed")
	}
	var response IPCResponse
	if decodeStrict(raw, &response) != nil || response.Version != IPCVersion || response.RequestID != id || !validIPCStatus(response.Status) || response.Mihomo != nil || response.Admission != nil {
		return ProxyWorkbench{}, errors.New("proxy IPC response invalid")
	}
	if !response.OK {
		return ProxyWorkbench{}, &IPCError{Code: response.ErrorCode, Message: "Local proxy operation failed"}
	}
	if response.Proxy == nil || response.Proxy.Engine != "mihomo" {
		return ProxyWorkbench{}, errors.New("proxy IPC view invalid")
	}
	return *response.Proxy, nil
}

func CallInterceptionIPC(ctx context.Context, input *InterceptionIntent) (InterceptionStatus, error) {
	action := "interception_status"
	if input != nil {
		action = "interception_set"
	}
	return callInterceptionIPC(ctx, action, input, nil)
}
func CallInterceptionUIScopeIPC(ctx context.Context, scope NativeUIScope) (InterceptionStatus, error) {
	return callInterceptionIPC(ctx, "interception_ui_scope", nil, &scope)
}
func callInterceptionIPC(ctx context.Context, action string, input *InterceptionIntent, scope *NativeUIScope) (InterceptionStatus, error) {
	c, err := dialIPC(ctx)
	if err != nil {
		return InterceptionStatus{}, err
	}
	defer c.Close()
	if d, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(d)
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	id := randomID()
	raw, err := json.Marshal(IPCRequest{Version: IPCVersion, RequestID: id, Action: action, Interception: input, UIScope: scope})
	if err != nil {
		return InterceptionStatus{}, err
	}
	if writeIPCFrame(c, raw) != nil {
		return InterceptionStatus{}, errors.New("native IPC write failed")
	}
	raw, err = readIPCFrame(c)
	if err != nil {
		return InterceptionStatus{}, errors.New("native IPC read failed")
	}
	var r IPCResponse
	if decodeStrict(raw, &r) != nil || r.Version != IPCVersion || r.RequestID != id || !validIPCStatus(r.Status) || r.Proxy != nil || r.Mihomo != nil || r.Admission != nil {
		return InterceptionStatus{}, errors.New("invalid native IPC response")
	}
	if !r.OK {
		return InterceptionStatus{}, &IPCError{Code: r.ErrorCode, Message: "Local interception operation failed"}
	}
	if r.Interception == nil || !validInterceptionStatus(*r.Interception) {
		return InterceptionStatus{}, errors.New("invalid native status")
	}
	return *r.Interception, nil
}
func validInterceptionStatus(s InterceptionStatus) bool {
	switch s.State {
	case interceptionInactive, interceptionPreparing, interceptionActive, interceptionStopping, interceptionSuspended, interceptionCleanupPending, interceptionFailed:
	default:
		return false
	}
	if s.ObservedAt.IsZero() {
		return false
	}
	if s.State == interceptionActive {
		return !s.CleanupPending && s.SystemProxy == s.DesiredSystemProxy && s.TUN == s.DesiredTUN && (s.SystemProxy || s.TUN)
	}
	if s.State == interceptionInactive {
		return !s.CleanupPending && !s.SystemProxy && !s.TUN && !s.DesiredSystemProxy && !s.DesiredTUN
	}
	// Stopping/cleanup can retain observed owned settings after stop intent is
	// durable. A desired/observed difference must remain visible to the caller.
	return true
}
