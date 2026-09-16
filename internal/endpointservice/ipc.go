package endpointservice

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"
)

const (
	IPCVersion          = 1
	PipeName            = `\\.\pipe\OpenSoha.Soha.NetworkService`
	maxIPCMessageBytes  = 32 << 10
	ipcOperationTimeout = 125 * time.Second
)

var ErrIPCUnsupported = errors.New("Soha network service is supported on Windows and macOS only")

type IPCRequest struct {
	Version   int             `json:"version"`
	RequestID string          `json:"requestId"`
	Action    string          `json:"action"`
	Connect   *ConnectInput   `json:"connect,omitempty"`
	Mihomo    *MihomoAppInput `json:"mihomo,omitempty"`
}

type IPCResponse struct {
	Version      int              `json:"version"`
	RequestID    string           `json:"requestId"`
	OK           bool             `json:"ok"`
	Status       Status           `json:"status"`
	Mihomo       *MihomoAppStatus `json:"mihomo,omitempty"`
	ErrorCode    string           `json:"errorCode,omitempty"`
	ErrorMessage string           `json:"errorMessage,omitempty"`
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
				response.Status, response.Mihomo, err = runIPCAction(requestCtx, manager, request)
			}
		}
	}
	if err == nil {
		response.OK = true
	} else {
		response.ErrorCode, response.ErrorMessage = "operation_failed", "Network operation failed"
		if response.RequestID == "" {
			response.ErrorCode, response.ErrorMessage = "invalid_request", "IPC request is invalid"
		}
		logger.Warn("endpoint IPC request failed", "event", "endpoint_ipc.request.failed", "requestId", response.RequestID, "errorCode", response.ErrorCode)
	}
	encoded, encodeErr := json.Marshal(response)
	if encodeErr == nil {
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
	if err := decodeStrict(raw, &response); err != nil || response.Version != IPCVersion || response.RequestID != requestID || !validIPCStatus(response.Status) || response.Mihomo != nil {
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
	if err := decodeStrict(raw, &response); err != nil || response.Version != IPCVersion || response.RequestID != requestID || !validIPCStatus(response.Status) || response.Mihomo == nil || !validIPCMihomoStatus(*response.Mihomo) {
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
	return slicesContains([]string{StateDisconnected, StateConnecting, StateConnected, StateDegraded}, status.State) && identifierPattern.MatchString(status.RuntimeID) && identifierPattern.MatchString(status.DeviceID) && status.ConfigurationVersion >= 0 && status.PolicyVersion >= 0 && status.UptimeSeconds >= 0 && validMihomo
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
