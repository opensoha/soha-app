package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

const meshDelegationPath = "/copilot/assistant-mesh/delegations"
const meshOSCapability = "desktop.os-version.v1"

type meshLocalDevice struct {
	scope   nativeUIScope
	id      string
	proof   string
	results map[string]meshLocalResult
}

type meshLocalResult struct {
	inputHash string
	value     string
	nonce     string
	fence     int
	mode      string
	failed    bool
	expiresAt time.Time
}

type meshDelegationReceipt struct {
	ID         string    `json:"id"`
	OwnerID    string    `json:"ownerId"`
	CallerName string    `json:"callerName"`
	Capability string    `json:"capability"`
	Field      string    `json:"field"`
	InputHash  string    `json:"inputHash"`
	Status     string    `json:"status"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

type meshDelegationAuth struct {
	DeviceID   string `json:"deviceId"`
	Proof      string `json:"proof"`
	InputHash  string `json:"inputHash"`
	Fence      int    `json:"fence,omitempty"`
	Mode       string `json:"mode,omitempty"`
	Ticket     string `json:"ticket,omitempty"`
	ResultHash string `json:"resultHash,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	Result     string `json:"result,omitempty"`
	Failed     bool   `json:"failed,omitempty"`
}

type meshNativeReceipt struct {
	State   string `json:"state"`
	Preview string `json:"preview,omitempty"`
}

type meshNativeRequest struct {
	ID   string `json:"id,omitempty"`
	Mode string `json:"mode,omitempty"`
}

func (h *appHost) handleMeshDelegation(w http.ResponseWriter, r *http.Request, action string) {
	w.Header().Set("Cache-Control", "no-store")
	if !validateHostMutation(w, r) {
		return
	}
	if h.appInfo.Platform != "darwin" || h.meshConfirmManaged == nil {
		writeData(w, http.StatusOK, meshNativeReceipt{State: "unavailable"})
		return
	}
	var input meshNativeRequest
	if decodeRequestJSON(r, &input) != nil || !input.valid(action) {
		writeError(w, http.StatusBadRequest, "invalid_delegation", "无效的委托请求")
		return
	}
	if !h.meshDelegationMu.TryLock() {
		writeError(w, http.StatusConflict, "delegation_busy", "请先处理当前的本机确认")
		return
	}
	defer h.meshDelegationMu.Unlock()
	scope := h.nativeUIScopeSnapshot()
	call := meshCoreCall{
		h: h, ctx: r.Context(), scope: scope, target: h.target.Load(),
		authorization: r.Header.Get("Authorization"),
	}
	if !call.current() || !strings.HasPrefix(call.authorization, "Bearer ") {
		writeError(w, http.StatusUnauthorized, "delegation_session", "当前登录已失效")
		return
	}
	if h.meshDevice.scope != scope {
		h.meshDevice = meshLocalDevice{scope: scope}
	}
	var account struct {
		UserID string `json:"userId"`
	}
	if err := call.do(http.MethodGet, "/auth/me", nil, &account); err != nil || scope.UserID != account.UserID {
		writeError(w, http.StatusUnauthorized, "delegation_session", "当前登录已失效")
		return
	}
	for id, result := range h.meshDevice.results {
		if !time.Now().Before(result.expiresAt) {
			delete(h.meshDevice.results, id)
		}
	}
	var reply meshNativeReceipt
	var err error
	if action == "device" {
		reply, err = h.registerMeshDevice(call)
	} else {
		reply, err = h.runMeshAction(call, action, input)
	}
	if !call.current() {
		writeError(w, http.StatusUnauthorized, "delegation_session", "当前登录已失效")
		return
	}
	if err != nil {
		var upstream meshCoreStatus
		if errors.As(err, &upstream) && upstream >= 400 && upstream <= 499 {
			writeError(w, int(upstream), "delegation_rejected", "委托已变更、失效或超出当前权限，请刷新")
			return
		}
		writeError(w, http.StatusBadGateway, "delegation_unverified", "未确认委托结果，请刷新查看状态")
		return
	}
	writeData(w, http.StatusOK, reply)
}

func (request meshNativeRequest) valid(action string) bool {
	if action == "device" {
		return request.ID == "" && request.Mode == ""
	}
	id, err := uuid.Parse(request.ID)
	if err != nil || id.String() != request.ID {
		return false
	}
	if action == "execute" {
		return request.Mode == "preview" || request.Mode == "direct"
	}
	return (action == "preview" || action == "deliver") && request.Mode == ""
}

func (h *appHost) registerMeshDevice(call meshCoreCall) (meshNativeReceipt, error) {
	if h.meshDevice.id == "" {
		if !h.meshConfirmManaged(call.ctx, "开启本机受管能力", "此设备可接收 macOS 版本核对请求。每次执行都需要你在本机批准。") {
			return meshNativeReceipt{State: "canceled"}, nil
		}
		id, err := uuid.NewRandom()
		if err != nil {
			return meshNativeReceipt{}, err
		}
		h.meshDevice.id, h.meshDevice.proof = id.String(), meshRandomSecret()
	}
	input := map[string]string{"deviceId": h.meshDevice.id, "proofHash": meshDigest(h.meshDevice.proof)}
	var registered struct {
		OwnerID  string `json:"ownerId"`
		DeviceID string `json:"deviceId"`
	}
	if err := call.do(http.MethodPost, meshDelegationPath+"/native-device", input, &registered); err != nil {
		return meshNativeReceipt{}, err
	}
	if registered.OwnerID != call.scope.UserID || registered.DeviceID != h.meshDevice.id {
		return meshNativeReceipt{}, errors.New("managed device receipt differs")
	}
	return meshNativeReceipt{State: "registered"}, nil
}

func (h *appHost) runMeshAction(call meshCoreCall, action string, input meshNativeRequest) (meshNativeReceipt, error) {
	var item meshDelegationReceipt
	path := meshDelegationPath + "/" + input.ID
	if err := call.do(http.MethodGet, path, nil, &item); err != nil {
		return meshNativeReceipt{}, err
	}
	if !item.valid(call.scope.UserID, input.ID) || h.meshDevice.id == "" {
		return meshNativeReceipt{State: "unavailable"}, nil
	}
	if action == "execute" {
		return h.executeMeshDelegation(call, path, item, input.Mode)
	}
	result, exists := h.meshDevice.results[item.ID]
	if !exists || result.inputHash != item.InputHash {
		return meshNativeReceipt{State: "unavailable"}, nil
	}
	if action == "preview" && item.Status == "executing" {
		return h.reportMeshResult(call, path, item, result)
	}
	if item.Status != "awaiting_confirmation" || result.mode != "preview" || result.failed {
		return meshNativeReceipt{State: "unavailable"}, nil
	}
	if action == "preview" {
		return meshNativeReceipt{State: "awaiting_confirmation", Preview: result.value}, nil
	}
	if !h.meshConfirmManaged(call.ctx, "确认私下回传", fmt.Sprintf("向 %q 发送 %s 的核对结果 %s。", item.CallerName, meshFieldLabel(item.Field), result.value)) {
		return meshNativeReceipt{State: "canceled"}, nil
	}
	var delivered meshDelegationReceipt
	auth := h.meshAuthorization(item.InputHash, result.fence)
	auth.Result, auth.Nonce = result.value, result.nonce
	if err := call.do(http.MethodPost, path+"/deliver", auth, &delivered); err != nil {
		return meshNativeReceipt{}, err
	}
	if !item.matches(delivered, "completed") {
		return meshNativeReceipt{}, errors.New("delivery receipt differs")
	}
	delete(h.meshDevice.results, item.ID)
	return meshNativeReceipt{State: "completed"}, nil
}

func (h *appHost) executeMeshDelegation(call meshCoreCall, path string, item meshDelegationReceipt, mode string) (meshNativeReceipt, error) {
	if item.Status != "awaiting_owner_approval" && item.Status != "approved" {
		return meshNativeReceipt{State: "unavailable"}, nil
	}
	effect := "结果先留在本机，稍后由你确认回传。"
	if mode == "direct" {
		effect = "结果将立即私下回传。"
	}
	message := fmt.Sprintf("请求人 %q（Heya）想核对你的 macOS %s。将以你的身份在本机读取该值。%s",
		item.CallerName, meshFieldLabel(item.Field), effect)
	if !h.meshConfirmManaged(call.ctx, "批准本机版本核对", message) {
		return meshNativeReceipt{State: "canceled"}, nil
	}
	auth := h.meshAuthorization(item.InputHash, 0)
	auth.Mode = mode
	var approval struct {
		Delegation meshDelegationReceipt `json:"delegation"`
		Ticket     string                `json:"ticket"`
		Fence      int                   `json:"fence"`
	}
	if err := call.do(http.MethodPost, path+"/approve", auth, &approval); err != nil {
		return meshNativeReceipt{}, err
	}
	if !item.matches(approval.Delegation, "approved") || len(approval.Ticket) != 64 || approval.Fence <= 0 {
		return meshNativeReceipt{}, errors.New("approval receipt differs")
	}
	auth = h.meshAuthorization(item.InputHash, approval.Fence)
	auth.Ticket = approval.Ticket
	var claim meshDelegationReceipt
	if err := call.do(http.MethodPost, path+"/claim", auth, &claim); err != nil {
		return meshNativeReceipt{}, err
	}
	if !item.matches(claim, "executing") || !call.current() {
		return meshNativeReceipt{}, errors.New("execution claim differs")
	}
	value, runErr := runManagedOSVersion(call.ctx, item.Field)
	result := meshLocalResult{
		inputHash: item.InputHash, value: value, fence: auth.Fence, mode: mode,
		failed: runErr != nil, expiresAt: item.ExpiresAt,
	}
	if !result.failed && mode == "preview" {
		result.nonce = meshRandomSecret()
	}
	if h.meshDevice.results == nil {
		h.meshDevice.results = make(map[string]meshLocalResult)
	}
	// Keep the post-execution receipt for explicit resubmission if the response is lost.
	h.meshDevice.results[item.ID] = result
	return h.reportMeshResult(call, path, item, result)
}

func (h *appHost) reportMeshResult(call meshCoreCall, path string, item meshDelegationReceipt, result meshLocalResult) (meshNativeReceipt, error) {
	auth := h.meshAuthorization(item.InputHash, result.fence)
	auth.Failed = result.failed
	expected := "failed"
	if !auth.Failed && result.mode == "direct" {
		auth.Result, auth.ResultHash, expected = result.value, meshDigest(result.value), "completed"
	} else if !auth.Failed {
		auth.ResultHash = meshDigest(result.nonce + "\n" + result.value)
		expected = "awaiting_confirmation"
	}
	var reported meshDelegationReceipt
	if err := call.do(http.MethodPost, path+"/report", auth, &reported); err != nil {
		return meshNativeReceipt{}, err
	}
	if !item.matches(reported, expected) {
		return meshNativeReceipt{}, errors.New("execution report differs")
	}
	if expected == "awaiting_confirmation" {
		return meshNativeReceipt{State: expected, Preview: result.value}, nil
	}
	delete(h.meshDevice.results, item.ID)
	return meshNativeReceipt{State: expected}, nil
}

func (h *appHost) meshAuthorization(hash string, fence int) meshDelegationAuth {
	return meshDelegationAuth{DeviceID: h.meshDevice.id, Proof: h.meshDevice.proof, InputHash: hash, Fence: fence}
}

func (item meshDelegationReceipt) valid(owner, id string) bool {
	_, err := managedOSVersionArg(item.Field)
	return item.ID == id && item.OwnerID == owner && item.Capability == meshOSCapability && err == nil &&
		item.InputHash == meshDigest(item.Capability+"\n"+item.Field) &&
		len(item.CallerName) <= 240 && time.Now().Before(item.ExpiresAt)
}

func (item meshDelegationReceipt) matches(newItem meshDelegationReceipt, status string) bool {
	return newItem.valid(item.OwnerID, item.ID) && newItem.InputHash == item.InputHash && newItem.Status == status
}

func meshFieldLabel(field string) string {
	if field == "buildVersion" {
		return "构建号"
	}
	return "产品版本"
}

func meshDigest(value string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(value)))
}

func meshRandomSecret() string {
	var secret [32]byte
	rand.Read(secret[:])
	return fmt.Sprintf("%x", secret[:])
}

type meshCoreCall struct {
	h             *appHost
	ctx           context.Context
	scope         nativeUIScope
	target        *url.URL
	authorization string
}

type meshCoreStatus int

func (status meshCoreStatus) Error() string { return fmt.Sprintf("Core returned HTTP %d", status) }

func (call meshCoreCall) current() bool {
	return call.scope.Authenticated && call.target != nil && call.ctx.Err() == nil &&
		call.h.target.Load() == call.target && call.h.nativeUIScopeSnapshot() == call.scope &&
		!call.h.credentialsBlocked.Load() && !call.h.hasPendingSwitch()
}

func (call meshCoreCall) do(method, path string, input any, result any) error {
	if !call.current() {
		return errors.New("desktop session changed")
	}
	target := *call.target
	target.Path = apiPrefix + path
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(call.ctx, method, target.String(), body)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", call.authorization)
	request.Header.Set("Accept", "application/json")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := call.h.client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return meshCoreStatus(response.StatusCode)
	}
	envelope := struct {
		Data any `json:"data"`
	}{Data: result}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 65537))
	if err := decoder.Decode(&envelope); err != nil || envelope.Data == nil || !call.current() {
		return errors.New("could not verify Core response")
	}
	return ensureJSONEOF(decoder)
}
