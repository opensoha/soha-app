package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestMeshDelegationNativeConsentAndPreview(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS native capability")
	}
	const id = "f94081fd-a866-478a-a06d-b8ecfe066f64"
	const auth = "Bearer fixture"
	path := "/api/v1" + meshDelegationPath + "/" + id
	receipt := meshDelegationReceipt{
		ID: id, OwnerID: "owner", CallerName: "reader", Capability: meshOSCapability,
		Field: "productVersion", InputHash: meshDigest(meshOSCapability + "\nproductVersion"),
		Status: "awaiting_owner_approval", ExpiresAt: time.Now().Add(time.Hour),
	}
	allowed := false
	claimCount, approvalCount, prompts := 0, 0, 0
	reports := 0
	var deviceID, proofHash, reportedDigest string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != auth {
			t.Error("unexpected authorization")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/api/v1/auth/me" {
			writeData(w, http.StatusOK, map[string]string{"userId": receipt.OwnerID})
			return
		}
		if r.URL.Path == "/api/v1"+meshDelegationPath+"/native-device" {
			var reg map[string]string
			_ = json.NewDecoder(r.Body).Decode(&reg)
			deviceID, proofHash = reg["deviceId"], reg["proofHash"]
			writeData(w, http.StatusOK, map[string]string{"ownerId": receipt.OwnerID, "deviceId": deviceID})
			return
		}
		if r.URL.Path == path && r.Method == http.MethodGet {
			writeData(w, http.StatusOK, receipt)
			return
		}
		var input meshDelegationAuth
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.DeviceID != deviceID ||
			meshDigest(input.Proof) != proofHash || input.InputHash != receipt.InputHash {
			t.Error("native proof or frozen input missing")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case path + "/approve":
			if input.Mode != "preview" {
				t.Error("unexpected execution mode")
			}
			approvalCount++
			receipt.Status = "approved"
			writeData(w, http.StatusOK, map[string]any{
				"delegation": receipt, "fence": 1, "ticket": strings.Repeat("1", 64),
			})
		case path + "/claim":
			if input.Fence != 1 || input.Ticket != strings.Repeat("1", 64) {
				t.Error("claim missing one-time ticket")
			}
			claimCount++
			receipt.Status = "executing"
			writeData(w, http.StatusOK, receipt)
		case path + "/report":
			reports++
			if reports == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if input.Failed || input.Result != "" || input.Nonce != "" || input.Ticket != "" || len(input.ResultHash) != 64 {
				t.Error("native preview body or ticket left the device")
			}
			reportedDigest = input.ResultHash
			receipt.Status = "awaiting_confirmation"
			w.WriteHeader(http.StatusServiceUnavailable)
		case path + "/deliver":
			if input.Result == "" || len(input.Nonce) != 64 || meshDigest(input.Nonce+"\n"+input.Result) != reportedDigest || input.Fence != 1 {
				t.Error("delivery differs from locally previewed result")
			}
			receipt.Status = "completed"
			writeData(w, http.StatusOK, receipt)
		default:
			t.Errorf("unexpected Core path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	h := &appHost{
		client: server.Client(), appInfo: AppInfo{Platform: "darwin"},
		nativeScope: nativeUIScope{Authenticated: true, UserID: receipt.OwnerID, ServerURL: server.URL, Generation: 1},
		meshConfirmManaged: func(context.Context, string, string) bool {
			prompts++
			return allowed
		},
	}
	h.target.Store(parsed)
	send := func(action, body string, want int) meshNativeReceipt {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/app/v1/assistant-mesh/delegation-"+action, strings.NewReader(body))
		req.Header.Set("Origin", "wails://localhost")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", auth)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("%s: code %d, want %d, body %s", action, rec.Code, want, rec.Body)
		}
		var envelope struct{ Data meshNativeReceipt }
		_ = json.Unmarshal(rec.Body.Bytes(), &envelope)
		return envelope.Data
	}
	if got := send("device", "{}", 200); got.State != "canceled" || deviceID != "" {
		t.Fatal("canceled registration contacted Core")
	}
	allowed = true
	if got := send("device", "{}", 200); got.State != "registered" || deviceID == "" {
		t.Fatal("native registration failed")
	}
	allowed = false
	body := `{"id":"` + id + `"}`
	execute := `{"id":"` + id + `","mode":"preview"}`
	if got := send("execute", execute, 200); got.State != "canceled" || approvalCount != 0 || claimCount != 0 {
		t.Fatal("canceled execution attempted claim")
	}
	send("execute", `{"id":"`+id+`","mode":"preview","field":"productName"}`, 400)
	allowed = true
	send("execute", execute, 502)
	if claimCount != 1 || receipt.Status != "executing" {
		t.Fatal("report failure changed the execution fence")
	}
	send("preview", body, 502)
	if reports != 2 || receipt.Status != "awaiting_confirmation" || claimCount != 1 {
		t.Fatal("lost report response did not leave an authenticated local receipt")
	}
	preview := send("preview", body, 200)
	if preview.State != "awaiting_confirmation" || preview.Preview == "" || meshDigest(preview.Preview) == reportedDigest || claimCount != 1 {
		t.Fatal("native preview did not remain local")
	}
	if got := send("execute", execute, 200); got.State != "unavailable" || claimCount != 1 {
		t.Fatal("repeated execution attempted another claim")
	}
	if got := send("preview", body, 200); got.Preview != preview.Preview {
		t.Fatal("preview could not be opened again in the same session")
	}
	allowed = false
	if got := send("deliver", body, 200); got.State != "canceled" || receipt.Status != "awaiting_confirmation" {
		t.Fatal("preview was sent without confirmation")
	}
	allowed = true
	if got := send("deliver", body, 200); got.State != "completed" || prompts != 6 {
		t.Fatal("native delivery was not confirmed")
	}
	h.invalidateNativeUIScopeLocked()
	if got := send("preview", body, 401); got.Preview != "" {
		t.Fatal("previous native account preview leaked")
	}
}
