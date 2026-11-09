//go:build !windows

package endpointservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	api "github.com/opensoha/soha-contracts/gen/go/sohaapi"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMihomoLocalActionsReadbackApprovedProbeAndEpochClose(t *testing.T) {
	var mu sync.Mutex
	selected := "node-a"
	connectionPresent := true
	deletes, selects, probes := 0, 0, 0
	upload, download := int64(1000), int64(2000)
	many := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "PUT /proxies/Soha":
			var body struct {
				Name string `json:"name"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				w.WriteHeader(400)
				return
			}
			selects++
			selected = body.Name
			w.WriteHeader(204)
		case "GET /proxies/Soha":
			json.NewEncoder(w).Encode(map[string]any{"now": selected, "all": []string{"node-a", "node-b"}})
		case "GET /proxies/node-a/delay":
			if r.URL.Query().Get("url") != "https://approved.invalid/health" || r.URL.Query().Get("timeout") != "3000" {
				w.WriteHeader(400)
				return
			}
			probes++
			json.NewEncoder(w).Encode(map[string]int{"delay": 12})
		case "GET /connections":
			items := []any{}
			if connectionPresent {
				count := 1
				if many {
					count = 201
				}
				for i := 0; i < count; i++ {
					id := "connection-1"
					if i > 0 {
						id = fmt.Sprintf("connection-%d", i+1)
					}
					items = append(items, map[string]any{"id": id, "upload": 10, "download": 20, "metadata": map[string]any{"host": "destination.example", "network": "tcp"}, "start": time.Now().UTC()})
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"uploadTotal": upload, "downloadTotal": download, "connections": items})
		case "DELETE /connections/connection-1":
			deletes++
			connectionPresent = false
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	controller, err := NewMihomoController(server.URL, strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	processController, _ := processFixture(t)
	if err := processController.process.start(context.Background(), "", func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	controller.process = processController.process
	configuration, projection := bundleFixture(time.Now())
	projection.Nodes = append(projection.Nodes, api.NetworkProxyEmployeeNode{NodeID: "node-b", Label: "Internal B", EndpointID: "internal-1"})
	projection.Groups[0].NodeIDs = append(projection.Groups[0].NodeIDs, "node-b")
	projection.Credential.NodeIDs = append(projection.Credential.NodeIDs, "node-b")
	configuration.Projection = &projection
	controller.applied = expectedMihomoReadback(configuration)
	controller.applied.SelectedProxy = "node-a"
	controller.probeProfiles = map[string]string{"approved": "https://approved.invalid/health"}
	if err := controller.selectLocal(context.Background(), configuration, "Soha", "node-b"); err != nil {
		t.Fatal(err)
	}
	if controller.applied.SelectedProxy != "node-b" {
		t.Fatal("selection was not read back")
	}
	if err := controller.selectLocal(context.Background(), configuration, "Soha", "node-outside-scope"); err == nil {
		t.Fatal("out-of-scope node selected")
	}
	result, err := controller.probeLocal(context.Background(), configuration, "node-a", "approved")
	if err != nil || result.LatencyMilliseconds != 12 {
		t.Fatalf("approved probe: %v", err)
	}
	if _, err = controller.probeLocal(context.Background(), configuration, "node-a", "arbitrary-url"); err == nil {
		t.Fatal("unregistered probe accepted")
	}
	first, snapshot, err := controller.observeLocal(context.Background())
	if err != nil || first.UploadBytesPerSecond != nil || snapshot.ReturnedCount != 1 {
		t.Fatalf("first sample: %v", err)
	}
	mu.Lock()
	upload, download = 1150, 2350
	mu.Unlock()
	second, _, err := controller.observeLocal(context.Background())
	if err != nil || second.UploadBytesPerSecond == nil || *second.UploadBytesPerSecond < 0 {
		t.Fatal("same-epoch monotonic counters did not yield rate")
	}
	mu.Lock()
	upload, download = 5, 10
	many = true
	mu.Unlock()
	reset, truncated, err := controller.observeLocal(context.Background())
	if !errors.Is(err, errBusinessCounterSample) || reset.UploadBytesPerSecond != nil || reset.UploadTotal != second.UploadTotal || !truncated.Truncated || truncated.TotalActive != 201 || truncated.ReturnedCount != 200 {
		t.Fatal("owned counter regression must be unknown with bounded connection metadata")
	}
	if err = controller.closeLocal(context.Background(), "connection-1", "old-epoch"); err == nil {
		t.Fatal("stale epoch close accepted")
	}
	mu.Lock()
	if deletes != 0 || selects != 1 || probes != 1 {
		t.Errorf("unauthorized side effects: close=%d select=%d probe=%d", deletes, selects, probes)
	}
	mu.Unlock()
	if err = controller.closeLocal(context.Background(), "connection-1", controller.ProcessStatus().ProcessEpoch); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if deletes != 1 || connectionPresent {
		t.Fatal("close was not read back")
	}
}
