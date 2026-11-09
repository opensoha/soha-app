//go:build !windows

package endpointservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opensoha/soha-contracts/proxytransport"
)

type counterHarness struct {
	mu         sync.Mutex
	raw        nativeConnectionSnapshot
	duringRead func()
	deletes    []string
	c          *MihomoController
}

func newCounterHarness(t *testing.T, owned bool) *counterHarness {
	t.Helper()
	h := &counterHarness{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if r.Method == http.MethodGet && r.URL.Path == "/connections" {
			if h.duringRead != nil {
				h.duringRead()
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(h.raw)
			return
		}
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/connections/") {
			id := strings.TrimPrefix(r.URL.Path, "/connections/")
			h.deletes = append(h.deletes, id)
			items := h.raw.Connections[:0]
			for _, item := range h.raw.Connections {
				if item.ID != id {
					items = append(items, item)
				}
			}
			h.raw.Connections = items
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	h.c, _ = NewMihomoController(server.URL, strings.Repeat("s", 32))
	h.c.applied = expectedMihomoReadback(managedMihomoConfiguration(h.c.port))
	if owned {
		fixture, _ := processFixture(t)
		if err := fixture.process.start(context.Background(), "", func(context.Context) error { return nil }); err != nil {
			t.Fatal(err)
		}
		h.c.process = fixture.process
		t.Cleanup(func() { _ = fixture.process.stop(context.Background()) })
	}
	return h
}
func (h *counterHarness) gate(port int) *mihomoEgress {
	g := &mihomoEgress{proxyPort: port, directPort: port + 1}
	h.c.mu.Lock()
	h.c.registerNativeBackendsLocked(g, MihomoConfiguration{GuardNodePorts: map[string]int{"node-a": port + 2}})
	h.c.mu.Unlock()
	return g
}
func (h *counterHarness) set(up, down int64, items ...nativeConnection) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.raw = nativeConnectionSnapshot{UploadTotal: up, DownloadTotal: down, Connections: items}
}
func businessItem(id string) nativeConnection {
	return nativeConnection{ID: id, Metadata: nativeConnectionMetadata{Host: "destination.example", Network: "tcp", InboundName: "DEFAULT-MIXED", InboundPort: "7890", InboundIP: "127.0.0.1", SourceIP: "127.0.0.1", Type: "Socks5"}}
}
func internalItem(id string, port int) nativeConnection {
	item := businessItem(id)
	item.Metadata.InboundName = "soha-owned-backend-node-a"
	item.Metadata.InboundPort = fmt.Sprint(port)
	return item
}

// These are real wrapper Read/Write operations, not manually added ledger totals.
func counterPayload(t *testing.T, gate *mihomoEgress, packet, counted bool, up, down int) {
	t.Helper()
	a, b := net.Pipe()
	var conn, peer net.Conn = a, b
	if packet {
		var err error
		conn, err = proxytransport.NewPacketConn(a, time.Now().Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		peer, err = proxytransport.NewPacketConn(b, time.Now().Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
	}
	if counted {
		conn = gate.countNativeBackend(conn)
	}
	tracked, err := gate.trackNode("node-a", conn)
	if err != nil {
		t.Fatal(err)
	}
	defer tracked.Close()
	defer peer.Close()
	done := make(chan error, 1)
	go func() {
		buffer := make([]byte, up)
		var err error
		if packet {
			var n int
			n, err = peer.Read(buffer)
			if n != up && err == nil {
				err = io.ErrUnexpectedEOF
			}
		} else {
			_, err = io.ReadFull(peer, buffer)
		}
		if err == nil {
			_, err = peer.Write(bytes.Repeat([]byte{'d'}, down))
		}
		done <- err
	}()
	if n, err := tracked.Write(bytes.Repeat([]byte{'u'}, up)); err != nil || n != up {
		t.Fatalf("payload upload n=%d err=%v", n, err)
	}
	buffer := make([]byte, down)
	if packet {
		n, err := tracked.Read(buffer)
		if err != nil || n != down {
			t.Fatalf("payload download n=%d err=%v", n, err)
		}
	} else if _, err := io.ReadFull(tracked, buffer); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestMihomoBusinessCountersDirectMappedTCPUDPAndClosedCumulative(t *testing.T) {
	for _, packet := range []bool{false, true} {
		for _, direct := range []bool{false, true} {
			t.Run(fmt.Sprintf("udp=%v/direct=%v", packet, direct), func(t *testing.T) {
				h := newCounterHarness(t, true)
				g := h.gate(18080)
				counterPayload(t, g, packet, direct, 80, 112)
				// Source bridge traffic is registered for revocation, never shadow-counted.
				if direct {
					counterPayload(t, g, packet, false, 80, 112)
				}
				up, down := int64(87), int64(123)
				if direct {
					up, down = 167, 235
				}
				h.set(up, down, businessItem("vpn-business"), internalItem("hidden-backend", 18082))
				traffic, connections, err := h.c.observeLocal(context.Background())
				if err != nil || traffic.UploadTotal != 87 || traffic.DownloadTotal != 123 || connections.TotalActive != 1 || connections.Items[0].ConnectionID != "vpn-business" {
					t.Fatalf("business sample %#v %#v %v", traffic, connections, err)
				}
				if len(g.nodeConnections) != 0 {
					t.Fatal("payload flows must already be closed before first sample")
				}
				flow, err := h.c.ProxyFlowSnapshot(context.Background())
				if err != nil || flow.UploadTotal != 87 || flow.DownloadTotal != 123 || flow.ActiveConnections != 1 || flow.ProcessEpoch != traffic.ProcessEpoch {
					t.Fatal("telemetry did not share normalized sample", flow, err)
				}
				// Replacing a gate in the same native epoch keeps closed-byte corrections.
				newGate := h.gate(19080)
				if direct {
					counterPayload(t, newGate, packet, true, 20, 30)
				}
				if direct {
					up, down = 207, 295
				} else {
					up, down = 107, 153
				}
				h.set(up, down, internalItem("closed-gate-inbound", 18082), internalItem("new-gate-inbound", 19082), businessItem("vpn-business"))
				after, active, err := h.c.observeLocal(context.Background())
				if err != nil || after.UploadTotal != 107 || after.DownloadTotal != 153 || active.TotalActive != 1 {
					t.Fatal("gate replacement lost cumulative totals", after, err)
				}
			})
		}
	}
}

type partialCounterConn struct{ net.Conn }

func (*partialCounterConn) Write(p []byte) (int, error) { return len(p), io.ErrUnexpectedEOF }
func (*partialCounterConn) Read(p []byte) (int, error)  { copy(p, "abc"); return 3, io.EOF }
func (*partialCounterConn) Close() error                { return nil }

func TestMihomoBusinessCounterErrorsMutationIdleAndEpoch(t *testing.T) {
	h := newCounterHarness(t, true)
	g := h.gate(18080)
	conn := g.countNativeBackend(&partialCounterConn{})
	if _, err := conn.Write([]byte("abcd")); err == nil {
		t.Fatal("partial error fixture")
	}
	_, _ = conn.Read(make([]byte, 8))
	h.set(8, 6)
	first, _, err := h.c.observeLocal(context.Background())
	if err != nil || first.UploadTotal != 4 || first.DownloadTotal != 3 {
		t.Fatal("positive n with error was not counted", first, err)
	}
	for _, bad := range []struct{ up, down int64 }{{3, 6}, {7, 6}, {-1, 6}} {
		h.set(bad.up, bad.down)
		traffic, _, err := h.c.observeLocal(context.Background())
		if !errors.Is(err, errBusinessCounterSample) || traffic.UploadTotal != 4 || traffic.UploadBytesPerSecond != nil || traffic.State != "unknown" {
			t.Fatal("counter underflow/regression fabricated a value", traffic, err)
		}
	}
	h.set(20, 6)
	h.mu.Lock()
	h.duringRead = func() { _, _ = conn.Write([]byte("x")) }
	h.mu.Unlock()
	if _, _, err := h.c.observeLocal(context.Background()); !errors.Is(err, errBusinessCounterSample) {
		t.Fatal("mutation during HTTP snapshot accepted")
	}
	h.mu.Lock()
	h.duringRead = nil
	h.mu.Unlock()
	// A blocked reader does not mutate the ledger or permanently suppress samples.
	a, b := net.Pipe()
	idle := g.countNativeBackend(a)
	done := make(chan struct{})
	go func() { _, _ = idle.Read(make([]byte, 8)); close(done) }()
	if _, _, err := h.c.observeLocal(context.Background()); err != nil {
		t.Fatal("idle blocked reader made sampling unavailable", err)
	}
	_ = b.Close()
	_ = idle.Close()
	<-done
	h.c.mu.Lock()
	h.c.observer.traffic.ObservedAt = time.Now().Add(-61 * time.Second)
	h.c.mu.Unlock()
	h.set(30, 6)
	gap, _, err := h.c.observeLocal(context.Background())
	if err != nil || gap.State != "gap" || gap.UploadBytesPerSecond != nil || gap.DownloadBytesPerSecond != nil {
		t.Fatal("recovery across a sampling gap invented a fresh rate", gap, err)
	}
	oldEpoch := h.c.ProcessStatus().ProcessEpoch
	if err := h.c.process.stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := h.c.process.start(context.Background(), "", func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if h.c.ProcessStatus().ProcessEpoch == oldEpoch {
		t.Fatal("native epoch did not change")
	}
	newGate := h.gate(20080)
	_, _ = conn.Write([]byte("late old epoch completion"))
	h.set(10, 15)
	reset, _, err := h.c.observeLocal(context.Background())
	if err != nil || reset.UploadTotal != 10 || reset.DownloadTotal != 15 || reset.UploadBytesPerSecond != nil || newGate.shadow == g.shadow {
		t.Fatal("old ledger contaminated new native epoch", reset, err)
	}
	newGate.shadow.mu.Lock()
	newGate.shadow.upload = math.MaxInt64 - 1
	newGate.shadow.mu.Unlock()
	_, _ = newGate.countNativeBackend(&partialCounterConn{}).Write([]byte("overflow"))
	h.set(math.MaxInt64, 15)
	if _, _, err := h.c.observeLocal(context.Background()); !errors.Is(err, errBusinessCounterSample) {
		t.Fatal("positive overflow accepted")
	}
}

func TestMihomoBusinessConnectionFilterBeforeBoundAndEpochClose(t *testing.T) {
	h := newCounterHarness(t, true)
	_ = h.gate(18080)
	items := []nativeConnection{}
	for i := 0; i < 205; i++ {
		items = append(items, internalItem(fmt.Sprintf("hidden-%d", i), 18082))
	}
	items = append(items, businessItem("outer-a"), businessItem("outer-b"))
	other := internalItem("different-port-user", 18083)
	items = append(items, other)
	h.set(100, 200, items...)
	_, visible, err := h.c.observeLocal(context.Background())
	if err != nil || visible.TotalActive != 3 || visible.ReturnedCount != 3 || visible.Truncated {
		t.Fatal("filter was applied after limit or hid unrelated traffic", visible, err)
	}
	epoch := h.c.ProcessStatus().ProcessEpoch
	if err := h.c.closeLocal(context.Background(), "hidden-0", epoch); err == nil {
		t.Fatal("internal connection ID accepted")
	}
	if err := h.c.closeLocal(context.Background(), "outer-a", "stale-epoch"); err == nil {
		t.Fatal("stale close accepted")
	}
	if err := h.c.closeLocal(context.Background(), "outer-a", epoch); err != nil {
		t.Fatal(err)
	}
	_, after, err := h.c.observeLocal(context.Background())
	if err != nil || after.TotalActive != 2 {
		t.Fatal("business close damaged unrelated B", after, err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.deletes) != 1 || h.deletes[0] != "outer-a" {
		t.Fatal("hidden/stale ID reached native delete")
	}
}

func TestMihomoExternalBusinessCountersUnavailable(t *testing.T) {
	h := newCounterHarness(t, false)
	_ = h.gate(18080)
	h.set(160, 224, internalItem("hidden", 18082), businessItem("outer"))
	traffic, connections, err := h.c.observeLocal(context.Background())
	if !errors.Is(err, errBusinessCounterEpoch) || traffic.State != "unavailable" || traffic.UploadBytesPerSecond != nil || traffic.ProcessEpoch != "" || connections.TotalActive != 1 {
		t.Fatal("external history was presented as fresh business counters", traffic, connections, err)
	}
	if _, err := h.c.ProxyFlowSnapshot(context.Background()); !errors.Is(err, errBusinessCounterEpoch) {
		t.Fatal("external telemetry accepted untrusted baseline")
	}
	if err := h.c.closeLocal(context.Background(), "outer", "any"); !errors.Is(err, ErrMihomoProcessUnsupported) {
		t.Fatal("external close enabled")
	}
	e, _ := NewCoordinatedExecutor(&fakeConfigurationExecutor{}, h.c)
	e.mihomoActive = true
	configuration := managedMihomoConfiguration(h.c.port)
	view := e.workbench(context.Background(), h.c, configuration, nil)
	found := false
	for _, capability := range view.Capabilities {
		if capability.Name == "traffic" && capability.State == "unavailable" && capability.ReasonCode == "business_counter_epoch_unavailable" {
			found = true
		}
	}
	if !found || view.Traffic.State != "unavailable" || view.Connections.TotalActive != 1 {
		t.Fatal("external uncertainty was not exposed through existing workbench fields")
	}
}

func TestMihomoTelemetryBaselineIncludesNativeEpoch(t *testing.T) {
	client, err := NewTelemetryClient("https://control.example.test", "endpoint-1", http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := ProxyFlowSnapshot{Active: true, Engine: "mihomo", Mode: "managed_follow", ProfileID: "profile-1", ProfileRevision: 1, SelectedProxy: "node-a", ProcessEpoch: "epoch-a", UploadTotal: 100, DownloadTotal: 200}
	now := time.Now()
	if _, ok := client.proxyAggregate(now, snapshot); !ok {
		t.Fatal("initial baseline rejected")
	}
	snapshot.UploadTotal = 150
	snapshot.DownloadTotal = 260
	value, ok := client.proxyAggregate(now.Add(time.Second), snapshot)
	if !ok {
		t.Fatal("same epoch rejected")
	}
	read := func(value any) (int64, int64) {
		raw, _ := json.Marshal(value)
		var flow struct {
			UploadBytes   int64 `json:"uploadBytes"`
			DownloadBytes int64 `json:"downloadBytes"`
		}
		if json.Unmarshal(raw, &flow) != nil {
			t.Fatal("aggregate invalid")
		}
		return flow.UploadBytes, flow.DownloadBytes
	}
	if up, down := read(value); up != 50 || down != 60 {
		t.Fatal("same epoch delta incorrect")
	}
	snapshot.ProcessEpoch = "epoch-b"
	snapshot.UploadTotal = 1000
	snapshot.DownloadTotal = 2000
	value, ok = client.proxyAggregate(now.Add(2*time.Second), snapshot)
	if !ok {
		t.Fatal("new epoch rejected")
	}
	if up, down := read(value); up != 0 || down != 0 {
		t.Fatal("new native process reused old telemetry baseline")
	}
}
