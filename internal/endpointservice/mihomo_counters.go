package endpointservice

import (
	"context"
	"errors"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

var errBusinessCounterEpoch = errors.New("business_counter_epoch_unavailable")
var errBusinessCounterSample = errors.New("business counter sample unsettled")

type nativeInbound struct {
	name, ip string
	port     int
}
type nativeShadowLedger struct {
	mu               sync.Mutex
	epoch            string
	owned            bool
	upload, download int64
	generation       uint64
	invalid          bool
	inbounds         map[nativeInbound]bool
}
type shadowSample struct {
	upload, download int64
	generation       uint64
	invalid          bool
}

func (l *nativeShadowLedger) snapshot() shadowSample {
	l.mu.Lock()
	defer l.mu.Unlock()
	return shadowSample{l.upload, l.download, l.generation, l.invalid}
}
func (l *nativeShadowLedger) add(upload bool, n int) {
	if n <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	value := &l.download
	if upload {
		value = &l.upload
	}
	if l.invalid || int64(n) > math.MaxInt64-*value || l.generation == math.MaxUint64 {
		l.invalid = true
		return
	}
	*value += int64(n)
	l.generation++
}

// The ledger belongs to the native epoch, not an egress gate. Old wrappers keep
// their old ledger after restart and cannot contaminate the new native counters.
func (c *MihomoController) nativeLedgerLocked() *nativeShadowLedger {
	epoch := c.localEpoch()
	owned := c.process != nil && epoch != ""
	if c.counterLedger == nil || c.counterLedger.epoch != epoch || c.counterLedger.owned != owned {
		c.counterLedger = &nativeShadowLedger{epoch: epoch, owned: owned, inbounds: map[nativeInbound]bool{}}
	}
	return c.counterLedger
}
func (c *MihomoController) registerNativeBackendsLocked(g *mihomoEgress, configuration MihomoConfiguration) {
	ledger := c.nativeLedgerLocked()
	ledger.inbounds[nativeInbound{"soha-backend-proxy", "127.0.0.1", g.proxyPort}] = true
	ledger.inbounds[nativeInbound{"soha-backend-direct", "127.0.0.1", g.directPort}] = true
	for id, port := range configuration.GuardNodePorts {
		ledger.inbounds[nativeInbound{"soha-owned-backend-" + id, "127.0.0.1", port}] = true
	}
	if ledger.owned {
		g.shadow = ledger
	}
}

type nativeShadowConnection struct {
	net.Conn
	ledger *nativeShadowLedger
}

func (c *nativeShadowConnection) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.ledger.add(false, n)
	return n, err
}
func (c *nativeShadowConnection) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.ledger.add(true, n)
	return n, err
}
func (c *nativeShadowConnection) Refresh(until time.Time) error {
	if r, ok := c.Conn.(interface{ Refresh(time.Time) error }); ok {
		return r.Refresh(until)
	}
	return c.Conn.SetDeadline(until)
}
func (g *mihomoEgress) countNativeBackend(conn net.Conn) net.Conn {
	if g.shadow == nil {
		return conn
	}
	return &nativeShadowConnection{Conn: conn, ledger: g.shadow}
}

type nativeConnectionMetadata struct {
	Host          string `json:"host"`
	DestinationIP string `json:"destinationIP"`
	Network       string `json:"network"`
	InboundName   string `json:"inboundName"`
	InboundIP     string `json:"inboundIP"`
	InboundPort   string `json:"inboundPort"`
	SourceIP      string `json:"sourceIP"`
	Type          string `json:"type"`
}
type nativeConnection struct {
	ID       string                   `json:"id"`
	Upload   int64                    `json:"upload"`
	Download int64                    `json:"download"`
	Start    time.Time                `json:"start"`
	Metadata nativeConnectionMetadata `json:"metadata"`
}
type nativeConnectionSnapshot struct {
	UploadTotal   int64              `json:"uploadTotal"`
	DownloadTotal int64              `json:"downloadTotal"`
	Connections   []nativeConnection `json:"connections"`
}

func (l *nativeShadowLedger) internal(item nativeConnection) bool {
	meta := item.Metadata
	port, err := strconv.Atoi(meta.InboundPort)
	inIP, inErr := netip.ParseAddr(meta.InboundIP)
	sourceIP, sourceErr := netip.ParseAddr(meta.SourceIP)
	return err == nil && inErr == nil && sourceErr == nil && inIP.IsLoopback() && sourceIP.IsLoopback() && meta.Type == "Socks5" && l.inbounds[nativeInbound{meta.InboundName, inIP.Unmap().String(), port}]
}

// Native and Go counters are asynchronous. The generation bracket detects Go
// commits during the HTTP read; it is not a native atomic-snapshot guarantee.
// Never derive a rate from a torn/regressing sample or clamp its totals to zero.
func (c *MihomoController) readBusinessSnapshotLocked(ctx context.Context) (nativeConnectionSnapshot, error) {
	ledger := c.nativeLedgerLocked()
	before := ledger.snapshot()
	var raw nativeConnectionSnapshot
	if c.request(ctx, http.MethodGet, "/connections", nil, http.StatusOK, &raw) != nil || len(raw.Connections) > 1_000_000 {
		return nativeConnectionSnapshot{}, errors.New("connection snapshot unavailable")
	}
	visible := make([]nativeConnection, 0, len(raw.Connections))
	for _, item := range raw.Connections {
		if !ledger.internal(item) {
			visible = append(visible, item)
		}
	}
	raw.Connections = visible
	if !ledger.owned {
		return raw, errBusinessCounterEpoch
	}
	if raw.UploadTotal < 0 || raw.DownloadTotal < 0 {
		return raw, errBusinessCounterSample
	}
	after := ledger.snapshot()
	if before.generation != after.generation || after.invalid || c.localEpoch() != ledger.epoch {
		return raw, errBusinessCounterSample
	}
	if c.observer.nativeEpoch == ledger.epoch && (raw.UploadTotal < c.observer.nativeUpload || raw.DownloadTotal < c.observer.nativeDownload) {
		return raw, errBusinessCounterSample
	}
	if after.upload > raw.UploadTotal || after.download > raw.DownloadTotal {
		return raw, errBusinessCounterSample
	}
	upload, download := raw.UploadTotal-after.upload, raw.DownloadTotal-after.download
	previous := c.observer.traffic
	if previous.ProcessEpoch == ledger.epoch && (upload < previous.UploadTotal || download < previous.DownloadTotal) {
		return raw, errBusinessCounterSample
	}
	c.observer.nativeEpoch = ledger.epoch
	c.observer.nativeUpload = raw.UploadTotal
	c.observer.nativeDownload = raw.DownloadTotal
	raw.UploadTotal, raw.DownloadTotal = upload, download
	return raw, nil
}
