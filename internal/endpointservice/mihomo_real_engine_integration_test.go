//go:build !windows

package endpointservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/opensoha/soha-contracts/gen/go/sohaapi"
	"github.com/opensoha/soha-contracts/proxytransport"
	"go.yaml.in/yaml/v3"
	"golang.org/x/net/proxy"
)

// Opt-in portable receiver proof. TLS/auth/projection and A/B source servers are
// fixtures, not a Core/PostgreSQL chain or native App/OS networking acceptance.
func TestMihomoRealEngineIntegration(t *testing.T) {
	binary := os.Getenv("SOHA_REAL_MIHOMO_BINARY")
	if binary == "" {
		t.Skip("owned Mihomo v1.19.30 binary is not configured")
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	output, err := exec.Command(binary, "-v").Output()
	if err != nil {
		t.Fatal(err)
	}
	version := strings.Split(strings.TrimSpace(string(output)), "\n")[0]
	if !strings.Contains(version, "v1.19.30") {
		t.Fatal("requires pinned v1.19.30")
	}
	t.Logf("portable owned engine sha256=%s version=%s", digest, version)
	for _, mode := range []string{"mapped_nodes", "direct_subscription", "direct_bad_relay"} {
		t.Run(mode, func(t *testing.T) { realAppEngineScenario(t, binary, digest, version, mode) })
	}
}

type realAppCountTransport struct {
	deletes      atomic.Int64
	base         http.RoundTripper
	puts         atomic.Int64
	frontPort    int
	trace        []string
	controller   *MihomoController
	delayReasons []string
}

func (r *realAppCountTransport) RoundTrip(q *http.Request) (*http.Response, error) {
	if q.Method == http.MethodDelete && strings.HasPrefix(q.URL.Path, "/connections/") {
		r.deletes.Add(1)
	}
	if q.Method == http.MethodPut && q.URL.Path == "/configs" {
		r.puts.Add(1)
		raw, err := io.ReadAll(q.Body)
		if err != nil {
			return nil, err
		}
		q.Body = io.NopCloser(bytes.NewReader(raw))
		var body struct{ Payload string }
		var rendered struct {
			Proxies []struct {
				Name string
				Port int
			}
		}
		if json.Unmarshal(raw, &body) == nil && yaml.Unmarshal([]byte(body.Payload), &rendered) == nil {
			for _, p := range rendered.Proxies {
				if p.Name == "node-a" {
					r.frontPort = p.Port
				}
			}
		}
	}
	response, err := r.base.RoundTrip(q)
	if response != nil && response.StatusCode == 503 && strings.HasSuffix(q.URL.Path, "/delay") {
		original := response.Body
		raw, readErr := io.ReadAll(io.LimitReader(original, 4096))
		response.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(raw), original), original}
		var body struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &body) == nil {
			message := body.Message
			if r.controller.egress != nil {
				message = strings.ReplaceAll(message, r.controller.egress.probeHost, "private.invalid")
			}
			if len(message) > 512 {
				message = message[:512]
			}
			r.delayReasons = append(r.delayReasons, fmt.Sprintf("%q readError=%T", message, readErr))
			follow := q.Clone(q.Context())
			u := *q.URL
			u.Path = strings.TrimSuffix(u.Path, "/delay")
			u.RawQuery = ""
			follow.URL = &u
			historyResponse, historyErr := r.base.RoundTrip(follow)
			if historyErr == nil {
				var history struct {
					Alive   bool `json:"alive"`
					History []struct {
						Delay uint16 `json:"delay"`
					} `json:"history"`
				}
				decodeErr := json.NewDecoder(io.LimitReader(historyResponse.Body, 4096)).Decode(&history)
				historyResponse.Body.Close()
				encoded, _ := json.Marshal(history)
				r.delayReasons = append(r.delayReasons, fmt.Sprintf("history status=%d decode=%T %s", historyResponse.StatusCode, decodeErr, encoded))
			}

		}
	}
	if response != nil && response.StatusCode >= 400 && r.controller != nil && r.controller.egress != nil {
		g := r.controller.egress
		r.trace = append(r.trace, fmt.Sprintf("probeCounts proxy=%d direct=%d", g.proxyProbes.Load(), g.directProbes.Load()))
	}
	if response != nil {
		r.trace = append(r.trace, fmt.Sprintf("%s %s %d", q.Method, q.URL.Path, response.StatusCode))
	}
	return response, err
}

func realAppPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// Source fixture addresses stay inside the disposable container. Production
// bootstrap/relay checks remain intact; no fixture dials the final public target.
func realAppFixtureIP(t *testing.T) string {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addresses {
		ip, _, _ := net.ParseCIDR(a.String())
		if ip.To4() != nil && ip.IsPrivate() && !ip.IsLoopback() {
			return ip.String()
		}
	}
	t.Fatal("requires disposable container private IPv4")
	return ""
}

type realAppUpstream struct {
	address, loopback string
	tcp, packets      atomic.Int64
	associations      atomic.Int64
	badRelay          atomic.Pointer[net.UDPAddr]
}

func realAppSource(t *testing.T, id, ip string, until time.Time) *realAppUpstream {
	t.Helper()
	u := &realAppUpstream{}
	serve := func(host string) string {
		listener, err := net.Listen("tcp4", net.JoinHostPort(host, "0"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		go func() {
			for {
				c, err := listener.Accept()
				if err != nil {
					return
				}
				t.Cleanup(func() { c.Close() })
				go func() {
					defer c.Close()
					c.SetDeadline(until)
					var head [2]byte
					if _, err := io.ReadFull(c, head[:]); err != nil || head[0] != 5 {
						return
					}
					methods := make([]byte, int(head[1]))
					if _, err := io.ReadFull(c, methods); err != nil {
						return
					}
					// Both production mapped client and native source adapter use this fixture credential.
					if _, err := c.Write([]byte{5, 2}); err != nil {
						return
					}
					if _, err := io.ReadFull(c, head[:]); err != nil || head[0] != 1 {
						return
					}
					user := make([]byte, int(head[1]))
					if _, err := io.ReadFull(c, user); err != nil {
						return
					}
					var length [1]byte
					if _, err := io.ReadFull(c, length[:]); err != nil {
						return
					}
					password := make([]byte, int(length[0]))
					if _, err := io.ReadFull(c, password); err != nil || string(user) != "fixture" || string(password) != "fixture-secret-0123456789abcdef0123456789abcdef" {
						return
					}
					c.Write([]byte{1, 0})
					var request [4]byte
					if _, err := io.ReadFull(c, request[:]); err != nil || request[0] != 5 {
						return
					}
					count := 0
					switch request[3] {
					case 1:
						count = 4
					case 4:
						count = 16
					case 3:
						if _, err := io.ReadFull(c, length[:]); err != nil {
							return
						}
						count = int(length[0])
					default:
						return
					}
					if _, err := io.CopyN(io.Discard, c, int64(count+2)); err != nil {
						return
					}
					if request[1] == 1 {
						c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
						buffer := make([]byte, 65507)
						for {
							n, err := c.Read(buffer)
							if err != nil {
								return
							}
							u.tcp.Add(1)
							if _, err := c.Write(append([]byte(id+":"), buffer[:n]...)); err != nil {
								return
							}
						}
					}
					if request[1] != 3 {
						return
					}
					u.associations.Add(1)
					socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(host)})
					if err != nil {
						return
					}
					defer socket.Close()
					socket.SetDeadline(until)
					relay := socket.LocalAddr().(*net.UDPAddr)
					if bad := u.badRelay.Load(); bad != nil {
						relay = bad
					}
					reply := append([]byte{5, 0, 0, 1}, relay.IP.To4()...)
					reply = append(reply, byte(relay.Port>>8), byte(relay.Port))
					if _, err := c.Write(reply); err != nil {
						return
					}
					done := make(chan struct{})
					go func() {
						defer close(done)
						buffer := make([]byte, 65507)
						for {
							n, peer, err := socket.ReadFromUDP(buffer)
							if err != nil {
								return
							}
							u.packets.Add(1)
							if n < 10 || !bytes.Equal(buffer[:4], []byte{0, 0, 0, 1}) {
								continue
							}
							response := append([]byte(nil), buffer[:10]...)
							response = append(response, []byte(id+":")...)
							response = append(response, buffer[10:n]...)
							if _, err = socket.WriteToUDP(response, peer); err != nil {
								return
							}
						}
					}()
					io.Copy(io.Discard, c)
					socket.Close()
					<-done
				}()
			}
		}()
		return listener.Addr().String()
	}
	u.loopback = serve("127.0.0.1")
	u.address = serve(ip)
	return u
}

func realAppTCP(t *testing.T, address, user, secret string) net.Conn {
	t.Helper()
	var auth *proxy.Auth
	if user != "" {
		auth = &proxy.Auth{User: user, Password: secret}
	}
	d, err := proxy.SOCKS5("tcp", address, auth, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := d.(proxy.ContextDialer).DialContext(ctx, "tcp", "8.8.8.8:53")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// Native mixed ingress has no authentication configured. This client only
// targets its owned loopback SOCKS listener and one fixed fixture destination.
type realAppNativePacket struct {
	*net.UDPConn
	control net.Conn
	header  []byte
}

func (c *realAppNativePacket) Close() error { c.control.Close(); return c.UDPConn.Close() }
func (c *realAppNativePacket) Write(b []byte) (int, error) {
	header := c.header
	_, err := c.UDPConn.Write(append(header, b...))
	if err != nil {
		return 0, err
	}
	return len(b), nil
}
func (c *realAppNativePacket) Read(b []byte) (int, error) {
	frame := make([]byte, 65507)
	n, err := c.UDPConn.Read(frame)
	if err != nil {
		return 0, err
	}
	if n < 10 || !bytes.Equal(frame[:10], c.header) || n-10 > len(b) {
		return 0, fmt.Errorf("invalid native UDP fixture response")
	}
	return copy(b, frame[10:n]), nil
}
func realAppNativeUDP(t *testing.T, address string, portOption ...int) net.Conn {
	port := 53
	if len(portOption) > 0 {
		port = portOption[0]
	}
	t.Helper()
	control, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	control.SetDeadline(time.Now().Add(time.Second))
	control.Write([]byte{5, 1, 0})
	var method [2]byte
	if _, err = io.ReadFull(control, method[:]); err != nil || method != [2]byte{5, 0} {
		control.Close()
		t.Fatal("native SOCKS no-auth handshake failed")
	}
	control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	var reply [10]byte
	if _, err = io.ReadFull(control, reply[:]); err != nil || !bytes.Equal(reply[:4], []byte{5, 0, 0, 1}) {
		control.Close()
		t.Fatal("native UDP association failed")
	}
	host := net.IP(reply[4:8])
	if host.IsUnspecified() {
		host = net.ParseIP("127.0.0.1")
	}
	if !host.IsLoopback() {
		control.Close()
		t.Fatal("native relay outside owned loopback")
	}
	relay := &net.UDPAddr{IP: host, Port: int(reply[8])<<8 | int(reply[9])}
	socket, err := net.DialUDP("udp4", nil, relay)
	if err != nil {
		control.Close()
		t.Fatal(err)
	}
	control.SetDeadline(time.Time{})
	c := &realAppNativePacket{UDPConn: socket, control: control, header: []byte{0, 0, 0, 1, 8, 8, 8, 8, byte(port >> 8), byte(port)}}
	t.Cleanup(func() { c.Close() })
	return c
}

func realAppEcho(t *testing.T, c net.Conn, id string, packet bool) {
	t.Helper()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	payload := []byte("proof")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 64)
	var n int
	var err error
	if packet {
		n, err = c.Read(b)
	} else {
		n, err = io.ReadFull(c, b[:len(id)+1+len(payload)])
	}
	if err != nil || !bytes.Equal(b[:n], append([]byte(id+":"), payload...)) {
		t.Fatalf("identified %s echo failed packet=%v n=%d err=%v", id, packet, n, err)
	}
	c.SetDeadline(time.Time{})
}
func realAppDenied(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetDeadline(time.Now().Add(120 * time.Millisecond))
	_, _ = c.Write([]byte("denied"))
	if _, err := c.Read(make([]byte, 64)); err == nil {
		t.Fatal("unauthorized data returned")
	}
}

// R06 captures native-source counters without assuming they equal user payload
// bytes. Only safe inbound metadata is retained; destinations/auth never leave.
func realAppR06(t *testing.T, c *MihomoController, label string) {
	t.Helper()
	var raw struct {
		UploadTotal   int64 `json:"uploadTotal"`
		DownloadTotal int64 `json:"downloadTotal"`
		Connections   []struct {
			Upload   int64 `json:"upload"`
			Download int64 `json:"download"`
			Metadata struct {
				InboundName string `json:"inboundName"`
				InboundPort string `json:"inboundPort"`
				InboundType string `json:"inboundType"`
				Type        string `json:"type"`
				Network     string `json:"network"`
			} `json:"metadata"`
		} `json:"connections"`
	}
	if err := c.request(context.Background(), http.MethodGet, "/connections", nil, http.StatusOK, &raw); err != nil {
		t.Fatal(err)
	}
	traffic, connections, err := c.observeLocal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(raw)
	t.Logf("R06 %s native=%s workbenchUp=%d workbenchDown=%d workbenchActive=%d", label, encoded, traffic.UploadTotal, traffic.DownloadTotal, connections.TotalActive)
}

// Samples are asynchronous. These bounded polls perform no business I/O and
// retain unsettled errors; exact assertions apply only after payload round trips.
func realAppBusiness(t *testing.T, c *MihomoController, label string, up, down int64, active int) (ProxyTraffic, ProxyConnections) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	unsettled := 0
	var traffic ProxyTraffic
	var connections ProxyConnections
	var flow ProxyFlowSnapshot
	var err error
	for time.Now().Before(deadline) {
		traffic, connections, err = c.observeLocal(context.Background())
		if err != nil && !errors.Is(err, errBusinessCounterSample) {
			t.Fatal(err)
		}
		if err != nil {
			unsettled++
		} else {
			flow, err = c.ProxyFlowSnapshot(context.Background())
			if err != nil && !errors.Is(err, errBusinessCounterSample) {
				t.Fatal(err)
			}
			epoch := c.ProcessStatus().ProcessEpoch
			if err == nil && traffic.UploadTotal == up && traffic.DownloadTotal == down && connections.TotalActive == active && connections.ReturnedCount == active && len(connections.Items) == active && !connections.Truncated && flow.UploadTotal == up && flow.DownloadTotal == down && flow.ActiveConnections == int64(active) && flow.ProcessEpoch == epoch && traffic.ProcessEpoch == epoch && connections.ProcessEpoch == epoch {
				t.Logf("R06 ASSERT %s businessUp=%d businessDown=%d active=%d epoch=%s unsettledSamples=%d", label, up, down, active, epoch, unsettled)
				return traffic, connections
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("R06 unsettled/mismatch %s want=%d/%d active=%d observed=%d/%d active=%d flow=%d/%d active=%d err=%v unsettled=%d", label, up, down, active, traffic.UploadTotal, traffic.DownloadTotal, connections.TotalActive, flow.UploadTotal, flow.DownloadTotal, flow.ActiveConnections, err, unsettled)
	return traffic, connections
}
func realAppNativeSnapshot(t *testing.T, c *MihomoController) nativeConnectionSnapshot {
	t.Helper()
	var raw nativeConnectionSnapshot
	if err := c.request(context.Background(), http.MethodGet, "/connections", nil, http.StatusOK, &raw); err != nil {
		t.Fatal(err)
	}
	return raw
}
func realAppRawTotals(t *testing.T, c *MihomoController, label string, up, down int64, active int) {
	t.Helper()
	raw := realAppNativeSnapshot(t, c)
	if raw.UploadTotal != up || raw.DownloadTotal != down || len(raw.Connections) != active {
		t.Fatalf("R06 native-source %s expected=%d/%d active%d got=%d/%d active%d", label, up, down, active, raw.UploadTotal, raw.DownloadTotal, len(raw.Connections))
	}
}
func realAppVisibleClose(t *testing.T, e *CoordinatedExecutor, c *MihomoController, transport *realAppCountTransport, native, mode string, bTCP, bUDP, bNativeUDP net.Conn) {
	t.Helper()
	var traffic ProxyTraffic
	var snapshot ProxyConnections
	deadline := time.Now().Add(3 * time.Second)
	for {
		var err error
		traffic, snapshot, err = c.observeLocal(context.Background())
		if err == nil {
			break
		}
		if !errors.Is(err, errBusinessCounterSample) || time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	beforeIDs := map[string]bool{}
	for _, item := range snapshot.Items {
		beforeIDs[item.ConnectionID] = true
	}
	rawBefore := realAppNativeSnapshot(t, c)
	nativeIDs := map[string]bool{}
	for _, item := range rawBefore.Connections {
		nativeIDs[item.ID] = true
	}
	extra := realAppTCP(t, native, "", "")
	realAppEcho(t, extra, "B", false)
	_, after := realAppBusiness(t, c, "extra-visible-B", traffic.UploadTotal+5, traffic.DownloadTotal+7, snapshot.TotalActive+1)
	visibleID := ""
	for _, item := range after.Items {
		if !beforeIDs[item.ConnectionID] {
			if visibleID != "" || item.Network != "tcp" {
				t.Fatal("extra B did not create exactly one visible TCP leg")
			}
			visibleID = item.ConnectionID
		}
	}
	if visibleID == "" {
		t.Fatal("extra visible B absent")
	}
	epoch := c.ProcessStatus().ProcessEpoch
	deletes := transport.deletes.Load()
	closeAction := func(id, epoch string) error {
		_, err := e.Proxy(context.Background(), &ProxyAction{Kind: "close", ConnectionID: id, ProcessEpoch: epoch}, nil)
		return err
	}
	if closeAction(visibleID, "old-"+epoch) == nil || transport.deletes.Load() != deletes {
		t.Fatal("old epoch reached native DELETE")
	}
	if mode == "direct_subscription" {
		raw := realAppNativeSnapshot(t, c)
		internalID := ""
		for _, item := range raw.Connections {
			if !nativeIDs[item.ID] && item.Metadata.InboundName == "soha-owned-backend-node-b" && item.Metadata.Network == "tcp" {
				internalID = item.ID
			}
		}
		if internalID == "" {
			t.Fatal("extra B internal backend leg absent from native source")
		}
		for _, item := range after.Items {
			if item.ConnectionID == internalID {
				t.Fatal("internal leg leaked into visible bounded snapshot")
			}
		}
		if closeAction(internalID, epoch) == nil || transport.deletes.Load() != deletes {
			t.Fatal("internal backend ID reached native DELETE")
		}
	}
	if err := closeAction(visibleID, epoch); err != nil {
		t.Fatal(err)
	}
	if transport.deletes.Load() != deletes+1 {
		t.Fatal("visible close did not issue exactly one native DELETE")
	}
	extra.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := extra.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatal("visible B close did not close its stream")
	}
	realAppBusiness(t, c, "closed-payload-retained", traffic.UploadTotal+5, traffic.DownloadTotal+7, snapshot.TotalActive)
	realAppEcho(t, bTCP, "B", false)
	realAppEcho(t, bUDP, "B", true)
	realAppEcho(t, bNativeUDP, "B", true)
	t.Logf("R06 CLOSE %s visibleBclosed onlyOnce=true staleEpochDenied=true internalBackendDenied=%v existingB TCP/UDP continue", mode, mode == "direct_subscription")
}

func realAppEngineScenario(t *testing.T, binary, digest, version, mode string) {
	badRelay := mode == "direct_bad_relay"
	if badRelay {
		mode = "direct_subscription"
	}
	now := time.Now().UTC()
	config := twoNodeBundle(now)
	config.MixedPort = realAppPort(t)
	config.ControllerPort = realAppPort(t)
	config.Protection.CIDRs = []string{"10.1.1.0/24"}
	ip := realAppFixtureIP(t)
	until := now.Add(90 * time.Second)
	aSource, bSource := realAppSource(t, "A", ip, until), realAppSource(t, "B", ip, until)
	sources := map[string]*realAppUpstream{"node-a": aSource, "node-b": bSource}
	var witnessPackets atomic.Int64
	if badRelay {
		witness, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { witness.Close() })
		aSource.badRelay.Store(witness.LocalAddr().(*net.UDPAddr))
		go func() {
			b := make([]byte, 65507)
			for {
				if _, _, err := witness.ReadFromUDP(b); err != nil {
					return
				}
				witnessPackets.Add(1)
			}
		}()
	}
	p := config.Projection
	credentials := map[string]string{}
	for id := range sources {
		user, _ := proxytransport.EncodeMappedUsername(p.Credential.CredentialID, id)
		credentials[user] = p.Credential.Secret
	}
	mappedSource := func(user string) *realAppUpstream {
		_, id, _ := proxytransport.DecodeMappedUsername(user)
		return sources[id]
	}
	tcpHandler, err := proxytransport.New(credentials, func(ctx context.Context, user, target string) (net.Conn, error) {
		u := mappedSource(user)
		if u == nil {
			return nil, fmt.Errorf("unknown node")
		}
		d, err := proxy.SOCKS5("tcp", u.loopback, &proxy.Auth{User: "fixture", Password: "fixture-secret-0123456789abcdef0123456789abcdef"}, &net.Dialer{})
		if err != nil {
			return nil, err
		}
		return d.(proxy.ContextDialer).DialContext(ctx, "tcp", target)
	}, until)
	if err != nil {
		t.Fatal(err)
	}
	defer tcpHandler.Close()
	var packetDials, packetRequests atomic.Int64
	packetHandler, err := proxytransport.NewPacketHandler(credentials, func(ctx context.Context, user, target string) (net.Conn, error) {
		packetDials.Add(1)
		u := mappedSource(user)
		if u == nil {
			return nil, fmt.Errorf("unknown node")
		}
		return proxytransport.DialSOCKS5UDP(ctx, u.loopback, "fixture", "fixture-secret-0123456789abcdef0123456789abcdef", target, until)
	}, func(context.Context, string, string) error { return nil }, until)
	if err != nil {
		t.Fatal(err)
	}
	defer packetHandler.Close()
	relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.Header.Values("Soha-Transport")) != 0 {
			packetRequests.Add(1)
			packetHandler.ServeHTTP(w, r)
		} else {
			tcpHandler.ServeHTTP(w, r)
		}
	}))
	defer relay.Close()
	p.Endpoints[0].URL = relay.URL
	if mode == "direct_subscription" {
		nodes := []map[string]any{}
		for _, id := range []string{"node-a", "node-b"} {
			host, port, _ := net.SplitHostPort(sources[id].address)
			nodes = append(nodes, map[string]any{"name": id, "type": "socks5", "server": host, "port": port, "username": "fixture", "password": "fixture-secret-0123456789abcdef0123456789abcdef", "udp": true})
		}
		content, _ := yaml.Marshal(map[string]any{"proxies": nodes})
		config.DirectProjection = &api.NetworkProxyDirectProjection{SchemaVersion: "proxy-direct/v1", RuntimeID: p.RuntimeID, ProfileID: p.ProfileID, BundleID: p.BundleID, Revision: p.Revision, ActiveRevision: p.ActiveRevision, SourceRevision: p.SourceRevision, OrgRevision: p.OrgRevision, ProjectionHash: p.ProjectionHash, ProcessEpoch: p.ProcessEpoch, ExpiresAt: p.ExpiresAt, DeliveryMode: api.NetworkProxyDirectProjectionDeliveryMode(mode), UpstreamDisclosure: "upstream_parameters", Format: "mihomo_yaml", Groups: p.Groups, Rules: p.Rules, Content: string(content)}
		config.Projection = nil
		config.DeliveryMode = mode
	}
	controller, err := NewConfiguredMihomoController(Config{MihomoControllerURL: fmt.Sprintf("http://127.0.0.1:%d", config.ControllerPort), StateDirectory: t.TempDir(), MihomoControllerSecretFile: "operator-owned-fixture-secret-0123456789abcdef0123456789abcdef", MihomoProcess: MihomoProcessConfig{Ownership: "soha_owned", Binary: binary, SHA256: digest, Version: version}}, strings.Repeat("s", 32))
	if err != nil {
		t.Fatal(err)
	}
	controller.transportTLS = relay.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	transport := &realAppCountTransport{base: http.DefaultTransport, controller: controller}
	controller.http.Transport = transport
	e, err := NewCoordinatedExecutor(&stoppedWireGuardFixture{fakeConfigurationExecutor: fakeConfigurationExecutor{outcome: ApplyOutcome{Status: "applied"}}}, controller, filepath.Join(t.TempDir(), "app.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Disable(context.Background())
	defer func() {
		if t.Failed() {
			if controller.egress != nil {
				t.Logf("UDP failure gateActive=%d mappedHandlerActive=%d sourceAassociations=%d sourceBassoc=%d sourceApackets=%d sourceBpackets=%d", controller.egress.socks.ActiveCount(), packetHandler.ActiveCount(), aSource.associations.Load(), bSource.associations.Load(), aSource.packets.Load(), bSource.packets.Load())
				realAppR06(t, controller, "failure-before-cleanup")
			}
		}
	}()
	desired := ConfigurationDesired{Mihomo: &config, PolicyVersion: config.Protection.PolicyVersion, ValidUntil: config.EnforcementUntil}
	if outcome := e.Apply(context.Background(), desired, now); outcome.Status != "applied" {

		t.Fatalf("real apply: %#v HTTP=%v process=%+v delayReasons=%v", outcome, transport.trace, controller.ProcessStatus(), transport.delayReasons)
	}
	gate := controller.egress
	before := controller.ProcessStatus()
	puts := transport.puts.Load()
	if before.PID == 0 || before.State != "running" || before.Ownership != "soha_owned" {
		t.Fatal("no owned real process")
	}
	native := fmt.Sprintf("127.0.0.1:%d", config.MixedPort)
	if badRelay {
		denied := realAppNativeUDP(t, native)
		realAppDenied(t, denied)
		time.Sleep(100 * time.Millisecond)
		if aSource.associations.Load() == 0 {
			t.Fatal("malicious relay case never reached upstream UDP ASSOCIATE")
		}
		if witnessPackets.Load() != 0 || aSource.packets.Load() != 0 {
			t.Fatal("unapproved protected relay received UDP packet")
		}
		if _, err := e.Proxy(context.Background(), &ProxyAction{Kind: "stop"}, nil); err != nil {
			t.Fatal(err)
		}
		t.Log("PASS malicious SOCKS UDP relay returned protected loopback witness; zero witness/backend datagrams")
		return
	}
	selectNode := func(id string) {
		t.Helper()
		raw, _ := json.Marshal(map[string]string{"name": id})
		if err := controller.request(context.Background(), http.MethodPut, "/proxies/Soha", raw, http.StatusNoContent, nil); err != nil {
			t.Fatal(err)
		}
	}
	selectNode("node-a")
	aTCP := realAppTCP(t, native, "", "")
	realAppBusiness(t, controller, "tcp-baseline", 0, 0, 0)
	realAppR06(t, controller, "tcp-before-16x5byte")
	for i := 0; i < 16; i++ {
		realAppEcho(t, aTCP, "A", false)
	}
	realAppBusiness(t, controller, "tcp-known-payload", 80, 112, 1)
	multiplier := int64(1)
	if mode == "direct_subscription" {
		multiplier = 2
	}
	realAppRawTotals(t, controller, "tcp", 80*multiplier, 112*multiplier, int(multiplier))
	realAppR06(t, controller, "tcp-after-16x5byte-up80-down112")
	realAppEcho(t, aTCP, "A", false)
	aNativeUDP := realAppNativeUDP(t, native)
	if os.Getenv("SOHA_REAL_UDP_DIAG") == "1" {
		probe := func(c net.Conn, payload, expected []byte, label string) {
			c.SetDeadline(time.Now().Add(500 * time.Millisecond))
			_, writeErr := c.Write(payload)
			b := make([]byte, 4096)
			n, readErr := c.Read(b)
			t.Logf("UDP DIAG %s match=%v n=%d writeErr=%v readErr=%v gate=%d tlsRequests=%d packetDials=%d packetHandler=%d sourceASSOC=%d sourcePackets=%d", label, bytes.Equal(b[:n], expected), n, writeErr, readErr, gate.socks.ActiveCount(), packetRequests.Load(), packetDials.Load(), packetHandler.ActiveCount(), aSource.associations.Load(), aSource.packets.Load())
			realAppR06(t, controller, "udp-diag-"+label)
		}
		var node struct {
			UDP  bool   `json:"udp"`
			Type string `json:"type"`
		}
		if err := controller.request(context.Background(), http.MethodGet, "/proxies/node-a", nil, http.StatusOK, &node); err != nil {
			t.Fatal(err)
		}
		t.Logf("UDP DIAG native nodeA udp=%v type=%s", node.UDP, node.Type)
		probe(aNativeUDP, []byte("proof"), []byte("A:proof"), "port53-nonDNS")
		alt := realAppNativeUDP(t, native, 443)
		probe(alt, []byte("proof"), []byte("A:proof"), "port443")
		dns := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 't', 'e', 's', 't', 7, 'i', 'n', 'v', 'a', 'l', 'i', 'd', 0, 0, 1, 0, 1}
		dnsConn := realAppNativeUDP(t, native, 53)
		probe(dnsConn, dns, append([]byte("A:"), dns...), "port53-validDNS")
		return
	}

	realAppBusiness(t, controller, "udp-baseline", 85, 119, 1)
	realAppR06(t, controller, "udp-before-16x5byte")
	for i := 0; i < 16; i++ {
		realAppEcho(t, aNativeUDP, "A", true)
	}
	realAppBusiness(t, controller, "udp-known-payload", 165, 231, 2)
	realAppRawTotals(t, controller, "udp", 165*multiplier, 231*multiplier, 2*int(multiplier))
	realAppR06(t, controller, "udp-after-16x5byte-up80-down112")
	realAppEcho(t, aNativeUDP, "A", true)
	selectNode("node-b")
	bTCP := realAppTCP(t, native, "", "")
	realAppEcho(t, bTCP, "B", false)
	bNativeUDP := realAppNativeUDP(t, native)
	realAppEcho(t, bNativeUDP, "B", true)
	selectNode("node-a")
	front := fmt.Sprintf("127.0.0.1:%d", transport.frontPort)
	udp := func(node, target string) net.Conn {
		t.Helper()
		c, err := proxytransport.DialSOCKS5UDP(context.Background(), front, projectionNodeUser(node), gate.proxySecret, target, until)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	aUDP, bUDP := udp("node-a", "8.8.8.8:53"), udp("node-b", "8.8.8.8:53")
	realAppEcho(t, aUDP, "A", true)
	realAppEcho(t, bUDP, "B", true)
	count := aSource.packets.Load() + bSource.packets.Load()
	for _, target := range []string{"10.1.1.1:53", "9.9.9.9:53"} {
		denied := udp("node-b", target)
		realAppDenied(t, denied)
		denied.Close()
	}
	if aSource.packets.Load()+bSource.packets.Load() != count {
		t.Fatal("denied packet reached upstream")
	}
	next := narrowedBundle(t, config)
	if ok, err := e.RenewProjection(context.Background(), ConfigurationDesired{Mihomo: &next, ValidUntil: config.EnforcementUntil}, time.Now()); err != nil || !ok {
		t.Fatalf("real narrow %v %v", ok, err)
	}
	after := controller.ProcessStatus()
	if after.PID != before.PID || after.ProcessEpoch != before.ProcessEpoch || transport.puts.Load() != puts || controller.egress != gate {
		t.Fatal("narrow restarted/reloaded engine or gate")
	}
	aTCP.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := aTCP.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatal("revoked TCP A not closed")
	}
	aPackets := aSource.packets.Load()
	realAppDenied(t, aUDP)
	realAppDenied(t, aNativeUDP)
	if aSource.packets.Load() != aPackets {
		t.Fatal("revoked A packet reached upstream")
	}
	realAppEcho(t, bNativeUDP, "B", true)
	realAppEcho(t, bTCP, "B", false)
	realAppEcho(t, bUDP, "B", true)
	if ok, err := e.RenewProjection(context.Background(), desired, time.Now()); err == nil || ok {
		t.Fatal("AB replay widened ceiling")
	}
	realAppEcho(t, bTCP, "B", false)
	realAppEcho(t, bUDP, "B", true)
	if _, err := e.Proxy(context.Background(), &ProxyAction{Kind: "select", GroupID: "Soha", NodeID: "node-b"}, nil); err != nil {
		t.Fatalf("explicit B selection after narrow: %v", err)
	}
	realAppEcho(t, bTCP, "B", false)
	realAppEcho(t, bUDP, "B", true)
	realAppVisibleClose(t, e, controller, transport, native, mode, bTCP, bUDP, bNativeUDP)
	if mode == "mapped_nodes" {
		// Same-credential renewal must keep its existing authorized stream; then a
		// short current lease expires without a late refresh resurrecting it.
		renewed := cloneMihomoConfiguration(next)
		renewed.Projection.Credential.ExpiresAt = time.Now().Add(1500 * time.Millisecond)
		if ok, err := e.RenewProjection(context.Background(), ConfigurationDesired{Mihomo: &renewed, ValidUntil: config.EnforcementUntil}, time.Now()); err != nil || !ok {
			t.Fatalf("short renewal %v %v", ok, err)
		}
		realAppEcho(t, bUDP, "B", true)
		timer := time.NewTimer(time.Until(renewed.Projection.Credential.ExpiresAt) + 60*time.Millisecond)
		<-timer.C
		realAppDenied(t, bUDP)
		if refresh, ok := bUDP.(interface{ Refresh(time.Time) error }); !ok || refresh.Refresh(time.Now().Add(time.Second)) == nil {
			t.Fatal("expired local association revived")
		}
		late := cloneMihomoConfiguration(renewed)
		late.Projection.Credential.ExpiresAt = time.Now().Add(30 * time.Second)
		if ok, err := e.RenewProjection(context.Background(), ConfigurationDesired{Mihomo: &late, ValidUntil: config.EnforcementUntil}, time.Now()); err == nil && ok {
			t.Fatal("late projection revived expired grant")
		}
	}
	if _, err := e.Proxy(context.Background(), &ProxyAction{Kind: "stop"}, nil); err != nil {
		t.Fatal(err)
	}
	if controller.ProcessStatus().PID != 0 || gate.socksReady.Load() || gate.socks.ActiveCount() != 0 {
		t.Fatal("stop retained owned process/UDP associations")
	}
	for _, address := range []string{native, front, fmt.Sprintf("127.0.0.1:%d", config.ControllerPort)} {
		c, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			c.Close()
			t.Fatalf("stop left listener %s", address)
		}
	}
	t.Logf("PASS real %s TCP/UDP A/B; protected/mandatory no packet; narrow same pid=%d epoch=%s configPUT=%d; replay denied; owned stop", mode, before.PID, before.ProcessEpoch, puts)
}
