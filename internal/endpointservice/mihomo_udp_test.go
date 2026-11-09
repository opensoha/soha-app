//go:build !windows

package endpointservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	api "github.com/opensoha/soha-contracts/gen/go/sohaapi"
	"github.com/opensoha/soha-contracts/proxytransport"
	"go.yaml.in/yaml/v3"
)

func udpEchoConnection(t *testing.T) net.Conn {
	t.Helper()
	a, b := net.Pipe()
	front, err := proxytransport.NewPacketConn(a, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	back, err := proxytransport.NewPacketConn(b, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = front.Close(); _ = back.Close() })
	go func() {
		defer back.Close()
		buffer := make([]byte, proxytransport.MaxDatagramBytes)
		for {
			n, err := back.Read(buffer)
			if err != nil {
				return
			}
			if _, err = back.Write(buffer[:n]); err != nil {
				return
			}
		}
	}()
	return front
}
func udpRoundTrip(t *testing.T, c net.Conn, payload []byte) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, proxytransport.MaxDatagramBytes)
	n, err := c.Read(buffer)
	if err != nil || !bytes.Equal(buffer[:n], payload) {
		t.Fatalf("datagram echo n=%d err=%v", n, err)
	}
	_ = c.SetDeadline(time.Time{})
}
func waitUDPCount(t *testing.T, gate *proxytransport.SOCKS5Gate, count int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if gate.ActiveCount() == count {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("UDP active=%d want=%d", gate.ActiveCount(), count)
}

func checkUDPFragment(t *testing.T, port int, secret string) {
	t.Helper()
	control, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(time.Second))
	_, _ = control.Write([]byte{5, 1, 2})
	reply := make([]byte, 2)
	if _, err = io.ReadFull(control, reply); err != nil || !bytes.Equal(reply, []byte{5, 2}) {
		t.Fatal("SOCKS methods", err)
	}
	user := projectionNodeUser("node-b")
	auth := append([]byte{1, byte(len(user))}, []byte(user)...)
	auth = append(auth, byte(len(secret)))
	auth = append(auth, []byte(secret)...)
	_, _ = control.Write(auth)
	if _, err = io.ReadFull(control, reply); err != nil || !bytes.Equal(reply, []byte{1, 0}) {
		t.Fatal("SOCKS auth", err)
	}
	_, _ = control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	relay := make([]byte, 10)
	if _, err = io.ReadFull(control, relay); err != nil || !bytes.Equal(relay[:4], []byte{5, 0, 0, 1}) {
		t.Fatal("SOCKS UDP", err)
	}
	udp, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IP(relay[4:8]), Port: int(relay[8])<<8 | int(relay[9])})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	packet := []byte{0, 0, 1, 1, 8, 8, 8, 8, 0, 53, 'x'}
	_ = udp.SetDeadline(time.Now().Add(30 * time.Millisecond))
	_, _ = udp.Write(packet)
	if _, err = udp.Read(make([]byte, 32)); err == nil {
		t.Fatal("fragmented UDP forwarded")
	}
	packet[2] = 0
	_ = udp.SetDeadline(time.Now().Add(time.Second))
	_, _ = udp.Write(packet)
	buffer := make([]byte, 32)
	n, err := udp.Read(buffer)
	if err != nil || !bytes.Equal(buffer[:n], packet) {
		t.Fatal("valid packet after fragment drop", err)
	}
}

func TestMihomoGuardedUDPNodeNarrowAndStop(t *testing.T) {
	for _, mode := range []string{"mapped_nodes", "direct_subscription"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC()
			config := twoNodeBundle(now)
			config.Protection.CIDRs = []string{"10.0.0.0/8"}
			oldPacketUntil := now.Add(time.Second)
			config.Projection.Credential.ExpiresAt = oldPacketUntil
			credentials := map[string]string{}
			for _, n := range config.Projection.Nodes {
				user, _ := proxytransport.EncodeMappedUsername(config.Projection.Credential.CredentialID, n.NodeID)
				credentials[user] = config.Projection.Credential.Secret
			}
			packetHandler, err := proxytransport.NewPacketHandler(credentials, func(context.Context, string, string) (net.Conn, error) { return udpEchoConnection(t), nil }, func(context.Context, string, string) error { return nil }, now.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			defer packetHandler.Close()
			relay := httptest.NewTLSServer(packetHandler)
			defer relay.Close()
			config.Projection.Endpoints[0].URL = relay.URL
			if mode == "direct_subscription" {
				p := config.Projection
				config.DirectProjection = &api.NetworkProxyDirectProjection{SchemaVersion: "proxy-direct/v1", RuntimeID: p.RuntimeID, ProfileID: p.ProfileID, BundleID: p.BundleID, Revision: p.Revision, ActiveRevision: p.ActiveRevision, SourceRevision: p.SourceRevision, OrgRevision: p.OrgRevision, ProjectionHash: p.ProjectionHash, ProcessEpoch: p.ProcessEpoch, ExpiresAt: oldPacketUntil, DeliveryMode: "direct_subscription", UpstreamDisclosure: "upstream_parameters", Format: "mihomo_yaml", Groups: p.Groups, Rules: p.Rules, Content: "proxies:\n  - {name: node-a, type: socks5, server: 8.8.8.8, port: 1080, udp: true}\n  - {name: node-b, type: socks5, server: 8.8.4.4, port: 1080, udp: true}\n"}
				config.Projection = nil
				config.DeliveryMode = mode
			}
			server, fixture := newMihomoControllerFixture(t, strings.Repeat("s", 32))
			controller, _ := NewMihomoController(server.URL, strings.Repeat("s", 32))
			controller.transportTLS = relay.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			config.ControllerPort = controller.port
			e, _ := NewCoordinatedExecutor(&stoppedWireGuardFixture{fakeConfigurationExecutor: fakeConfigurationExecutor{outcome: ApplyOutcome{Status: "applied"}}}, controller, filepath.Join(t.TempDir(), "app.json"))
			defer e.Disable(context.Background())
			if result := e.Apply(context.Background(), ConfigurationDesired{Mihomo: &config, PolicyVersion: config.Protection.PolicyVersion, ValidUntil: config.EnforcementUntil}, now); result.Status != "applied" {
				t.Fatal(result)
			}
			processController, _ := processFixture(t)
			if err := processController.process.start(context.Background(), "", func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
			controller.process = processController.process
			before := controller.ProcessStatus()
			gate := controller.egress
			fixture.mu.Lock()
			payload := fixture.payload
			fixture.mu.Unlock()
			var rendered struct {
				Listeners []struct {
					Name string
					Port int
					UDP  bool
				}
				Proxies []struct {
					Name, Type string
					Port       int
					UDP        bool
				}
			}
			if yaml.Unmarshal([]byte(payload), &rendered) != nil {
				t.Fatal("rendered config invalid")
			}
			frontPort := 0
			for _, node := range rendered.Proxies {
				if node.Name == "node-b" {
					frontPort = node.Port
					if node.Type != "socks5" || !node.UDP {
						t.Fatal("native UDP adapter missing")
					}
				}
			}
			if mode == "direct_subscription" {
				for _, listener := range rendered.Listeners {
					if !strings.HasPrefix(listener.Name, "soha-owned-backend-") {
						continue
					}
					if !listener.UDP {
						t.Fatal("owned backend UDP disabled")
					}
					backend, err := proxytransport.NewSOCKS5Gate(map[string]string{"proxy": gate.proxySecret}, func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("UDP fixture only") }, func(context.Context, string, string) (net.Conn, error) { return udpEchoConnection(t), nil }, func(context.Context, string, string) error { return nil }, now.Add(time.Minute))
					if err != nil {
						t.Fatal(err)
					}
					l, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", listener.Port))
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = backend.Close(); _ = l.Close() })
					go func() { _ = backend.Serve(l) }()
				}
			}
			dial := func(node, target string) net.Conn {
				c, err := proxytransport.DialSOCKS5UDP(context.Background(), fmt.Sprintf("127.0.0.1:%d", frontPort), projectionNodeUser(node), gate.proxySecret, target, now.Add(time.Minute))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = c.Close() })
				return c
			}
			a, b := dial("node-a", "8.8.8.8:53"), dial("node-b", "8.8.8.8:53")
			udpRoundTrip(t, a, []byte("A"))
			udpRoundTrip(t, b, nil)
			udpRoundTrip(t, b, []byte("B"))
			waitUDPCount(t, gate.socks, 2)
			checkUDPFragment(t, frontPort, gate.proxySecret)
			waitUDPCount(t, gate.socks, 2)
			for _, target := range []string{"10.1.1.1:53", "9.9.9.9:53"} {
				denied := dial("node-b", target)
				_ = denied.SetDeadline(time.Now().Add(30 * time.Millisecond))
				_, _ = denied.Write([]byte("deny"))
				if _, err := denied.Read(make([]byte, 32)); err == nil {
					t.Fatalf("protected/mandatory destination admitted: %s", target)
				}
				_ = denied.Close()
			}
			next := narrowedBundle(t, config)
			if next.DirectProjection != nil {
				next.DirectProjection.ExpiresAt = oldPacketUntil.Add(10 * time.Second)
			}
			if ok, err := e.RenewProjection(context.Background(), ConfigurationDesired{Mihomo: &next, ValidUntil: config.EnforcementUntil}, now); err != nil || !ok {
				t.Fatalf("narrow %v %v", ok, err)
			}
			if controller.ProcessStatus().PID != before.PID || controller.ProcessStatus().ProcessEpoch != before.ProcessEpoch {
				t.Fatal("UDP narrow restarted engine")
			}
			_ = a.SetDeadline(time.Now().Add(30 * time.Millisecond))
			_, _ = a.Write([]byte("removed"))
			if _, err := a.Read(make([]byte, 32)); err == nil {
				t.Fatal("A survived revocation")
			}
			waitUDPCount(t, gate.socks, 1)
			udpRoundTrip(t, b, []byte("B continues"))
			time.Sleep(max(0, time.Until(oldPacketUntil)) + 10*time.Millisecond)
			udpRoundTrip(t, b, []byte("B past initial lease"))
			if result := e.Verify(context.Background(), ConfigurationDesired{Mihomo: &next, ValidUntil: config.EnforcementUntil}, time.Now()); result.Status != "applied" {
				t.Fatal("native snapshot drifted after UDP renewal", result)
			}
			view, err := e.Proxy(context.Background(), nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			udpAvailable := false
			for _, capability := range view.Capabilities {
				if capability.Name == "udp" && capability.State == "available" {
					udpAvailable = true
				}
			}
			if !udpAvailable {
				t.Fatal("installed healthy UDP capability missing")
			}
			if len(view.Nodes) != 1 || view.Nodes[0].NodeID != "node-b" || len(view.Groups) != 1 || view.Groups[0].SelectedNodeID != "" {
				t.Fatal("narrowed workbench retained A or auto-selected B")
			}
			selected, err := e.Proxy(context.Background(), &ProxyAction{Kind: "select", GroupID: config.SelectorGroup, NodeID: "node-b"}, nil)
			if err != nil || selected.Groups[0].SelectedNodeID != "node-b" {
				t.Fatal("explicit B selection blocked by native AB snapshot", err)
			}
			if result := e.Verify(context.Background(), ConfigurationDesired{Mihomo: &next, ValidUntil: config.EnforcementUntil}, time.Now()); result.Status != "applied" {
				t.Fatal("explicit B selection lost native snapshot", result)
			}
			udpRoundTrip(t, b, []byte("B after selection"))
			if ok, err := e.RenewProjection(context.Background(), ConfigurationDesired{Mihomo: &config, PolicyVersion: config.Protection.PolicyVersion, ValidUntil: config.EnforcementUntil}, now); err == nil || ok {
				t.Fatal("UDP scope replay widened")
			}
			udpRoundTrip(t, b, []byte("B after replay"))
			if _, err := e.Proxy(context.Background(), &ProxyAction{Kind: "stop"}, nil); err != nil {
				t.Fatal(err)
			}
			waitUDPCount(t, gate.socks, 0)
			if controller.ProcessStatus().PID != 0 || gate.socksReady.Load() {
				t.Fatal("owned stop left UDP gate/process")
			}
		})
	}
}

func TestMihomoUDPRenewalCapsAndCannotReviveExpired(t *testing.T) {
	now := time.Now()
	_, projection := bundleFixture(now)
	oldUntil := now.Add(200 * time.Millisecond)
	projection.Credential.ExpiresAt = oldUntil
	gate := &mihomoEgress{}
	gate.until.Store(oldUntil.UnixNano())
	gate.refreshProjection(&projection)
	a, b := net.Pipe()
	front, err := proxytransport.NewPacketConn(a, oldUntil)
	if err != nil {
		t.Fatal(err)
	}
	back, err := proxytransport.NewPacketConn(b, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer back.Close()
	go func() {
		buffer := make([]byte, 32)
		for {
			n, err := back.Read(buffer)
			if err != nil {
				return
			}
			if _, err = back.Write(buffer[:n]); err != nil {
				return
			}
		}
	}()
	guarded := &guardedPacketConnection{Conn: front, until: gate.packetUntil, check: func(context.Context) error { return nil }}
	tracked, err := gate.trackNode("node-a", guarded)
	if err != nil {
		t.Fatal(err)
	}
	defer tracked.Close()
	newUntil := now.Add(800 * time.Millisecond)
	projection.Credential.ExpiresAt = newUntil
	gate.refreshProjection(&projection)
	gate.until.Store(now.Add(time.Hour).UnixNano())
	if err = tracked.(*nodeConnection).Refresh(now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(max(0, time.Until(oldUntil)) + 10*time.Millisecond)
	udpRoundTrip(t, tracked, []byte("renewed"))
	time.Sleep(max(0, time.Until(newUntil)) + 10*time.Millisecond)
	if err = tracked.(*nodeConnection).Refresh(now.Add(time.Minute)); err == nil {
		t.Fatal("expired UDP revived")
	}
	if _, err = tracked.Write([]byte("expired")); err == nil {
		t.Fatal("UDP exceeded credential hard expiry")
	}
	if directNodeUDP(MihomoConfiguration{BootstrapNodes: []map[string]any{{"name": "http", "type": "http", "udp": true}}}, "http") {
		t.Fatal("HTTP upstream advertised UDP")
	}
}

func TestMihomoUDPTrustedDefaultsAndCanonicalNarrowing(t *testing.T) {
	for _, kind := range []string{"socks5", "ss", "trojan", "vmess", "vless", "http", "ssr", "snell", "unknown"} {
		node := map[string]any{"type": kind}
		if err := normalizeDirectUDP(node); err != nil {
			t.Fatal(err)
		}
		want := kind == "socks5" || kind == "ss" || kind == "trojan" || kind == "vmess" || kind == "vless"
		if node["udp"] != want {
			t.Fatalf("wrong protocol default %s", kind)
		}
		node["udp"] = false
		if err := normalizeDirectUDP(node); err != nil || node["udp"] != false {
			t.Fatal("explicit false overridden")
		}
	}
	if normalizeDirectUDP(map[string]any{"type": "socks5", "udp": "false"}) == nil {
		t.Fatal("malformed UDP flag accepted")
	}
	base := api.NetworkProxyDirectProjection{Content: "proxies:\n - {name: node-b, type: socks5, server: 8.8.8.8, port: 1080}\n"}
	explicit := base
	explicit.Content = strings.Replace(base.Content, "port: 1080}", "port: 1080, udp: true}", 1)
	a, err := directCanonical(&base)
	if err != nil {
		t.Fatal(err)
	}
	b, err := directCanonical(&explicit)
	if err != nil || !sameJSON(a, b) {
		t.Fatal("equivalent typed UDP defaults differ")
	}
	explicit.Content = strings.Replace(explicit.Content, "udp: true", "udp: false", 1)
	b, err = directCanonical(&explicit)
	if err != nil || sameJSON(a, b) {
		t.Fatal("explicit UDP disable swallowed by normalization")
	}
	explicit = base
	explicit.Content = strings.Replace(base.Content, "8.8.8.8", "8.8.4.4", 1)
	b, err = directCanonical(&explicit)
	if err != nil || sameJSON(a, b) {
		t.Fatal("backend mutation swallowed by normalization")
	}
}
