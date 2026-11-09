//go:build !windows

package endpointservice

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/opensoha/soha-contracts/gen/go/sohaapi"
	"github.com/opensoha/soha-contracts/proxytransport"
	socksproxy "golang.org/x/net/proxy"
)

func fakeSourceSOCKS(t *testing.T, malicious bool) (mihomoSOCKSUpstream, *atomic.Int64) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	hidden, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	count := &atomic.Int64{}
	t.Cleanup(func() { _ = listener.Close(); _ = relay.Close(); _ = hidden.Close() })
	go func() {
		buffer := make([]byte, 65536)
		for {
			_, _, err := hidden.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			count.Add(1)
		}
	}()
	go func() {
		buffer := make([]byte, 65536)
		for {
			n, from, err := relay.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			_, _ = relay.WriteToUDP(buffer[:n], from)
		}
	}()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(time.Minute))
				r := bufio.NewReader(conn)
				header := make([]byte, 2)
				if _, err := io.ReadFull(r, header); err != nil {
					return
				}
				methods := make([]byte, int(header[1]))
				if _, err = io.ReadFull(r, methods); err != nil {
					return
				}
				_, _ = conn.Write([]byte{5, 2})
				if _, err = io.ReadFull(r, header); err != nil {
					return
				}
				user := make([]byte, int(header[1]))
				if _, err = io.ReadFull(r, user); err != nil {
					return
				}
				n, err := r.ReadByte()
				if err != nil {
					return
				}
				secret := make([]byte, int(n))
				if _, err = io.ReadFull(r, secret); err != nil {
					return
				}
				if string(user) != "source-user" || string(secret) != "short" {
					_, _ = conn.Write([]byte{1, 1})
					return
				}
				_, _ = conn.Write([]byte{1, 0})
				request := make([]byte, 4)
				if _, err = io.ReadFull(r, request); err != nil || request[3] != 1 {
					return
				}
				destination := make([]byte, 6)
				if _, err = io.ReadFull(r, destination); err != nil {
					return
				}
				if request[1] == 1 {
					_, _ = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
					_, _ = io.Copy(conn, r)
					return
				}
				if request[1] != 3 {
					return
				}
				bound := relay.LocalAddr().(*net.UDPAddr)
				if malicious {
					bound = hidden.LocalAddr().(*net.UDPAddr)
				}
				reply := append([]byte{5, 0, 0, 1}, bound.IP.To4()...)
				if bound.IP.To4() == nil {
					reply = append([]byte{5, 0, 0, 4}, bound.IP.To16()...)
				}
				reply = append(reply, byte(bound.Port>>8), byte(bound.Port))
				_, _ = conn.Write(reply)
				_, _ = io.Copy(io.Discard, r)
			}()
		}
	}()
	return mihomoSOCKSUpstream{ip: netip.MustParseAddr("127.0.0.1"), user: "source-user", secret: "short", connect: func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	}}, count
}

func mockNativeBridgeBackend(t *testing.T, bridge *mihomoSOCKSBridge) string {
	t.Helper()
	address := fmt.Sprintf("127.0.0.1:%v", bridge.node["port"])
	user, secret := bridge.node["username"].(string), bridge.node["password"].(string)
	gate, err := proxytransport.NewSOCKS5Gate(map[string]string{"native": strings.Repeat("n", 32)}, func(ctx context.Context, _ string, target string) (net.Conn, error) {
		d, err := socksproxy.SOCKS5("tcp", address, &socksproxy.Auth{User: user, Password: secret}, &net.Dialer{})
		if err != nil {
			return nil, err
		}
		return d.(socksproxy.ContextDialer).DialContext(ctx, "tcp", target)
	}, func(ctx context.Context, _ string, target string) (net.Conn, error) {
		return proxytransport.DialSOCKS5UDP(ctx, address, user, secret, target, time.Now().Add(time.Minute))
	}, func(context.Context, string, string) error { return nil }, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gate.Close(); _ = l.Close() })
	go func() { _ = gate.Serve(l) }()
	return l.Addr().String()
}

func TestMihomoSOCKSBridgeOwnedNativeRelayAndNarrow(t *testing.T) {
	for _, malicious := range []bool{false, true} {
		t.Run(fmt.Sprint(malicious), func(t *testing.T) {
			c, _ := processFixture(t)
			if err := c.process.start(context.Background(), "", func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
			defer c.process.stop(context.Background())
			config := twoNodeBundle(time.Now())
			config.Projection = nil
			config.DirectProjection = &api.NetworkProxyDirectProjection{Content: "proxies:\n - {name: node-a}\n - {name: node-b}\n"}
			config.EffectiveRules = nil
			g := &mihomoEgress{probeHost: "soha-egress-source.invalid", bridges: map[string]*mihomoSOCKSBridge{}}
			g.until.Store(time.Now().Add(time.Minute).UnixNano())
			g.updatePolicy(config)
			defer g.closeBridges()
			var hidden *atomic.Int64
			for _, id := range []string{"node-a", "node-b"} {
				source, count := fakeSourceSOCKS(t, malicious)
				hidden = count
				bridge, err := c.installSOCKSBridge(g, &config, id, source)
				if err != nil {
					t.Fatal(err)
				}
				g.bridges[id] = bridge
			}
			aNative, bNative := mockNativeBridgeBackend(t, g.bridges["node-a"]), mockNativeBridgeBackend(t, g.bridges["node-b"])
			dial := func(address string) net.Conn {
				conn, err := proxytransport.DialSOCKS5UDP(context.Background(), address, "native", strings.Repeat("n", 32), "8.8.8.8:53", time.Now().Add(time.Minute))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = conn.Close() })
				return conn
			}
			a, b := dial(aNative), dial(bNative)
			if malicious {
				_ = b.SetDeadline(time.Now().Add(50 * time.Millisecond))
				_, _ = b.Write([]byte("must not leave approved source"))
				if _, err := b.Read(make([]byte, 64)); err == nil {
					t.Fatal("hidden relay admitted")
				}
				if hidden.Load() != 0 {
					t.Fatal("outgoing UDP reached unapproved relay")
				}
				waitUDPCount(t, g.bridges["node-b"].gate, 0)
				return
			}
			udpRoundTrip(t, a, []byte("A"))
			udpRoundTrip(t, b, []byte("B"))
			d, err := socksproxy.SOCKS5("tcp", bNative, &socksproxy.Auth{User: "native", Password: strings.Repeat("n", 32)}, &net.Dialer{})
			if err != nil {
				t.Fatal(err)
			}
			stream, err := d.(socksproxy.ContextDialer).DialContext(context.Background(), "tcp", "8.8.8.8:443")
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			echoStream(t, stream)
			before := c.ProcessStatus()
			narrow := cloneMihomoConfiguration(config)
			narrow.DirectProjection.Content = "proxies:\n - {name: node-b}\n"
			narrow.DirectProjection.Groups = nil
			for _, conn := range g.publishPolicy(narrow) {
				_ = conn.Close()
			}
			_ = a.SetDeadline(time.Now().Add(30 * time.Millisecond))
			_, _ = a.Write([]byte("removed"))
			if _, err := a.Read(make([]byte, 32)); err == nil {
				t.Fatal("A UDP survived")
			}
			udpRoundTrip(t, b, []byte("B survives"))
			echoStream(t, stream)
			if c.ProcessStatus().PID != before.PID || c.ProcessStatus().ProcessEpoch != before.ProcessEpoch {
				t.Fatal("bridge narrow replaced owned process")
			}
			g.closeBridges()
			waitUDPCount(t, g.bridges["node-b"].gate, 0)
		})
	}
}

func TestMihomoSOCKSBridgePrivateRenderReadbackAndTLSChoice(t *testing.T) {
	for _, mode := range []string{"normal", "noauth", "explicit_false", "implicit_unknown_tls", "explicit_unknown_tls"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now()
			config, p := bundleFixture(now)
			content := "proxies:\n - {name: node-a, type: socks5, server: 8.8.8.8, port: 1080, username: private-source-user, password: private-source-secret"
			if mode == "noauth" {
				content = "proxies:\n - {name: node-a, type: socks5, server: 8.8.8.8, port: 1080"
			}
			if mode == "explicit_false" {
				content += ", udp: false, fingerprint: native-private-pin"
			}
			if strings.Contains(mode, "unknown_tls") {
				content += ", fingerprint: native-private-pin"
			}
			if mode == "explicit_unknown_tls" {
				content += ", udp: true"
			}
			content += "}\n"
			config.Projection = nil
			config.DeliveryMode = "direct_subscription"
			config.DirectProjection = &api.NetworkProxyDirectProjection{SchemaVersion: "proxy-direct/v1", RuntimeID: p.RuntimeID, ProfileID: p.ProfileID, BundleID: p.BundleID, Revision: p.Revision, ActiveRevision: p.ActiveRevision, SourceRevision: p.SourceRevision, OrgRevision: p.OrgRevision, ProjectionHash: p.ProjectionHash, ProcessEpoch: p.ProcessEpoch, ExpiresAt: p.ExpiresAt, DeliveryMode: "direct_subscription", UpstreamDisclosure: "upstream_parameters", Format: "mihomo_yaml", Content: content, Groups: p.Groups, Rules: p.Rules}
			server, fixture := newMihomoControllerFixture(t, strings.Repeat("s", 32))
			c, _ := NewMihomoController(server.URL, strings.Repeat("s", 32))
			config.ControllerPort = c.port
			e, _ := NewCoordinatedExecutor(&stoppedWireGuardFixture{fakeConfigurationExecutor: fakeConfigurationExecutor{outcome: ApplyOutcome{Status: "applied"}}}, c, filepath.Join(t.TempDir(), "app.json"))
			defer e.Disable(context.Background())
			desired := ConfigurationDesired{Mihomo: &config, PolicyVersion: config.Protection.PolicyVersion, ValidUntil: config.EnforcementUntil}
			outcome := e.Apply(context.Background(), desired, now)
			if mode == "explicit_unknown_tls" {
				if outcome.Status != "rejected" || outcome.ReasonCode != "mihomo_udp_source_unsupported" {
					t.Fatal("explicit unsupported source was silently accepted", outcome)
				}
				return
			}
			if outcome.Status != "applied" {
				t.Fatal(outcome)
			}
			if result := e.Verify(context.Background(), desired, now); result.Status != "applied" {
				t.Fatal("rewritten native snapshot did not verify", result)
			}
			if mode == "normal" || mode == "noauth" {
				fixture.mu.Lock()
				payload := fixture.payload
				fixture.mu.Unlock()
				if strings.Contains(payload, "private-source-secret") || strings.Contains(payload, "private-source-user") || strings.Contains(payload, "8.8.8.8") {
					t.Fatal("original SOCKS source escaped private Go material")
				}
				bridge := c.egress.bridges["node-a"]
				if bridge == nil || bridge.node["server"] != "127.0.0.1" || len(bridge.node["username"].(string)) > 255 || bridge.probes.Load() < 2 {
					t.Fatal("native private bridge readback missing")
				}
				if config.DirectProjection.Content != content {
					t.Fatal("original IR overwritten")
				}
				conn, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%v", bridge.node["port"]))
				if err != nil {
					t.Fatal(err)
				}
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				_, _ = conn.Write([]byte{5, 1, 0})
				reply := make([]byte, 2)
				if _, err = io.ReadFull(conn, reply); err != nil || reply[1] != 255 {
					t.Fatal("NoAuth bypassed private local bridge", err)
				}
				_ = conn.Close()
			} else if len(c.egress.bridges) != 0 {
				t.Fatal("TCP-only path unexpectedly rewritten")
			}
		})
	}
	scope, _ := proxytransport.NewScope([]string{"10.0.0.0/8"}, nil)
	for _, server := range []string{"127.0.0.1", "10.1.1.1", "not-pinned.example"} {
		if _, err := newMihomoSOCKSUpstream(map[string]any{"type": "socks5", "server": server, "port": 1080}, scope); err == nil {
			t.Fatal("unapproved source accepted")
		}
	}
	unknown := api.NetworkProxyDirectProjection{Content: "proxies:\n - {name: node-a, type: socks5, server: 8.8.8.8, port: 1080, fingerprint: native-pin}\n"}
	canonical, err := directCanonical(&unknown)
	if err != nil || canonical["node-a"]["udp"] != false {
		t.Fatal("implicit unsupported source did not canonicalize to TCP", err)
	}
	unknown.Content = strings.Replace(unknown.Content, "fingerprint:", "udp: true, fingerprint:", 1)
	if _, err = directCanonical(&unknown); err == nil {
		t.Fatal("narrowing swallowed explicit unsupported UDP request")
	}
	options, err := parseSOCKSBridgeOptions(map[string]any{"type": "socks5", "server": "8.8.8.8", "port": 1080, "tls": true, "servername": "source.example", "alpn": []any{"socks"}})
	if err != nil || options.tlsConfig.ServerName != "source.example" || options.tlsConfig.InsecureSkipVerify || options.tlsConfig.RootCAs != nil || len(options.tlsConfig.NextProtos) != 1 {
		t.Fatal("source TLS verification/SNI/ALPN changed", err)
	}
}
