//go:build !windows

package endpointservice

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	api "github.com/opensoha/soha-contracts/gen/go/sohaapi"
	"github.com/opensoha/soha-contracts/proxypolicy"
	"go.yaml.in/yaml/v3"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func twoNodeBundle(now time.Time) MihomoConfiguration {
	c, p := bundleFixture(now)
	p.Nodes = append(p.Nodes, api.NetworkProxyEmployeeNode{NodeID: "node-b", Label: "B", EndpointID: "internal-1"})
	p.Credential.NodeIDs = append(p.Credential.NodeIDs, "node-b")
	p.Groups[0].NodeIDs = append(p.Groups[0].NodeIDs, "node-b")
	p.Rules = []api.NetworkProxyRule{{RuleID: "required-a", Source: "organization_required", Enabled: true, Matcher: api.NetworkProxyRuleMatcher{Type: "cidr", Value: "9.9.9.9/32"}, Action: api.NetworkProxyRuleAction{Type: "node", TargetID: "node-a"}}}
	c.Projection = &p
	return c
}
func narrowedBundle(t *testing.T, c MihomoConfiguration) MihomoConfiguration {
	t.Helper()
	next := cloneMihomoConfiguration(c)
	result, err := proxypolicy.NarrowTargets(configurationGroups(c), projectionRules(c), []string{"node-b"})
	if err != nil {
		t.Fatal(err)
	}
	if next.Projection != nil {
		next.Projection.Nodes = next.Projection.Nodes[1:]
		next.Projection.Credential.NodeIDs = []string{"node-b"}
		next.Projection.Groups = result.Groups
		next.Projection.Rules = result.Rules
		next.Projection.Credential.ExpiresAt = next.Projection.Credential.ExpiresAt.Add(10 * time.Second)
	} else {
		nodes, err := directCanonical(next.DirectProjection)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := yaml.Marshal(map[string]any{"proxies": []map[string]any{nodes["node-b"]}})
		next.DirectProjection.Content = string(raw)
		next.DirectProjection.Groups = result.Groups
		next.DirectProjection.Rules = result.Rules
	}
	return next
}
func fakeEchoSOCKS(t *testing.T, address string) {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				r := bufio.NewReader(conn)
				header := make([]byte, 2)
				if _, err = io.ReadFull(r, header); err != nil {
					return
				}
				methods := make([]byte, int(header[1]))
				if _, err = io.ReadFull(r, methods); err != nil {
					return
				}
				conn.Write([]byte{5, 2})
				if _, err = io.ReadFull(r, header); err != nil {
					return
				}
				io.CopyN(io.Discard, r, int64(header[1]))
				length, _ := r.ReadByte()
				io.CopyN(io.Discard, r, int64(length))
				conn.Write([]byte{1, 0})
				request := make([]byte, 4)
				if _, err = io.ReadFull(r, request); err != nil {
					return
				}
				count := 0
				switch request[3] {
				case 1:
					count = 4
				case 4:
					count = 16
				case 3:
					n, _ := r.ReadByte()
					count = int(n)
				default:
					return
				}
				if _, err = io.CopyN(io.Discard, r, int64(count+2)); err != nil {
					return
				}
				conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				io.Copy(conn, r)
			}()
		}
	}()
}
func gateStream(t *testing.T, port int, node, secret string) (net.Conn, int) {
	t.Helper()
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(conn, "CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\nProxy-Authorization: Basic %s\r\n\r\n", base64.StdEncoding.EncodeToString([]byte(projectionNodeUser(node)+":"+secret)))
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	return conn, response.StatusCode
}
func echoStream(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 4)
	if _, err := io.ReadFull(c, body); err != nil || string(body) != "ping" {
		t.Fatalf("unaffected stream failed: %v", err)
	}
}
func TestMihomoNarrowKeepsOwnedProcessAndUnaffectedStreams(t *testing.T) {
	for _, mode := range []string{"mapped_nodes", "direct_subscription"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC()
			config := twoNodeBundle(now)
			relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, buffer, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
				buffer.Flush()
				io.Copy(conn, buffer)
			}))
			defer relay.Close()
			config.Projection.Endpoints[0].URL = relay.URL
			if mode == "direct_subscription" {
				p := config.Projection
				config.DirectProjection = &api.NetworkProxyDirectProjection{SchemaVersion: "proxy-direct/v1", RuntimeID: p.RuntimeID, ProfileID: p.ProfileID, BundleID: p.BundleID, Revision: p.Revision, ActiveRevision: p.ActiveRevision, SourceRevision: p.SourceRevision, OrgRevision: p.OrgRevision, ProjectionHash: p.ProjectionHash, ProcessEpoch: p.ProcessEpoch, ExpiresAt: p.ExpiresAt, DeliveryMode: "direct_subscription", UpstreamDisclosure: "upstream_parameters", Format: "mihomo_yaml", Groups: p.Groups, Rules: p.Rules, Content: "proxies:\n  - {name: node-a, type: http, server: 8.8.8.8, port: 443, password: fake-a}\n  - {name: node-b, type: http, server: 8.8.4.4, port: 443, password: fake-b}\n"}
				config.Projection = nil
				config.DeliveryMode = mode
			}
			controllerServer, fixture := newMihomoControllerFixture(t, strings.Repeat("s", 32))
			controller, _ := NewMihomoController(controllerServer.URL, strings.Repeat("s", 32))
			controller.transportTLS = relay.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			config.ControllerPort = controller.port
			e, _ := NewCoordinatedExecutor(&stoppedWireGuardFixture{fakeConfigurationExecutor: fakeConfigurationExecutor{outcome: ApplyOutcome{Status: "applied"}}}, controller, filepath.Join(t.TempDir(), "app.json"))
			defer e.Disable(context.Background())
			e.personalLoaded = true
			e.personalRules = personalRuleState{Version: 1, Rules: []api.NetworkProxyRule{{RuleID: "personal-a", Source: "personal", Enabled: true, Matcher: api.NetworkProxyRuleMatcher{Type: "domain", Value: "a.example"}, Action: api.NetworkProxyRuleAction{Type: "node", TargetID: "node-a"}}}}
			desired := ConfigurationDesired{Mihomo: &config, PolicyVersion: config.Protection.PolicyVersion, ValidUntil: config.EnforcementUntil}
			if outcome := e.Apply(context.Background(), desired, now); outcome.Status != "applied" {
				t.Fatalf("initial apply: %#v", outcome)
			}
			processController, _ := processFixture(t)
			if err := processController.process.start(context.Background(), "", func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
			controller.process = processController.process
			fixture.mu.Lock()
			payload := fixture.payload
			frontPort := 0
			for _, p := range fixture.document.Proxies {
				if p.Name == mihomoGuardProxyName {
					frontPort = p.Port
				}
			}
			fixture.mu.Unlock()
			if mode == "direct_subscription" {
				var rendered struct {
					Listeners []struct {
						Name string
						Port int
					}
				}
				if yaml.Unmarshal([]byte(payload), &rendered) != nil {
					t.Fatal("bad fixture config")
				}
				for _, l := range rendered.Listeners {
					if strings.HasPrefix(l.Name, "soha-owned-backend-") {
						fakeEchoSOCKS(t, fmt.Sprintf("127.0.0.1:%d", l.Port))
					}
				}
			}
			a, status := gateStream(t, frontPort, "node-a", controller.egress.proxySecret)
			if status != 200 {
				t.Fatalf("A status %d", status)
			}
			defer a.Close()
			b, status := gateStream(t, frontPort, "node-b", controller.egress.proxySecret)
			if status != 200 {
				t.Fatalf("B status %d", status)
			}
			defer b.Close()
			echoStream(t, a)
			echoStream(t, b)
			pid := controller.ProcessStatus()
			gate := controller.egress
			next := narrowedBundle(t, config)
			renewed, err := e.RenewProjection(context.Background(), ConfigurationDesired{Mihomo: &next, ValidUntil: config.EnforcementUntil}, now)
			if err != nil || !renewed {
				t.Fatalf("narrow %v %v", renewed, err)
			}
			if controller.ProcessStatus().PID != pid.PID || controller.ProcessStatus().ProcessEpoch != pid.ProcessEpoch || controller.egress != gate {
				t.Fatal("narrow restarted or replaced owned process/gate")
			}
			a.SetReadDeadline(time.Now().Add(time.Second))
			if _, err = a.Read(make([]byte, 1)); err == nil || isTimeout(err) {
				t.Fatal("revoked A stream survived")
			}
			echoStream(t, b)
			rejected, code := gateStream(t, frontPort, "node-a", gate.proxySecret)
			rejected.Close()
			if code == 200 {
				t.Fatal("revoked A admitted")
			}
			if outcome := e.Verify(context.Background(), desired, now); outcome.Status != "applied" {
				t.Fatalf("native snapshot no longer verifies: %#v", outcome)
			}
			fixture.mu.Lock()
			unchanged := fixture.payload == payload
			fixture.mu.Unlock()
			if !unchanged {
				t.Fatal("narrow used controller reload")
			}
			rules, err := e.composeRules(*e.proxyDesired)
			if err != nil || len(rules.Rules) != 1 || len(rules.Conflicts) == 0 {
				t.Fatal("personal A draft/conflict lost")
			}
			if _, err = e.RenewProjection(context.Background(), desired, now); err == nil {
				t.Fatal("old AB projection widened current ceiling")
			}
			echoStream(t, b)
			if next.Projection != nil {
				changedEpoch := cloneMihomoConfiguration(next)
				changedEpoch.Projection.CredentialEpoch++
				changedEpoch.Projection.Credential.CredentialEpoch++
				renewed, err := e.RenewProjection(context.Background(), ConfigurationDesired{Mihomo: &changedEpoch, ValidUntil: config.EnforcementUntil}, now)
				if err != nil || renewed {
					t.Fatal("new credential epoch transparently renewed old streams")
				}
				echoStream(t, b)
			}
			invalid := cloneMihomoConfiguration(next)
			if invalid.Projection != nil {
				invalid.Projection.Credential.Secret += "mutated"
			} else {
				invalid.DirectProjection.Content = strings.ReplaceAll(invalid.DirectProjection.Content, "fake-b", "mutated-b")
			}
			if _, err = e.RenewProjection(context.Background(), ConfigurationDesired{Mihomo: &invalid, ValidUntil: config.EnforcementUntil}, now); err == nil {
				t.Fatal("backend/auth mutation accepted")
			}
			for _, kind := range []string{"expired", "other_boot"} {
				bad := cloneMihomoConfiguration(next)
				if bad.Projection != nil {
					if kind == "expired" {
						bad.Projection.ExpiresAt = now.Add(-time.Second)
					} else {
						bad.Projection.ProcessEpoch = "other-boot"
					}
				} else {
					if kind == "expired" {
						bad.DirectProjection.ExpiresAt = now.Add(-time.Second)
					} else {
						bad.DirectProjection.ProcessEpoch = "other-boot"
					}
				}
				if _, err = e.RenewProjection(context.Background(), ConfigurationDesired{Mihomo: &bad, ValidUntil: config.EnforcementUntil}, now); err == nil {
					t.Fatalf("%s projection revived", kind)
				}
			}
			if next.DirectProjection != nil {
				for _, key := range []string{"server", "tls", "username"} {
					bad := cloneMihomoConfiguration(next)
					nodes, _ := directCanonical(bad.DirectProjection)
					if key == "tls" {
						nodes["node-b"][key] = true
					} else {
						nodes["node-b"][key] = "changed"
					}
					raw, _ := yaml.Marshal(map[string]any{"proxies": []map[string]any{nodes["node-b"]}})
					bad.DirectProjection.Content = string(raw)
					if _, err = e.RenewProjection(context.Background(), ConfigurationDesired{Mihomo: &bad, ValidUntil: config.EnforcementUntil}, now); err == nil {
						t.Fatalf("direct %s mutation accepted", key)
					}
				}
			}
			gate.connectionsMu.Lock()
			aCount, bCount := 0, 0
			for conn := range gate.nodeConnections {
				if conn.nodeID == "node-a" {
					aCount++
				}
				if conn.nodeID == "node-b" {
					bCount++
				}
			}
			gate.connectionsMu.Unlock()
			if aCount != 0 || bCount != 1 {
				t.Fatalf("node tracking A=%d B=%d", aCount, bCount)
			}
			echoStream(t, b)

		})
	}
}
func TestMihomoNarrowCeilingPersists(t *testing.T) {
	c := twoNodeBundle(time.Now())
	next := narrowedBundle(t, c)
	path := filepath.Join(t.TempDir(), "floor.json")
	if err := rememberEmployeeProjection(path, *c.Projection); err != nil {
		t.Fatal(err)
	}
	if err := rememberEmployeeProjection(path, *next.Projection); err != nil {
		t.Fatal(err)
	}
	if err := rememberEmployeeProjection(path, *c.Projection); err == nil {
		t.Fatal("persisted ceiling allowed AB replay")
	}
}

func isTimeout(err error) bool { value, ok := err.(net.Error); return ok && value.Timeout() }

func TestMihomoNarrowManagerSelectsRenewalWithoutApply(t *testing.T) {
	now := time.Now().UTC()
	configuration := twoNodeBundle(now)
	configuration.Protection.PolicyVersion = 3
	server, _ := newMihomoControllerFixture(t, strings.Repeat("s", 32))
	controller, _ := NewMihomoController(server.URL, strings.Repeat("s", 32))
	configuration.ControllerPort = controller.port
	wg := &stoppedWireGuardFixture{fakeConfigurationExecutor: fakeConfigurationExecutor{outcome: ApplyOutcome{Status: "applied", ReadbackHash: emptyReadbackHash()}}}
	e, _ := NewCoordinatedExecutor(wg, controller, filepath.Join(t.TempDir(), "app.json"))
	defer e.Disable(context.Background())
	desired := ConfigurationDesired{ConfigurationVersion: 5, PolicyVersion: 3, ValidUntil: now.Add(3 * time.Minute), AccessProfile: "full", ProtectedResourceIDs: []string{}, NetworkLeases: []NetworkLease{}, ResourceLeases: []ResourceLease{}, Mihomo: &configuration}
	raw, _ := json.Marshal(desired)
	control := &bundleControl{fakeControl: fakeControl{configuration: RuntimeMessage{SchemaVersion: RuntimeSchemaVersion, MessageID: "message-1", MessageType: MessageConfiguration, ProducerID: "network-control", RuntimeID: "endpoint-1", RuntimeKind: "endpoint", OccurredAt: now, ExpiresAt: desired.ValidUntil, Payload: raw}}, projection: *configuration.Projection}
	manager, err := NewManager(ManagerOptions{ControlURL: "https://control.example.test", ConfigurationStatePath: filepath.Join(t.TempDir(), "floor.json"), RuntimeID: "endpoint-1", DeviceID: "device-1", PollInterval: time.Second, HeartbeatInterval: time.Minute, RenewBefore: 30 * time.Second, MaxClockSkew: time.Minute}, control, e, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return now }
	if err = manager.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	processController, _ := processFixture(t)
	if err = processController.process.start(context.Background(), "", func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	controller.process = processController.process
	pid := controller.ProcessStatus().PID
	next := narrowedBundle(t, configuration)
	control.projection = *next.Projection
	if err = manager.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if wg.applyCalls != 1 || wg.disableCalls != 0 || controller.ProcessStatus().PID != pid || !e.proxyNarrowed {
		t.Fatal("manager reapplied instead of narrowing")
	}
	if err = manager.Cycle(context.Background()); err != nil || controller.ProcessStatus().PID != pid {
		t.Fatalf("stable narrowed native snapshot: %v", err)
	}
}
