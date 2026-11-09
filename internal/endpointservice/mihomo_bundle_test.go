package endpointservice

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	api "github.com/opensoha/soha-contracts/gen/go/sohaapi"
	"github.com/opensoha/soha-contracts/proxypolicy"
	"github.com/opensoha/soha-contracts/proxytransport"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func bundleFixture(now time.Time) (MihomoConfiguration, api.NetworkProxyEmployeeProjection) {
	c := managedMihomoConfiguration(9090)
	c.SubscriptionURL = ""
	c.SelectedProxy = ""
	c.DeliveryMode = "mapped_nodes"
	c.BundleID = "bundle-1"
	c.OrgRevision = 1
	c.SourceRevision = 1
	c.EnforcementUntil = now.Add(3 * time.Minute)
	p := api.NetworkProxyEmployeeProjection{SchemaVersion: "proxy-projection/v1", RuntimeID: "endpoint-1", ProfileID: c.ProfileID, BundleID: c.BundleID, Revision: 1, SourceRevision: 1, OrgRevision: 1, ActiveRevision: 1, ProjectionHash: "sha256:" + strings.Repeat("a", 64), DeliveryMode: "mapped_nodes", ProcessEpoch: "boot-1", CredentialEpoch: 1, ExpiresAt: now.Add(2 * time.Minute), Nodes: []api.NetworkProxyEmployeeNode{{NodeID: "node-a", Label: "Internal A", EndpointID: "internal-1"}}, Endpoints: []api.NetworkProxyEmployeeEndpoint{{EndpointID: "internal-1", URL: "https://127.0.0.1:9443"}}, Groups: []api.NetworkProxyGroup{{GroupID: "Soha", Label: "Soha", NodeIDs: []string{"node-a"}, SelectedNodeID: "node-a", Type: "select"}}, Rules: []api.NetworkProxyRule{}, Credential: api.NetworkProxyEmployeeCredential{CredentialID: "credential-1", CredentialEpoch: 1, UserID: "user-1", DeviceID: "device-1", NodeIDs: []string{"node-a"}, Secret: strings.Repeat("scoped-secret-", 4), ExpiresAt: now.Add(time.Minute)}}
	return c, p
}
func TestMihomoProjectionValidationAndFloor(t *testing.T) {
	now := time.Now().UTC()
	c, p := bundleFixture(now)
	if err := validateEmployeeProjection(p, c, "endpoint-1", "device-1", c.EnforcementUntil, now); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*api.NetworkProxyEmployeeProjection){func(p *api.NetworkProxyEmployeeProjection) { p.ProfileID = "other" }, func(p *api.NetworkProxyEmployeeProjection) { p.ActiveRevision = 0 }, func(p *api.NetworkProxyEmployeeProjection) { p.OrgRevision = 2 }, func(p *api.NetworkProxyEmployeeProjection) { p.Credential.DeviceID = "other" }, func(p *api.NetworkProxyEmployeeProjection) { p.ExpiresAt = now.Add(-time.Second) }, func(p *api.NetworkProxyEmployeeProjection) {
		p.Endpoints = []api.NetworkProxyEmployeeEndpoint{{EndpointID: "internal-1", URL: "http://127.0.0.1"}}
	}} {
		copy := p
		change(&copy)
		if validateEmployeeProjection(copy, c, "endpoint-1", "device-1", c.EnforcementUntil, now) == nil {
			t.Fatal("unsafe projection accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "configuration-floor.json")
	if err := rememberEmployeeProjection(path, p); err != nil {
		t.Fatal(err)
	}
	renewed := p
	renewed.ExpiresAt = now.Add(150 * time.Second)

	if err := rememberEmployeeProjection(path, renewed); err != nil {
		t.Fatalf("safe renewal rejected: %v", err)
	}
	changedAuth := p
	changedAuth.Credential.Secret += "changed"
	if rememberEmployeeProjection(path, changedAuth) == nil {
		t.Fatal("same identity changed credential accepted")
	}
	changed := p
	changed.ProjectionHash = "sha256:" + strings.Repeat("b", 64)
	if rememberEmployeeProjection(path, changed) == nil {
		t.Fatal("same revision changed hash accepted")
	}
	newer := p
	newer.Revision = 2
	if err := rememberEmployeeProjection(path, newer); err != nil {
		t.Fatal(err)
	}
	if rememberEmployeeProjection(path, p) == nil {
		t.Fatal("projection rollback survived reconstruction")
	}
}
func TestMihomoProjectionClientNoStoreBootNonceAndNoFallback(t *testing.T) {
	_, projection := bundleFixture(time.Now())
	cache := "private, no-store"
	unexpected := 0
	invalidJSON := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/source") {
			unexpected++
			http.Error(w, "upstream-secret", 500)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/projection") {
			t.Errorf("unexpected projection path %s", r.URL.Path)
		}
		projection.ProcessEpoch = r.URL.Query().Get("processEpoch")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", cache)
		if invalidJSON {
			w.Write([]byte(`{"sourceUrl":"https://upstream-secret.invalid"}`))
			return
		}
		json.NewEncoder(w).Encode(projection)
	}))
	defer server.Close()
	client, err := NewControlClient(server.URL, "endpoint-1", server.Client(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.MihomoProjection(context.Background(), projection.ProfileID)
	if err != nil || got.ProcessEpoch != client.processEpoch {
		t.Fatalf("projection: %v", err)
	}
	cache = "no-store"
	if _, err = client.MihomoProjection(context.Background(), projection.ProfileID); err == nil {
		t.Fatal("public projection accepted")
	}
	cache = "private, no-store"
	invalidJSON = true
	if _, err = client.MihomoProjection(context.Background(), projection.ProfileID); err == nil || strings.Contains(err.Error(), "upstream-secret") {
		t.Fatalf("unsafe response error: %v", err)
	}
	if unexpected != 0 {
		t.Fatal("source fallback was used")
	}
}
func TestMihomoPersonalCASRecoveryAndMasking(t *testing.T) {
	c, p := bundleFixture(time.Now())
	c.Projection = &p
	required := api.NetworkProxyRule{RuleID: "org-deny", Source: "organization_required", Enabled: true, Matcher: api.NetworkProxyRuleMatcher{Type: "domain", Value: "blocked.example"}, Action: api.NetworkProxyRuleAction{Type: "reject"}}
	c.Projection.Rules = []api.NetworkProxyRule{required}
	e, _ := NewCoordinatedExecutor(&fakeConfigurationExecutor{}, &fakeMihomoRuntime{}, filepath.Join(t.TempDir(), "app.json"))
	draft := api.NetworkProxyRule{RuleID: "personal-1", Source: "personal", Enabled: true, Matcher: required.Matcher, Action: api.NetworkProxyRuleAction{Type: "node", TargetID: "node-a"}}
	input := api.NetworkProxyRulesInput{ExpectedOrgRevision: 1, ExpectedPersonalRevision: 0, Rules: []api.NetworkProxyRule{draft}}
	if err := e.storePersonal(input, c); err != nil {
		t.Fatal(err)
	}
	if err := e.storePersonal(input, c); !errors.Is(err, proxypolicy.ErrRevisionConflict) {
		t.Fatalf("CAS: %v", err)
	}
	recovered, _ := NewCoordinatedExecutor(&fakeConfigurationExecutor{}, &fakeMihomoRuntime{}, e.appStatePath)
	if err := recovered.loadPersonal(); err != nil {
		t.Fatal(err)
	}
	result, err := recovered.composeRules(c)
	if err != nil || len(result.Rules) != 1 || len(result.Conflicts) != 1 || result.Rules[0].RuleID != draft.RuleID {
		t.Fatalf("retained rules=%#v err=%v", result, err)
	}
	c.OrgRevision = 2
	c.Projection.Rules = nil
	result, err = recovered.composeRules(c)
	if err != nil || len(result.Conflicts) != 0 || result.PersonalRevision != 1 {
		t.Fatalf("org refresh lost personal draft: %#v %v", result, err)
	}
	edited := draft
	edited.Matcher = api.NetworkProxyRuleMatcher{Type: "process_name", Value: "browser"}
	edited.Action = api.NetworkProxyRuleAction{Type: "direct"}
	if err := recovered.storePersonal(api.NetworkProxyRulesInput{ExpectedOrgRevision: 2, ExpectedPersonalRevision: 1, Rules: []api.NetworkProxyRule{edited}}, c); err != nil {
		t.Fatal(err)
	}
	if recovered.personalRules.Revision != 2 {
		t.Fatal("personal revision did not advance")
	}
}

type bundleControl struct {
	fakeControl
	projection    api.NetworkProxyEmployeeProjection
	projectionErr error
	receipts      []api.NetworkProxyProjectionApplied
}

func (c *bundleControl) MihomoProjection(context.Context, string) (api.NetworkProxyEmployeeProjection, error) {
	return c.projection, c.projectionErr
}
func (c *bundleControl) ReportMihomoProjection(_ context.Context, _ string, r api.NetworkProxyProjectionApplied) error {
	c.receipts = append(c.receipts, r)
	return nil
}
func TestMihomoManagerRenewalReceiptsAndFailureClose(t *testing.T) {
	now := time.Now().UTC()
	c, p := bundleFixture(now)
	c.Protection.PolicyVersion = 3
	desired := ConfigurationDesired{ConfigurationVersion: 5, PolicyVersion: 3, ValidUntil: now.Add(3 * time.Minute), AccessProfile: "full", ProtectedResourceIDs: []string{}, NetworkLeases: []NetworkLease{}, ResourceLeases: []ResourceLease{}, Mihomo: &c}
	raw, _ := json.Marshal(desired)
	control := &bundleControl{fakeControl: fakeControl{configuration: RuntimeMessage{SchemaVersion: RuntimeSchemaVersion, MessageID: "message-1", MessageType: MessageConfiguration, ProducerID: "network-control", RuntimeID: "endpoint-1", RuntimeKind: "endpoint", OccurredAt: now, ExpiresAt: desired.ValidUntil, Payload: raw}}, projection: p}
	executor := &fakeConfigurationExecutor{outcome: ApplyOutcome{Status: "applied", ReadbackHash: emptyReadbackHash()}}
	manager, err := NewManager(ManagerOptions{ControlURL: "https://control.example.test", ConfigurationStatePath: filepath.Join(t.TempDir(), "floor.json"), RuntimeID: "endpoint-1", DeviceID: "device-1", PollInterval: time.Second, HeartbeatInterval: time.Minute, RenewBefore: 30 * time.Second, MaxClockSkew: time.Minute}, control, executor, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return now }
	if err = manager.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if executor.applyCalls != 1 || len(control.receipts) != 1 || control.receipts[0].ProcessEpoch != p.ProcessEpoch || control.sourceCalls != 0 {
		t.Fatalf("apply=%d receipts=%v source=%d", executor.applyCalls, control.receipts, control.sourceCalls)
	}
	if err = manager.Cycle(context.Background()); err != nil || executor.applyCalls != 1 || len(control.receipts) != 1 {
		t.Fatalf("stable poll: %v", err)
	}
	control.projection.Credential.ExpiresAt = now.Add(90 * time.Second)
	if err = manager.Cycle(context.Background()); err != nil || executor.applyCalls != 2 || len(control.receipts) != 2 {
		t.Fatalf("same-revision lease renewal: %v apply=%d", err, executor.applyCalls)
	}
	control.projectionErr = errors.New("upstream-secret-must-not-be-forwarded")
	if err = manager.Cycle(context.Background()); err == nil || strings.Contains(err.Error(), "upstream-secret") {
		t.Fatalf("unavailable projection err=%v", err)
	}
	if executor.disableCalls == 0 || control.sourceCalls != 0 {
		t.Fatal("projection failure did not fail closed, or used source fallback")
	}
}
func TestMihomoProjectionTLSConnectCredentialStaysInService(t *testing.T) {
	_, p := bundleFixture(time.Now())
	var gotUser, gotPassword, target string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target = r.Host
		encoded := strings.TrimPrefix(r.Header.Get("Proxy-Authorization"), "Basic ")
		raw, _ := base64.StdEncoding.DecodeString(encoded)
		parts := strings.SplitN(string(raw), ":", 2)
		if len(parts) == 2 {
			gotUser, gotPassword = parts[0], parts[1]
		}
		conn, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		buffer.Flush()
		body := make([]byte, 4)
		if _, err = io.ReadFull(buffer, body); err == nil {
			conn.Write(body)
		}
	}))
	defer server.Close()
	p.Endpoints[0].URL = server.URL
	c, _ := NewMihomoController("http://127.0.0.1:9090", strings.Repeat("a", 32))
	c.transportTLS = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	conn, err := c.dialProjection(context.Background(), &p, "node-a", "destination.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("ping"))
	body := make([]byte, 4)
	if _, err = io.ReadFull(conn, body); err != nil || string(body) != "ping" {
		t.Fatal(err)
	}
	credential, node, err := proxytransport.DecodeMappedUsername(gotUser)
	if err != nil || credential != p.Credential.CredentialID || node != "node-a" || gotPassword != p.Credential.Secret || target != "destination.example:443" {
		t.Fatal("scoped CONNECT identity or destination was changed")
	}
	c.transportTLS = &tls.Config{MinVersion: tls.VersionTLS12}
	if conn, err = c.dialProjection(context.Background(), &p, "node-a", "destination.example:443"); err == nil {
		conn.Close()
		t.Fatal("untrusted internal TLS accepted")
	}
}
func TestMihomoProxyIPCFrameBoundary(t *testing.T) {
	if err := writeIPCFrame(io.Discard, make([]byte, maxIPCMessageBytes)); err != nil {
		t.Fatal(err)
	}
	if err := writeIPCFrame(io.Discard, make([]byte, maxIPCMessageBytes+1)); err == nil {
		t.Fatal("oversized proxy frame accepted")
	}
	var framed bytes.Buffer
	if err := writeIPCFrame(&framed, []byte(`{"safe":true}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := readIPCFrame(&framed); err != nil {
		t.Fatal(err)
	}
}

func TestMihomoDirectBundleNeverFetchesSourceAndKeepsContentOutOfIPC(t *testing.T) {
	now := time.Now().UTC()
	c, _ := bundleFixture(now)
	c.DeliveryMode = "direct_subscription"
	c.SourceType = "manual_node"
	c.DirectProjection = &api.NetworkProxyDirectProjection{SchemaVersion: "proxy-direct/v1", RuntimeID: "endpoint-1", ProfileID: c.ProfileID, BundleID: c.BundleID, Revision: 1, ActiveRevision: 1, SourceRevision: 1, OrgRevision: 1, ProjectionHash: "sha256:" + strings.Repeat("a", 64), ProcessEpoch: "boot-1", ExpiresAt: now.Add(2 * time.Minute), DeliveryMode: "direct_subscription", UpstreamDisclosure: "upstream_parameters", Format: "mihomo_yaml", Content: "proxies:\n  - name: node-a\n    type: http\n    server: 8.8.8.8\n    port: 443\n    tls: true\n    username: direct-user\n    password: upstream-secret\n", Groups: []api.NetworkProxyGroup{{GroupID: "Soha", Label: "Soha", NodeIDs: []string{"node-a"}, Type: "select"}}, Rules: []api.NetworkProxyRule{}}
	if err := validateDirectProjection(*c.DirectProjection, c, "endpoint-1", c.EnforcementUntil, now); err != nil {
		t.Fatal(err)
	}
	secret := strings.Repeat("a", 32)
	server, fixture := newMihomoControllerFixture(t, secret)
	controller, err := NewMihomoController(server.URL, secret)
	if err != nil {
		t.Fatal(err)
	}
	c.ControllerPort = controller.port
	e, _ := NewCoordinatedExecutor(&fakeConfigurationExecutor{outcome: ApplyOutcome{Status: "applied"}}, controller, filepath.Join(t.TempDir(), "app.json"))
	defer e.Disable(context.Background())
	outcome := e.Apply(context.Background(), ConfigurationDesired{PolicyVersion: c.Protection.PolicyVersion, ValidUntil: c.EnforcementUntil, Mihomo: &c}, now)
	if outcome.Status != "applied" {
		t.Fatalf("direct apply=%#v", outcome)
	}
	view, err := e.Proxy(context.Background(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(view)
	if strings.Contains(string(raw), "upstream-secret") || strings.Contains(string(raw), "8.8.8.8") || strings.Contains(string(raw), "direct-user") {
		t.Fatal("direct content leaked into IPC workbench")
	}
	fixture.mu.Lock()
	payload := fixture.payload
	fixture.mu.Unlock()
	if !strings.Contains(payload, "soha-owned-outbound-") || !strings.Contains(payload, "soha-owned-backend-") {
		t.Fatal("direct node did not get guarded backend")
	}
}
func TestMihomoProxyIPCStatusAndParameterIsolation(t *testing.T) {
	controller, _ := NewMihomoController("http://127.0.0.1:9090", strings.Repeat("a", 32))
	e, _ := NewCoordinatedExecutor(&fakeConfigurationExecutor{}, controller)
	manager := &Manager{executor: e}
	if view, err := runProxyIPCAction(context.Background(), manager, IPCRequest{Action: "proxy_status"}); err != nil || view.Engine != "mihomo" {
		t.Fatalf("proxy status %v", err)
	}
	if _, err := runProxyIPCAction(context.Background(), manager, IPCRequest{Action: "proxy_status", Proxy: &ProxyAction{Kind: "stop"}}); err == nil {
		t.Fatal("read operation accepted write parameters")
	}
	e.mihomoActive = true
	if _, err := runProxyIPCAction(context.Background(), manager, IPCRequest{Action: "proxy_action", Proxy: &ProxyAction{Kind: "stop"}}); !errors.Is(err, ErrMihomoProcessUnsupported) {
		t.Fatalf("external stop=%v", err)
	}
	if !e.mihomoActive {
		t.Fatal("unsupported external stop changed runtime observation")
	}
}

func TestMihomoPersonalCompositionPreservesLargeProtectedSetQuota(t *testing.T) {
	c, _ := bundleFixture(time.Now())
	c.Protection.CIDRs = []string{}
	c.Protection.Hosts = []string{}
	for i := 0; i < 2050; i++ {
		c.Protection.CIDRs = append(c.Protection.CIDRs, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
	}
	e, _ := NewCoordinatedExecutor(&fakeConfigurationExecutor{}, &fakeMihomoRuntime{})
	result, err := e.composeRules(c)
	if err != nil || len(result.EffectiveRules) != 2050 {
		t.Fatalf("protected quota regressed: %d %v", len(result.EffectiveRules), err)
	}
	baseline := len(mihomoRules(c))
	c.EffectiveRules = result.EffectiveRules
	if len(mihomoRules(c)) != baseline {
		t.Fatal("protected rules were duplicated by composition")
	}
}

func TestMihomoPersonalRulesPrecedeBypassAndLegacyGroupRemainsGuarded(t *testing.T) {
	c := managedMihomoConfiguration(9090)
	c.EffectiveRules = []api.NetworkProxyRule{{RuleID: "personal-route", Source: "personal", Enabled: true, Matcher: api.NetworkProxyRuleMatcher{Type: "domain", Value: "control.example.test"}, Action: api.NetworkProxyRuleAction{Type: "group", TargetID: c.SelectorGroup}}}
	rules := mihomoRules(c)
	if len(rules) == 0 || rules[0].Proxy != mihomoGuardProxyName || rules[0].Payload != "control.example.test" {
		t.Fatal("personal preference was shadowed by bypass or bypassed guard")
	}
}

func TestMihomoBundleModeCannotFallBackThroughLegacyAppMode(t *testing.T) {
	c, _ := bundleFixture(time.Now())
	c.Mode = "app_subscription"
	c.SourceType = ""
	c.SelectedProxy = ""
	if validateMihomoConfiguration(&c, nil, false) == nil {
		t.Fatal("mapped delivery accepted app subscription mode")
	}
	c, _ = bundleFixture(time.Now())
	c.DeliveryMode = ""
	if validateMihomoConfiguration(&c, nil, false) == nil {
		t.Fatal("ambiguous bundle accepted legacy source path")
	}
}
