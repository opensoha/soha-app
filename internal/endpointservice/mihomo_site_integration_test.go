//go:build !windows

package endpointservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/opensoha/soha-contracts/proxytransport"
	"go.yaml.in/yaml/v3"
	"golang.org/x/net/proxy"
)

// This opt-in library harness uses actual enrolled control/projection/receipts.
// Its explicit empty-network System never configures an OS tunnel or proxy.
type siteHarnessInput struct {
	Version                 int               `json:"version"`
	Stage                   string            `json:"stage"`
	LifecycleScenario       string            `json:"lifecycleScenario"`
	Config                  Config            `json:"config"`
	ClientVersion           string            `json:"clientVersion"`
	TimeoutSeconds          int               `json:"timeoutSeconds"`
	MarkerWaitSeconds       int               `json:"markerWaitSeconds"`
	MarkerDirectory         string            `json:"markerDirectory"`
	ProfileID               string            `json:"profileId"`
	DeliveryMode            string            `json:"deliveryMode"`
	TCPDestination          string            `json:"tcpDestination"`
	UDPDestination          string            `json:"udpDestination"`
	Nodes                   []siteHarnessNode `json:"nodes"`
	ProtectedTCPDestination string            `json:"protectedTcpDestination"`
	ProtectedUDPDestination string            `json:"protectedUdpDestination"`
	ForbiddenMarkers        []string          `json:"forbiddenMarkers"`
	AllowedMappedOrigins    []string          `json:"allowedMappedOrigins"`
}
type siteHarnessNode struct {
	ID         string `json:"id"`
	EchoPrefix string `json:"echoPrefix"`
}
type siteNoNetworkSystem struct{}

func (siteNoNetworkSystem) Apply(context.Context, TunnelPlan) error {
	return errors.New("site harness forbids OS network apply")
}
func (siteNoNetworkSystem) Readback(context.Context) (TunnelReadback, error) {
	return TunnelReadback{}, nil
}
func (siteNoNetworkSystem) Disable(context.Context) error { return nil }

type siteNoVPNExecutor struct{ *Executor }

func (e siteNoVPNExecutor) Apply(ctx context.Context, d ConfigurationDesired, now time.Time) ApplyOutcome {
	if d.WireGuard != nil {
		return ApplyOutcome{Status: "rejected", ReadbackHash: emptyReadbackHash(), ReasonCode: "site_vpn_not_supported"}
	}
	return e.Executor.Apply(ctx, d, now)
}
func (e siteNoVPNExecutor) Verify(ctx context.Context, d ConfigurationDesired, now time.Time) ApplyOutcome {
	if d.WireGuard != nil {
		return ApplyOutcome{Status: "rejected", ReadbackHash: emptyReadbackHash(), ReasonCode: "site_vpn_not_supported"}
	}
	return e.Executor.Verify(ctx, d, now)
}

type siteProjectionIdentity struct {
	BundleID       string `json:"bundleId"`
	ProfileID      string `json:"profileId"`
	Hash           string `json:"projectionHash"`
	Boot           string `json:"endpointBoot"`
	Revision       int64  `json:"revision"`
	ActiveRevision int64  `json:"activeRevision"`
	SourceRevision int64  `json:"sourceRevision"`
	OrgRevision    int64  `json:"orgRevision"`
	Credential     string `json:"-"`
}

func siteCurrent(t *testing.T, e *CoordinatedExecutor) (MihomoConfiguration, siteProjectionIdentity) {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.proxyDesired == nil {
		t.Fatal("site profile is not applied")
	}
	c := cloneMihomoConfiguration(*e.proxyDesired)
	identity := siteProjectionIdentity{ProfileID: c.ProfileID}
	if p := c.Projection; p != nil {
		identity.BundleID = p.BundleID
		identity.Hash = p.ProjectionHash
		identity.Boot = p.ProcessEpoch
		identity.Revision = p.Revision
		identity.ActiveRevision = p.ActiveRevision
		identity.SourceRevision = p.SourceRevision
		identity.OrgRevision = p.OrgRevision
		identity.Credential = projectionCredentialKey(p)
	} else if p := c.DirectProjection; p != nil {
		identity.BundleID = p.BundleID
		identity.Hash = p.ProjectionHash
		identity.Boot = p.ProcessEpoch
		identity.Revision = p.Revision
		identity.ActiveRevision = p.ActiveRevision
		identity.SourceRevision = p.SourceRevision
		identity.OrgRevision = p.OrgRevision
	} else {
		t.Fatal("site requires actual bundled projection")
	}
	return c, identity
}
func siteInput(t *testing.T, path string) siteHarnessInput {
	t.Helper()
	raw, err := readFileBounded(path, 64<<10, true)
	if err != nil {
		t.Fatal("private site input unavailable")
	}
	defer clear(raw)
	var in siteHarnessInput
	if decodeStrict(raw, &in) != nil {
		t.Fatal("invalid private site input")
	}
	if in.Version != 1 || (in.Stage != "enroll-cycle" && in.Stage != "traffic" && in.Stage != "inspect-negative" && in.Stage != "lifecycle") || in.Config.Version != 1 || !identifierPattern.MatchString(in.Config.RuntimeID) || !identifierPattern.MatchString(in.Config.DeviceID) || !filepath.IsAbs(in.Config.StateDirectory) || in.Config.EnrollmentID == "" || in.ClientVersion == "" {
		t.Fatal("invalid site identity or stage")
	}
	if in.TimeoutSeconds == 0 {
		in.TimeoutSeconds = 180
	}
	if in.TimeoutSeconds < 15 || in.TimeoutSeconds > 240 {
		t.Fatal("site duration must be 15..240 seconds")
	}
	if in.Stage == "lifecycle" {
		if in.MarkerWaitSeconds == 0 {
			in.MarkerWaitSeconds = 90
		}
		if siteValidateLifecycle(in) != nil {
			t.Fatal("invalid lifecycle private input")
		}
	}
	if in.Stage == "inspect-negative" {
		if siteValidateNegative(in) != nil {
			t.Fatal("invalid inspect-negative private input")
		}
	}
	if in.Stage == "traffic" {
		if in.MarkerWaitSeconds == 0 {
			in.MarkerWaitSeconds = 90
		}
		if in.MarkerWaitSeconds < 1 || in.MarkerWaitSeconds > 120 || in.TimeoutSeconds < in.MarkerWaitSeconds+30 {
			t.Fatal("invalid bounded marker interval")
		}
		if !filepath.IsAbs(in.MarkerDirectory) || !identifierPattern.MatchString(in.ProfileID) || (in.DeliveryMode != "mapped_nodes" && in.DeliveryMode != "direct_subscription") || len(in.Nodes) != 2 || in.Nodes[0].ID == in.Nodes[1].ID {
			t.Fatal("traffic requires actual profile, distinct A/B and private marker directory")
		}
		for _, node := range in.Nodes {
			if !identifierPattern.MatchString(node.ID) || len(node.EchoPrefix) > 32 || strings.ContainsAny(node.EchoPrefix, "\r\n\x00") {
				t.Fatal("invalid node echo fixture expectation")
			}
		}
		for _, target := range []string{in.TCPDestination, in.UDPDestination} {
			a, err := netip.ParseAddrPort(target)
			if err != nil || !a.Addr().Is4() || !a.Addr().IsGlobalUnicast() || a.Port() == 0 {
				t.Fatal("site destinations must be explicit unicast IPv4:port")
			}
		}
	}
	return in
}

// Record only the request location and protocol outcome. Never format the raw
// transport error: url/tls errors can contain certificate or proxy material.
type siteHTTPDiagnostics struct {
	privacy            *sitePrivacyScan
	base               http.RoundTripper
	mu                 sync.Mutex
	method, host, path string
	status, tlsVersion int
	jsonResponse       bool
}

func (d *siteHTTPDiagnostics) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := d.base.RoundTrip(r)
	if d.privacy != nil && response != nil && r.Method == http.MethodGet && (strings.HasSuffix(r.URL.Path, "/configuration") || strings.HasSuffix(r.URL.Path, "/projection") || strings.HasSuffix(r.URL.Path, "/direct-projection") || strings.HasSuffix(r.URL.Path, "/source")) {
		raw, readErr := siteReplayBody(response)
		if readErr != nil {
			d.privacy.fail("core-response-read")
		} else {
			d.privacy.add("actual-core-response", raw, "json")
		}
		if strings.HasSuffix(r.URL.Path, "/source") || strings.HasSuffix(r.URL.Path, "/direct-projection") {
			d.privacy.fail("mapped-source-fallback")
		}
	}
	d.mu.Lock()
	d.method = r.Method
	d.host = r.URL.Host
	d.path = r.URL.Path
	d.status = 0
	d.tlsVersion = 0
	d.jsonResponse = false
	if response != nil {
		d.status = response.StatusCode
		d.jsonResponse = strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "application/json")
		if response.TLS != nil {
			d.tlsVersion = int(response.TLS.Version)
		}
	}
	d.mu.Unlock()
	return response, err
}
func (d *siteHTTPDiagnostics) summary() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return fmt.Sprintf("method=%s host=%s path=%s status=%d tlsVersion=%d json=%v", d.method, d.host, d.path, d.status, d.tlsVersion, d.jsonResponse)
}
func siteSafeError(err error) string {
	codes := []string{}
	chain := []string{}
	var runtimeHTTP *RuntimeHTTPError
	if errors.As(err, &runtimeHTTP) {
		code := "unknown"
		switch runtimeHTTP.Code {
		case "stale_configuration", "configuration_ack_conflict":
			code = runtimeHTTP.Code
		}
		codes = append(codes, fmt.Sprintf("runtime_http_status=%d_code=%s", runtimeHTTP.StatusCode, code))
	}

	if errors.Is(err, context.DeadlineExceeded) {
		codes = append(codes, "deadline")
	}
	if errors.Is(err, context.Canceled) {
		codes = append(codes, "cancelled")
	}
	if errors.Is(err, io.EOF) {
		codes = append(codes, "eof")
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		codes = append(codes, "unexpected_eof")
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		codes = append(codes, "x509_unknown_authority")
	}
	var host x509.HostnameError
	if errors.As(err, &host) {
		codes = append(codes, "x509_hostname")
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		codes = append(codes, fmt.Sprintf("x509_invalid_reason_%d", invalid.Reason))
	}
	var roots x509.SystemRootsError
	if errors.As(err, &roots) {
		codes = append(codes, "x509_system_roots")
	}
	var record tls.RecordHeaderError
	if errors.As(err, &record) {
		codes = append(codes, "tls_record_header")
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		codes = append(codes, fmt.Sprintf("dns_notfound=%v_timeout=%v", dns.IsNotFound, dns.IsTimeout))
	}
	var operation *net.OpError
	if errors.As(err, &operation) {
		codes = append(codes, "net_operation="+operation.Op+"_"+operation.Net)
	}
	var number syscall.Errno
	if errors.As(err, &number) {
		codes = append(codes, fmt.Sprintf("errno_%d", number))
	}
	static := map[string]string{
		"endpoint enrollment parameters are invalid":                             "enrollment_parameters",
		"network runtime returned a non-JSON response":                           "response_non_json",
		"network runtime response exceeded the safe limit":                       "response_read_or_size",
		"network control returned malformed JSON":                                "response_runtime_json",
		"network control returned a message outside the endpoint trust boundary": "response_trust_boundary",
		"network control returned an invalid endpoint payload":                   "response_payload",
		"http: server gave HTTP response to HTTPS client":                        "https_received_http",
		"remote error: tls: certificate required":                                "tls_client_certificate_required",
		"tls: bad certificate":                                                   "tls_bad_certificate",
		"tls: unknown certificate authority":                                     "tls_unknown_ca",
	}
	for cause, n := err, 0; cause != nil && n < 10; cause, n = errors.Unwrap(cause), n+1 {
		chain = append(chain, fmt.Sprintf("%T", cause))
		if code := static[cause.Error()]; code != "" {
			codes = append(codes, code)
		}
		if strings.HasPrefix(cause.Error(), "endpoint enrollment was not accepted: ") {
			codes = append(codes, "enrollment_not_accepted")
		}
	}
	return "classes=" + strings.Join(chain, "->") + " codes=" + strings.Join(codes, ",")
}

func TestMihomoSiteIntegration(t *testing.T) {
	inputPath := os.Getenv("SOHA_APP_SITE_INPUT")
	if inputPath == "" {
		t.Skip("private site harness input not configured")
	}
	in := siteInput(t, inputPath)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(in.TimeoutSeconds)*time.Second)
	defer cancel()
	if err := os.MkdirAll(in.Config.StateDirectory, 0700); err != nil {
		t.Fatal("site state directory unavailable")
	}
	if err := secureStateDirectory(in.Config.StateDirectory); err != nil {
		t.Fatal("site state directory must be private")
	}
	// Do not call platform Config.Validate: Linux native service installation is
	// unsupported. The actual library constructors validate each used dependency.
	controlHTTP, devicePublicKey, err := in.Config.ControlHTTPClient()
	if err != nil {
		t.Fatal("site device mTLS identity unavailable")
	}
	var privacy *sitePrivacyScan
	if in.Stage == "inspect-negative" {
		privacy = newSitePrivacyScan(in.ForbiddenMarkers)
	}
	diagnostic := &siteHTTPDiagnostics{base: controlHTTP.Transport, privacy: privacy}
	controlHTTP.Transport = diagnostic
	control, err := NewControlClient(in.Config.ControlURL, in.Config.RuntimeID, controlHTTP, time.Minute, "mihomo", "mihomo-policy-v1", "mihomo-dns-pin-v1")
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := LoadOrCreatePrivateKey(filepath.Join(in.Config.StateDirectory, "site-wireguard.key"))
	if err != nil {
		t.Fatal("site key persistence unavailable")
	}
	enrolled, err := EnrollmentCompleted(in.Config.EnrollmentMarkerPath(), in.Config.EnrollmentID)
	if err != nil {
		t.Fatal("site enrollment marker unavailable")
	}
	if !enrolled && (in.Stage == "inspect-negative" || in.Stage == "lifecycle") {
		t.Fatal("stage requires original persisted enrollment marker")
	}
	if !enrolled {
		enrollment, err := in.Config.Enrollment(privateKey.PublicKey().String(), devicePublicKey, in.ClientVersion)
		if err != nil {
			t.Fatal("site enrollment input unavailable")
		}
		if _, err = control.Enroll(ctx, enrollment); err != nil {
			var status *RuntimeHTTPError
			if errors.As(err, &status) {
				t.Fatalf("actual enrollment rejected status=%d code=%s", status.StatusCode, status.Code)
			}
			t.Fatalf("actual enrollment failed %s %s", diagnostic.summary(), siteSafeError(err))
		}
		if err = RecordEnrollment(in.Config.EnrollmentMarkerPath(), in.Config.EnrollmentID); err != nil {
			t.Fatal("site enrollment result could not persist")
		}
	}
	secret, err := in.Config.MihomoControllerSecret()
	if err != nil {
		t.Fatal("site owned-controller secret unavailable")
	}
	defer func() { secret = "" }()
	controller, err := NewConfiguredMihomoController(in.Config, secret)
	if err != nil {
		t.Fatal("site owned Mihomo configuration invalid")
	}
	transport := &realAppCountTransport{base: controller.http.Transport, controller: controller}
	if transport.base == nil {
		transport.base = http.DefaultTransport
	}
	controller.http.Transport = transport
	if privacy != nil {
		controller.http.Transport = &sitePrivacyControllerTransport{base: transport, scan: privacy}
	}
	wg, err := NewExecutor(privateKey, siteNoNetworkSystem{})
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewCoordinatedExecutor(siteNoVPNExecutor{wg}, controller, filepath.Join(in.Config.StateDirectory, "site-app.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err := executor.Disable(cleanup); err != nil {
			t.Error("owned site process cleanup failed")
		}
		if controller.ProcessStatus().PID != 0 {
			t.Error("owned site process remained after cleanup")
		}
	}()
	manager, err := NewManager(ManagerOptions{ControlURL: in.Config.ControlURL, ConfigurationStatePath: filepath.Join(in.Config.StateDirectory, "site-configuration-floor.json"), RuntimeID: in.Config.RuntimeID, DeviceID: in.Config.DeviceID, PollInterval: time.Second, HeartbeatInterval: time.Minute, RenewBefore: 30 * time.Second, MaxClockSkew: time.Minute}, control, executor, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal("site manager initialization failed")
	}
	if err := manager.Cycle(ctx); err != nil {
		if privacy != nil && privacy.problem() != "" {
			t.Fatal("mapped privacy inspection failed")
		}
		t.Fatalf("actual site Cycle failed diagnostic=%s %s %s", manager.Status().Diagnostic, diagnostic.summary(), siteSafeError(err))
	}
	if manager.Status().ConfigurationVersion < 1 {
		t.Fatal("actual configuration was not accepted")
	}
	if in.Stage == "enroll-cycle" {
		t.Logf("SITE PASS stage=enroll-cycle runtime=%s device=%s version=%d; actual enrollment/configuration/report path", in.Config.RuntimeID, in.Config.DeviceID, manager.Status().ConfigurationVersion)
		return
	}
	configuration, identity := siteCurrent(t, executor)
	if configuration.ProfileID != in.ProfileID || configuration.DeliveryMode != in.DeliveryMode || identity.Hash == "" {
		t.Fatal("actual site profile binding differs from input")
	}
	allowed := configurationNodeIDs(configuration)
	for _, node := range in.Nodes {
		if !slicesContains(allowed, node.ID) {
			t.Fatal("site expected node is not authorized")
		}
	}
	native := net.JoinHostPort("127.0.0.1", fmt.Sprint(configuration.MixedPort))
	before := controller.ProcessStatus()
	puts := transport.puts.Load()
	if before.Ownership != "soha_owned" || before.PID == 0 || before.State != "running" {
		t.Fatal("site kernel is not owned and running")
	}
	if in.Stage == "inspect-negative" {
		siteInspectNegative(t, ctx, in, executor, controller, configuration, privacy)
		return
	}
	if in.Stage == "lifecycle" {
		siteLifecycle(t, ctx, in, manager, executor, controller, transport, configuration, identity, before, puts)
		return
	}
	realAppBusiness(t, controller, "site-baseline", 0, 0, 0)
	var streams [2]net.Conn
	var packets [2]net.Conn
	var up, down int64
	for i, node := range in.Nodes {
		if _, err := executor.Proxy(ctx, &ProxyAction{Kind: "select", GroupID: configuration.SelectorGroup, NodeID: node.ID}, nil); err != nil {
			t.Fatal("actual node selection failed")
		}
		streams[i] = siteTCP(t, ctx, native, in.TCPDestination)
		packets[i] = siteUDP(t, native, in.UDPDestination)
		for _, flow := range []struct {
			conn   net.Conn
			packet bool
		}{{streams[i], false}, {packets[i], true}} {
			for n := 0; n < 16; n++ {
				if err := siteEcho(ctx, flow.conn, node.EchoPrefix, flow.packet); err != nil {
					t.Fatal("actual site A/B echo failed")
				}
			}
			up += 80
			down += int64(16 * (len(node.EchoPrefix) + 5))
			realAppBusiness(t, controller, "site-fixed-payload", up, down, 2*i+1+boolInt(flow.packet))
		}
	}
	if err := manager.Cycle(ctx); err != nil {
		t.Fatalf("actual projection renewal failed diagnostic=%s", manager.Status().Diagnostic)
	}
	_, renewed := siteCurrent(t, executor)
	if renewed != identity || controller.ProcessStatus().PID != before.PID || controller.ProcessStatus().ProcessEpoch != before.ProcessEpoch || transport.puts.Load() != puts {
		t.Fatal("actual renewal changed immutable projection or owned kernel")
	}
	siteClose(t, ctx, executor, controller, transport, native, in, streams[1], packets[1])
	siteNarrow(t, ctx, in, manager, executor, controller, transport, configuration, identity, before, puts, streams, packets)
	t.Logf("SITE PASS stage=traffic runtime=%s profile=%s mode=%s actual A/B TCP/UDP, metering, close, renewal, live narrow; nativePID=%d", in.Config.RuntimeID, in.ProfileID, in.DeliveryMode, before.PID)
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
func siteTCP(t *testing.T, ctx context.Context, native, target string) net.Conn {
	t.Helper()
	d, err := proxy.SOCKS5("tcp", native, nil, &net.Dialer{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.(proxy.ContextDialer).DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatal("site native TCP connect failed")
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func siteUDP(t *testing.T, native, target string) net.Conn {
	t.Helper()
	address := netip.MustParseAddrPort(target)
	packet := realAppNativeUDP(t, native).(*realAppNativePacket)
	ip := address.Addr().As4()
	packet.header = []byte{0, 0, 0, 1, ip[0], ip[1], ip[2], ip[3], byte(address.Port() >> 8), byte(address.Port())}
	return packet
}

var errSiteEchoPayload = errors.New("unexpected fixed site fixture response")

func siteEcho(ctx context.Context, c net.Conn, prefix string, packet bool) error {
	deadline := time.Now().Add(3 * time.Second)
	if until, ok := ctx.Deadline(); ok && until.Before(deadline) {
		deadline = until
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.SetDeadline(deadline)
	defer c.SetDeadline(time.Time{})
	payload := []byte("proof")
	if _, err := c.Write(payload); err != nil {
		return err
	}
	expected := append([]byte(prefix), payload...)
	buffer := make([]byte, 65507)
	var n int
	var err error
	if packet {
		n, err = c.Read(buffer)
	} else {
		n, err = io.ReadFull(c, buffer[:len(expected)])
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(buffer[:n], expected) {
		return errSiteEchoPayload
	}
	return nil
}
func siteClose(t *testing.T, ctx context.Context, e *CoordinatedExecutor, c *MihomoController, transport *realAppCountTransport, native string, in siteHarnessInput, bTCP, bUDP net.Conn) {
	t.Helper()
	traffic, snapshot, err := c.observeLocal(ctx)
	if err != nil {
		t.Fatal("site close baseline unsettled")
	}
	ids := map[string]bool{}
	for _, item := range snapshot.Items {
		ids[item.ConnectionID] = true
	}
	extra := siteTCP(t, ctx, native, in.TCPDestination)
	if err := siteEcho(ctx, extra, in.Nodes[1].EchoPrefix, false); err != nil {
		t.Fatal("site close fixture failed")
	}
	_, after := realAppBusiness(t, c, "site-extra-B", traffic.UploadTotal+5, traffic.DownloadTotal+int64(5+len(in.Nodes[1].EchoPrefix)), snapshot.TotalActive+1)
	id := ""
	for _, item := range after.Items {
		if !ids[item.ConnectionID] {
			if id != "" {
				t.Fatal("site close requires exactly one visible extra flow")
			}
			id = item.ConnectionID
		}
	}
	if id == "" {
		t.Fatal("site close visible ID absent")
	}
	deletes := transport.deletes.Load()
	epoch := c.ProcessStatus().ProcessEpoch
	if _, err := e.Proxy(ctx, &ProxyAction{Kind: "close", ConnectionID: id, ProcessEpoch: epoch}, nil); err != nil || transport.deletes.Load() != deletes+1 {
		t.Fatal("actual site visible close failed")
	}
	extra.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := extra.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatal("site closed flow survived")
	}
	if siteEcho(ctx, bTCP, in.Nodes[1].EchoPrefix, false) != nil || siteEcho(ctx, bUDP, in.Nodes[1].EchoPrefix, true) != nil {
		t.Fatal("site close interrupted existing B")
	}
}

type siteNarrowMarker struct {
	RunID string `json:"runId"`
}

func siteNarrow(t *testing.T, ctx context.Context, in siteHarnessInput, manager *Manager, e *CoordinatedExecutor, c *MihomoController, transport *realAppCountTransport, configuration MihomoConfiguration, identity siteProjectionIdentity, before MihomoProcessStatus, puts int64, streams, packets [2]net.Conn) {
	t.Helper()
	if err := os.MkdirAll(in.MarkerDirectory, 0700); err != nil {
		t.Fatal("site marker directory unavailable")
	}
	if err := secureStateDirectory(in.MarkerDirectory); err != nil {
		t.Fatal("site marker directory must be private")
	}
	readyPath := filepath.Join(in.MarkerDirectory, "traffic-ready.json")
	narrowPath := filepath.Join(in.MarkerDirectory, "narrow-ready.json")
	if _, err := os.Lstat(narrowPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("root narrow marker must be absent at traffic start")
	}
	run := randomID()
	ready := struct {
		RunID     string `json:"runId"`
		RuntimeID string `json:"runtimeId"`
		ProfileID string `json:"profileId"`
		Mode      string `json:"deliveryMode"`
		BundleID  string `json:"bundleId"`
		Hash      string `json:"projectionHash"`
		NodeA     string `json:"nodeA"`
		NodeB     string `json:"nodeB"`
	}{run, in.Config.RuntimeID, in.ProfileID, in.DeliveryMode, identity.BundleID, identity.Hash, in.Nodes[0].ID, in.Nodes[1].ID}
	raw, err := json.Marshal(ready)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(readyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("traffic marker already exists or is unavailable")
	}
	_, writeErr := file.Write(raw)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("traffic marker write failed")
	}
	t.Log("SITE READY private traffic-ready.json written; waiting for root source scope narrowing")
	waitCtx, cancel := context.WithTimeout(ctx, time.Duration(in.MarkerWaitSeconds)*time.Second)
	defer cancel()
	narrowed := false
	for {
		if err := waitCtx.Err(); err != nil {
			t.Fatal("site narrow marker deadline exceeded")
		}
		if err := manager.Cycle(waitCtx); err != nil {
			t.Fatalf("actual narrow Cycle failed diagnostic=%s", manager.Status().Diagnostic)
		}
		current, actual := siteCurrent(t, e)
		if actual != identity || c.ProcessStatus().PID != before.PID || c.ProcessStatus().ProcessEpoch != before.ProcessEpoch || transport.puts.Load() != puts {
			t.Fatal("site immutable projection/credential/native identity changed")
		}
		ids := configurationNodeIDs(current)
		hasA, hasB := slicesContains(ids, in.Nodes[0].ID), slicesContains(ids, in.Nodes[1].ID)
		if !hasB {
			t.Fatal("site narrowing removed B")
		}
		if !hasA {
			if !narrowed {
				streams[0].SetReadDeadline(time.Now().Add(time.Second))
				if _, err := streams[0].Read(make([]byte, 1)); err == nil || isTimeout(err) {
					t.Fatal("site narrowed A TCP survived")
				}
				realAppDenied(t, packets[0])
				if _, err := e.Proxy(waitCtx, &ProxyAction{Kind: "select", GroupID: configuration.SelectorGroup, NodeID: in.Nodes[0].ID}, nil); err == nil {
					t.Fatal("site narrowed A selectable")
				}
				narrowed = true
			}
		} else if narrowed {
			t.Fatal("site A authorization widened again")
		}
		if siteEcho(waitCtx, streams[1], in.Nodes[1].EchoPrefix, false) != nil || siteEcho(waitCtx, packets[1], in.Nodes[1].EchoPrefix, true) != nil {
			t.Fatal("site B flow did not continue across source narrowing")
		}
		if hasA {
			if siteEcho(waitCtx, streams[0], in.Nodes[0].EchoPrefix, false) != nil || siteEcho(waitCtx, packets[0], in.Nodes[0].EchoPrefix, true) != nil {
				// Source commit may race an authorized keepalive. A fresh actual Cycle must
				// confirm that exact narrowing, rather than treating arbitrary I/O loss as pass.
				if err := manager.Cycle(waitCtx); err != nil {
					t.Fatal("site A loss not confirmed by actual control")
				}
				after, identityAfter := siteCurrent(t, e)
				if identityAfter != identity || slicesContains(configurationNodeIDs(after), in.Nodes[0].ID) {
					t.Fatal("site A flow failed while still authorized")
				}
			}
		}
		markerRaw, readErr := readFileBounded(narrowPath, 4096, true)
		if readErr == nil {
			var marker siteNarrowMarker
			if decodeStrict(markerRaw, &marker) != nil || marker.RunID != run {
				t.Fatal("site narrow marker nonce mismatch")
			}
			if narrowed {
				if _, err := e.Proxy(waitCtx, &ProxyAction{Kind: "select", GroupID: configuration.SelectorGroup, NodeID: in.Nodes[1].ID}, nil); err != nil {
					t.Fatal("site B cannot be explicitly selected after narrowing")
				}
				t.Log("SITE PASS actual immutable projection narrowed A to B; live B streams/native PID/epoch/config PUT preserved")
				return
			}
		}
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			t.Fatal("site narrow marker is unsafe or unreadable")
		}
		select {
		case <-waitCtx.Done():
			t.Fatal("site narrow marker deadline exceeded")
		case <-time.After(time.Second):
		}
	}
}

func siteValidateNegative(in siteHarnessInput) error {
	if in.DeliveryMode != "mapped_nodes" || !identifierPattern.MatchString(in.ProfileID) || len(in.Nodes) != 1 || !identifierPattern.MatchString(in.Nodes[0].ID) || len(in.Nodes[0].EchoPrefix) > 32 || strings.ContainsAny(in.Nodes[0].EchoPrefix, "\r\n\x00") {
		return errors.New("mapped retained B required")
	}
	if len(in.ForbiddenMarkers) < 1 || len(in.ForbiddenMarkers) > 16 || len(in.AllowedMappedOrigins) < 1 || len(in.AllowedMappedOrigins) > 4 {
		return errors.New("bounded privacy inputs required")
	}
	for _, marker := range in.ForbiddenMarkers {
		if len(marker) < 1 || len(marker) > 512 {
			return errors.New("invalid private marker length")
		}
	}
	for _, origin := range in.AllowedMappedOrigins {
		if _, err := projectionEndpoint(origin); err != nil {
			return errors.New("invalid approved mapped origin")
		}
	}
	for _, target := range []string{in.TCPDestination, in.UDPDestination, in.ProtectedTCPDestination, in.ProtectedUDPDestination} {
		a, err := netip.ParseAddrPort(target)
		if err != nil || !a.Addr().Is4() || !a.Addr().IsGlobalUnicast() || a.Port() == 0 {
			return errors.New("explicit unicast destinations required")
		}
	}
	if in.TCPDestination == in.ProtectedTCPDestination || in.UDPDestination == in.ProtectedUDPDestination {
		return errors.New("positive and protected controls must differ")
	}
	return nil
}

type sitePrivacyScan struct {
	mu                                       sync.Mutex
	markers                                  []string
	digest                                   hash.Hash
	surfaces, bytes, rendered, addressChecks int
	stateReads, executables                  int
	problemCode                              string
}

func newSitePrivacyScan(markers []string) *sitePrivacyScan {
	return &sitePrivacyScan{markers: markers, digest: sha256.New()}
}
func (s *sitePrivacyScan) fail(code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.problemCode == "" {
		s.problemCode = code
	}
}
func (s *sitePrivacyScan) problem() string { s.mu.Lock(); defer s.mu.Unlock(); return s.problemCode }
func (s *sitePrivacyScan) add(label string, raw []byte, codec string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.surfaces++
	s.bytes += len(raw)
	if s.surfaces > 256 || len(raw) > 4<<20 || s.bytes > 16<<20 {
		s.problemCode = "privacy-budget"
		return
	}
	found := false
	for _, marker := range s.markers {
		if bytes.Contains(raw, []byte(marker)) {
			found = true
		}
	}
	var decoded any
	if codec == "json" {
		_ = json.Unmarshal(raw, &decoded)
	} else if codec == "yaml" {
		_ = yaml.Unmarshal(raw, &decoded)
	}
	var visit func(any)
	visit = func(value any) {
		switch value := value.(type) {
		case string:
			for _, marker := range s.markers {
				if strings.Contains(value, marker) {
					found = true
				}
			}
		case map[string]any:
			for key, child := range value {
				visit(key)
				visit(child)
			}
		case []any:
			for _, child := range value {
				visit(child)
			}
		}
	}
	visit(decoded)
	if found {
		s.problemCode = "private-upstream-marker"
	}
	s.digest.Write([]byte(label))
	s.digest.Write([]byte{0})
	s.digest.Write(raw)
}
func (s *sitePrivacyScan) summary() (int, int, int, int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.surfaces, s.bytes, s.rendered, s.addressChecks, fmt.Sprintf("%x", s.digest.Sum(nil))
}
func siteReplayBody(response *http.Response) ([]byte, error) {
	original := response.Body
	raw, err := io.ReadAll(io.LimitReader(original, (4<<20)+1))
	response.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(raw), original), original}
	if err != nil || len(raw) > 4<<20 {
		return nil, errors.New("bounded response inspection failed")
	}
	return raw, nil
}

type sitePrivacyControllerTransport struct {
	base http.RoundTripper
	scan *sitePrivacyScan
}

func (d *sitePrivacyControllerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPut && r.URL.Path == "/configs" {
		original := r.Body
		raw, err := io.ReadAll(io.LimitReader(original, (4<<20)+1))
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(raw), original), original}
		if err != nil || len(raw) > 4<<20 {
			d.scan.fail("native-config-read")
		} else {
			var payload struct {
				Payload string `json:"payload"`
			}
			if json.Unmarshal(raw, &payload) != nil {
				d.scan.fail("native-config-json")
			} else {
				d.scan.add("actual-native-payload", []byte(payload.Payload), "yaml")
				count, err := siteOwnedProxyAddresses([]byte(payload.Payload))
				if err != nil {
					d.scan.fail("native-address-boundary")
				} else {
					d.scan.mu.Lock()
					if count > 0 {
						d.scan.rendered++
						d.scan.addressChecks += count
					}
					d.scan.mu.Unlock()
				}
			}
		}
	}
	return d.base.RoundTrip(r)
}
func siteOwnedProxyAddresses(raw []byte) (int, error) {
	var document struct {
		Proxies []struct {
			Type   string `yaml:"type"`
			Server string `yaml:"server"`
			Port   int    `yaml:"port"`
		}
		Providers   map[string]any `yaml:"proxy-providers"`
		BindAddress string         `yaml:"bind-address"`
		AllowLAN    bool           `yaml:"allow-lan"`
		TUN         struct {
			Enable bool `yaml:"enable"`
		} `yaml:"tun"`
		Listeners []struct {
			Listen string `yaml:"listen"`
			Port   int    `yaml:"port"`
		} `yaml:"listeners"`
	}
	if yaml.Unmarshal(raw, &document) != nil || len(document.Providers) > 0 {
		return 0, errors.New("unexpected native transport")
	}
	if document.AllowLAN || document.TUN.Enable {
		return 0, errors.New("unexpected native network exposure")
	}
	if len(document.Proxies) > 0 {
		bind, err := netip.ParseAddr(document.BindAddress)
		if err != nil || !bind.IsLoopback() {
			return 0, errors.New("native bind is not loopback")
		}
	}
	for _, listener := range document.Listeners {
		address, err := netip.ParseAddr(listener.Listen)
		if err != nil || !address.IsLoopback() || listener.Port < 1 || listener.Port > 65535 {
			return 0, errors.New("native backend listener is not loopback")
		}
	}
	for _, node := range document.Proxies {
		ip, err := netip.ParseAddr(node.Server)
		if err != nil || !ip.IsLoopback() || node.Port < 1 || node.Port > 65535 || (node.Type != "http" && node.Type != "socks5") {
			return 0, errors.New("native proxy is not an owned loopback adapter")
		}
	}
	return len(document.Proxies), nil
}
func siteScanState(ctx context.Context, c *MihomoController, scan *sitePrivacyScan, state string) (int, int, error) {
	files, executables := 0, 0
	err := filepath.WalkDir(state, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("owned state walk failed")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("owned state symlink refused")
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("owned state nonregular file refused")
		}
		info, err := entry.Info()
		if err != nil {
			return errors.New("owned state stat failed")
		}
		relative, err := filepath.Rel(c.process.directory, path)
		ownedExecutable := err == nil && !strings.HasPrefix(relative, "..") && strings.HasPrefix(filepath.Base(filepath.Dir(path)), "launch-") && filepath.Base(path) == "mihomo"
		if ownedExecutable {
			file, err := os.Open(path)
			if err != nil {
				return errors.New("owned executable read failed")
			}
			digest := sha256.New()
			n, readErr := io.Copy(digest, io.LimitReader(file, (256<<20)+1))
			file.Close()
			if readErr != nil || n != info.Size() || n > 256<<20 || fmt.Sprintf("%x", digest.Sum(nil)) != c.ProcessStatus().BinarySHA256 {
				return errors.New("owned executable identity mismatch")
			}
			executables++
			return nil
		}
		raw, err := readFileBounded(path, 4<<20, false)
		if err != nil {
			return errors.New("owned state read failed")
		}
		codec := "raw"
		switch filepath.Ext(path) {
		case ".json":
			codec = "json"
		case ".yaml", ".yml":
			codec = "yaml"
		}
		scan.add("owned-state", raw, codec)
		clear(raw)
		files++
		return nil
	})
	if err == nil {
		scan.mu.Lock()
		scan.stateReads += files
		scan.executables += executables
		scan.mu.Unlock()
	}
	return files, executables, err
}
func sitePrivacySurfaces(t *testing.T, ctx context.Context, in siteHarnessInput, e *CoordinatedExecutor, c *MihomoController, configuration MihomoConfiguration, scan *sitePrivacyScan) {
	t.Helper()
	if configuration.Projection == nil || configuration.DirectProjection != nil || configuration.ManualNode != nil || configuration.SubscriptionURL != "" || len(configuration.BootstrapNodes) != 0 {
		t.Fatal("mapped configuration exposed an unexpected source surface")
	}
	if len(configuration.Projection.Endpoints) == 0 {
		t.Fatal("mapped endpoints absent")
	}
	for _, endpoint := range configuration.Projection.Endpoints {
		origin, err := projectionEndpoint(endpoint.URL)
		if err != nil {
			t.Fatal("mapped endpoint invalid")
		}
		approved := false
		for _, allowed := range in.AllowedMappedOrigins {
			parsed, _ := projectionEndpoint(allowed)
			if strings.TrimRight(parsed.String(), "/") == strings.TrimRight(origin.String(), "/") {
				approved = true
			}
		}
		if !approved {
			t.Fatal("mapped endpoint outside installer-approved origins")
		}
	}
	raw, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal("mapped configuration inspection failed")
	}
	scan.add("applied-mapped-configuration", raw, "json")
	for _, path := range []string{"/configs", "/proxies"} {
		var payload json.RawMessage
		if c.request(ctx, http.MethodGet, path, nil, http.StatusOK, &payload) != nil {
			t.Fatal("actual controller privacy surface unavailable")
		}
		scan.add("controller-surface", payload, "json")
	}
	view, err := e.Proxy(ctx, nil, nil)
	if err != nil {
		t.Fatal("actual mapped diagnostics unavailable")
	}
	raw, err = json.Marshal(view)
	if err != nil {
		t.Fatal("mapped diagnostics inspection failed")
	}
	scan.add("actual-workbench-diagnostics", raw, "json")
	if _, _, err := siteScanState(ctx, c, scan, in.Config.StateDirectory); err != nil {
		t.Fatal("owned state/cache/config privacy inspection failed")
	}
	if scan.problem() != "" {
		t.Fatal("mapped privacy boundary violated")
	}
	_, _, rendered, addresses, _ := scan.summary()
	if rendered == 0 || addresses == 0 {
		t.Fatal("actual applied native transport payload was not inspected")
	}
}
func siteProtectedDeclared(c MihomoConfiguration, target string) bool {
	address, err := netip.ParseAddrPort(target)
	if err != nil || c.Protection == nil {
		return false
	}
	for _, cidr := range c.Protection.CIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err == nil && prefix.Contains(address.Addr()) {
			return true
		}
	}
	return false
}
func siteRejectProtected(t *testing.T, ctx context.Context, label string, dial func(context.Context) (net.Conn, error)) {
	t.Helper()
	if ctx.Err() != nil {
		t.Fatal("negative stage overall deadline expired")
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	conn, err := dial(bounded)
	if ctx.Err() != nil {
		t.Fatal("negative stage overall deadline expired")
	}
	if err != nil {
		t.Logf("SITE NEGATIVE %s refused-before-payload=true", label)
		return
	}
	defer conn.Close()
	deadline := time.Now().Add(700 * time.Millisecond)
	if until, ok := bounded.Deadline(); ok && until.Before(deadline) {
		deadline = until
	}
	conn.SetDeadline(deadline)
	if _, err = conn.Write([]byte("proof")); err == nil {
		n, readErr := conn.Read(make([]byte, 65507))
		if n > 0 || readErr == nil {
			t.Fatal("protected destination returned payload")
		}
	}
	if ctx.Err() != nil {
		t.Fatal("negative stage overall deadline expired")
	}
	t.Logf("SITE NEGATIVE %s no-payload=true", label)
}
func siteInspectNegative(t *testing.T, ctx context.Context, in siteHarnessInput, e *CoordinatedExecutor, c *MihomoController, configuration MihomoConfiguration, scan *sitePrivacyScan) {
	t.Helper()
	if scan == nil || configuration.DeliveryMode != "mapped_nodes" || configuration.Projection == nil {
		t.Fatal("inspect-negative requires actual mapped projection")
	}
	if len(configurationNodeIDs(configuration)) != 1 || configurationNodeIDs(configuration)[0] != in.Nodes[0].ID {
		t.Fatal("inspect-negative requires actual B-only scope")
	}
	if !siteProtectedDeclared(configuration, in.ProtectedTCPDestination) || !siteProtectedDeclared(configuration, in.ProtectedUDPDestination) {
		t.Fatal("negative destinations absent from actual ProtectedSet")
	}
	sitePrivacySurfaces(t, ctx, in, e, c, configuration, scan)
	node := in.Nodes[0]
	if _, err := e.Proxy(ctx, &ProxyAction{Kind: "select", GroupID: configuration.SelectorGroup, NodeID: node.ID}, nil); err != nil {
		t.Fatal("retained B selection failed")
	}
	native := net.JoinHostPort("127.0.0.1", fmt.Sprint(configuration.MixedPort))
	positiveTCP := siteTCP(t, ctx, native, in.TCPDestination)
	positiveUDP := siteUDP(t, native, in.UDPDestination)
	if siteEcho(ctx, positiveTCP, node.EchoPrefix, false) != nil || siteEcho(ctx, positiveUDP, node.EchoPrefix, true) != nil {
		t.Fatal("native B positive control failed")
	}
	siteRejectProtected(t, ctx, "native-tcp", func(bounded context.Context) (net.Conn, error) {
		dialer, err := proxy.SOCKS5("tcp", native, nil, &net.Dialer{Timeout: time.Second})
		if err != nil {
			return nil, err
		}
		return dialer.(proxy.ContextDialer).DialContext(bounded, "tcp", in.ProtectedTCPDestination)
	})
	siteRejectProtected(t, ctx, "native-udp", func(context.Context) (net.Conn, error) { return siteUDP(t, native, in.ProtectedUDPDestination), nil })
	// Reuse actual production TLS/credential paths, bypassing both App gates and
	// the native listener. No replacement credential or mTLS identity is invented.
	directTCP, err := c.dialProjection(ctx, configuration.Projection, node.ID, in.TCPDestination)
	if err != nil {
		t.Fatal("actual scoped HTTPS TCP positive control failed")
	}
	defer directTCP.Close()
	if siteEcho(ctx, directTCP, node.EchoPrefix, false) != nil {
		t.Fatal("actual scoped HTTPS TCP echo failed")
	}
	packetDial := func(bounded context.Context, target string) (net.Conn, error) {
		secured, err := c.projectionTLS(bounded, configuration.Projection, node.ID)
		if err != nil {
			return nil, err
		}
		user, err := proxytransport.EncodeMappedUsername(configuration.Projection.Credential.CredentialID, node.ID)
		if err != nil {
			secured.Close()
			return nil, err
		}
		until := time.Now().Add(15 * time.Second)
		if expiry := projectionCredentialUntil(configuration.Projection); expiry.Before(until) {
			until = expiry
		}
		conn, err := proxytransport.DialPacketTunnel(bounded, secured, target, user, configuration.Projection.Credential.Secret, until)
		if err != nil {
			secured.Close()
		}
		return conn, err
	}
	directUDP, err := packetDial(ctx, in.UDPDestination)
	if err != nil {
		t.Fatal("actual scoped HTTPS UDP positive control failed")
	}
	defer directUDP.Close()
	if siteEcho(ctx, directUDP, node.EchoPrefix, true) != nil {
		t.Fatal("actual scoped HTTPS UDP echo failed")
	}
	siteRejectProtected(t, ctx, "scoped-https-tcp-bypass", func(bounded context.Context) (net.Conn, error) {
		return c.dialProjection(bounded, configuration.Projection, node.ID, in.ProtectedTCPDestination)
	})
	siteRejectProtected(t, ctx, "scoped-https-udp-bypass", func(bounded context.Context) (net.Conn, error) {
		return packetDial(bounded, in.ProtectedUDPDestination)
	})
	if siteEcho(ctx, positiveTCP, node.EchoPrefix, false) != nil || siteEcho(ctx, positiveUDP, node.EchoPrefix, true) != nil || siteEcho(ctx, directTCP, node.EchoPrefix, false) != nil || siteEcho(ctx, directUDP, node.EchoPrefix, true) != nil {
		t.Fatal("B positive controls unavailable after protected checks")
	}
	sitePrivacySurfaces(t, ctx, in, e, c, configuration, scan)
	surfaces, size, rendered, addresses, digest := scan.summary()
	scan.mu.Lock()
	stateReads, executables := scan.stateReads, scan.executables
	scan.mu.Unlock()
	t.Logf("SITE PASS stage=inspect-negative privacySurfaces=%d inspectedBytes=%d nativePayloads=%d ownedLoopbackAdapters=%d stateReads=%d verifiedExecutableExclusions=%d digest=%s positivePaths=4 positiveRounds=2 protectedChecks=4; independent protected witness requires Root receipt", surfaces, size, rendered, addresses, stateReads, executables, digest)
}

func TestSiteNegativePrivacyHelpers(t *testing.T) {
	t.Run("safe-surface-and-bounded-input", func(t *testing.T) {
		scan := newSitePrivacyScan([]string{"private-upstream"})
		scan.add("synthetic", []byte(`{"safe":true}`), "json")
		surfaces, size, _, _, digest := scan.summary()
		if scan.problem() != "" || surfaces != 1 || size != 13 || len(digest) != 64 {
			t.Fatal("safe privacy surface rejected")
		}
		input := siteHarnessInput{ProfileID: "profile-1", DeliveryMode: "mapped_nodes", Nodes: []siteHarnessNode{{ID: "node-b"}}, ForbiddenMarkers: []string{"private-upstream"}, AllowedMappedOrigins: []string{"https://gateway.example.invalid"}, TCPDestination: "198.18.0.101:12001", UDPDestination: "198.18.0.101:12002", ProtectedTCPDestination: "198.18.0.102:12001", ProtectedUDPDestination: "198.18.0.102:12002"}
		if siteValidateNegative(input) != nil {
			t.Fatal("valid negative input rejected")
		}
		input.ForbiddenMarkers = nil
		if siteValidateNegative(input) == nil {
			t.Fatal("unwitnessed privacy input accepted")
		}
	})

	t.Run("raw-and-escaped-markers", func(t *testing.T) {
		for _, sample := range []struct{ raw, codec string }{{"binary-private-upstream", "raw"}, {`{"value":"private\u002dupstream"}`, "json"}, {"value: private-upstream\n", "yaml"}} {
			scan := newSitePrivacyScan([]string{"private-upstream"})
			scan.add("synthetic", []byte(sample.raw), sample.codec)
			if scan.problem() == "" {
				t.Fatal("private marker escaped inspection")
			}
		}
	})
	t.Run("only-loopback-native-servers", func(t *testing.T) {
		for _, raw := range []string{"proxies: [{type: socks5, server: 198.18.0.12, port: 1080}]", "proxies: [{type: ss, server: 127.0.0.1, port: 1080}]", "proxy-providers: {unexpected: {}}"} {
			if _, err := siteOwnedProxyAddresses([]byte("bind-address: 127.0.0.1\n" + raw)); err == nil {
				t.Fatal("unexpected native transport accepted")
			}
		}
		if count, err := siteOwnedProxyAddresses([]byte("bind-address: 127.0.0.1\nproxies: [{type: socks5, server: 127.0.0.1, port: 12345}]")); err != nil || count != 1 {
			t.Fatal("owned loopback adapter rejected")
		}
	})
	t.Run("restores-exact-response-body", func(t *testing.T) {
		payload := []byte(`{"safe":true}`)
		response := &http.Response{Body: io.NopCloser(bytes.NewReader(payload))}
		raw, err := siteReplayBody(response)
		again, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || readErr != nil || !bytes.Equal(raw, payload) || !bytes.Equal(again, payload) {
			t.Fatal("passive inspection changed response")
		}
	})
}

func siteValidateLifecycle(in siteHarnessInput) error {
	if in.LifecycleScenario != "core-close" && in.LifecycleScenario != "shrink" && in.LifecycleScenario != "restart" && in.LifecycleScenario != "steady" {
		return errors.New("unsupported lifecycle scenario")
	}
	if in.DeliveryMode != "mapped_nodes" || !identifierPattern.MatchString(in.ProfileID) || len(in.Nodes) != 1 || !identifierPattern.MatchString(in.Nodes[0].ID) || len(in.Nodes[0].EchoPrefix) > 32 || strings.ContainsAny(in.Nodes[0].EchoPrefix, "\r\n\x00") || !filepath.IsAbs(in.MarkerDirectory) {
		return errors.New("lifecycle requires mapped retained B and private marker directory")
	}
	if in.MarkerWaitSeconds < 1 || in.MarkerWaitSeconds > 180 || in.TimeoutSeconds > 240 || in.TimeoutSeconds < in.MarkerWaitSeconds+30 {
		return errors.New("invalid lifecycle bounds")
	}
	for _, target := range []string{in.TCPDestination, in.UDPDestination} {
		address, err := netip.ParseAddrPort(target)
		if err != nil || !address.Addr().Is4() || !address.Addr().IsGlobalUnicast() || address.Port() == 0 {
			return errors.New("lifecycle requires approved literal targets")
		}
	}
	return nil
}

type siteLifecycleMarker struct {
	RunID       string `json:"runId"`
	OperationID string `json:"operationId,omitempty"`
}

func siteReadLifecycleMarker(path, run string, operationRequired bool) (siteLifecycleMarker, bool, error) {
	raw, err := readFileBounded(path, 4096, true)
	if errors.Is(err, os.ErrNotExist) {
		return siteLifecycleMarker{}, false, nil
	}
	if err != nil {
		return siteLifecycleMarker{}, false, errors.New("unsafe lifecycle marker")
	}
	var marker siteLifecycleMarker
	if decodeStrict(raw, &marker) != nil || marker.RunID != run || !identifierPattern.MatchString(marker.RunID) || (operationRequired && !identifierPattern.MatchString(marker.OperationID)) || (marker.OperationID != "" && !identifierPattern.MatchString(marker.OperationID)) {
		return siteLifecycleMarker{}, false, errors.New("lifecycle marker identity mismatch")
	}
	return marker, true, nil
}
func siteWriteLifecycleMarker(directory, name string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return errors.New("lifecycle marker encoding failed")
	}
	file, err := os.CreateTemp(directory, ".hold-*.tmp")
	if err != nil {
		return errors.New("lifecycle marker staging failed")
	}
	path := file.Name()
	defer os.Remove(path)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(raw)
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return errors.New("lifecycle marker write failed")
	}
	if os.Rename(path, filepath.Join(directory, name)) != nil {
		return errors.New("lifecycle marker rename failed")
	}
	return nil
}

type siteLifecycleFlow struct {
	conn      net.Conn
	closed    bool
	ambiguous bool
	echoes    int
}

func siteLifecycleCounts(flows []siteLifecycleFlow) (alive, closed, echoes int) {
	for _, flow := range flows {
		if flow.closed {
			closed++
		} else if !flow.ambiguous {
			alive++
		}
		echoes += flow.echoes
	}
	return
}
func siteLifecyclePartialProof(alive, closed, total int) bool {
	return total > 1 && alive > 0 && closed > 0 && alive+closed == total
}

// A local timeout/cancellation/Close is not evidence of a peer closing TCP.
func siteLifecycleRemoteTCPClosed(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, net.ErrClosed) || errors.Is(err, errSiteEchoPayload) {
		return false
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return false
	}
	return errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET)
}
func siteLifecycleTCPEcho(ctx context.Context, c net.Conn, prefix string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline := time.Now().Add(3 * time.Second)
	if until, ok := ctx.Deadline(); ok && until.Before(deadline) {
		deadline = until
	}
	if err := c.SetDeadline(deadline); err != nil {
		return err
	}
	defer c.SetDeadline(time.Time{})
	payload := []byte("proof")
	written, err := c.Write(payload)
	if err != nil {
		return err
	}
	if written != len(payload) {
		return io.ErrShortWrite
	}
	expected := append([]byte(prefix), payload...)
	buffer := make([]byte, len(expected))
	n, err := io.ReadFull(c, buffer)
	// Preserve partial bytes: corrupt/truncated payload is never converted into
	// remote-close evidence solely because an EOF accompanied that payload.
	if !bytes.Equal(buffer[:n], expected[:n]) {
		return errSiteEchoPayload
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return io.EOF
	}
	return err
}

// Observe bytes returned by the existing reader without changing its data/errors.
type siteLifecycleReadObservation struct {
	net.Conn
	expected      []byte
	readBytes     int
	prefixMatches bool
}

func (c *siteLifecycleReadObservation) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	for i := 0; i < n; i++ {
		if c.readBytes+i >= len(c.expected) || b[i] != c.expected[c.readBytes+i] {
			c.prefixMatches = false
		}
	}
	c.readBytes += n
	return n, err
}

type siteLifecycleIOObservation struct {
	FlowIndex      int       `json:"flowIndex"`
	Network        string    `json:"network"`
	OldUDP         bool      `json:"oldUDP"`
	Classification string    `json:"classification"`
	ErrorKind      string    `json:"errorKind"`
	ReadBytes      int       `json:"readBytes"`
	ReadMatches    bool      `json:"readMatches"`
	StartedAt      time.Time `json:"startedAt"`
	ObservedAt     time.Time `json:"observedAt"`
}

func siteLifecycleIOErrorKind(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, errSiteEchoPayload) {
		return "bad-prefix"
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "EOF"
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return "reset"
	}
	var network net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &network) && network.Timeout()) {
		return "timeout"
	}
	return "other"
}
func siteLifecycleObserveIO(index int, network, classification string, started time.Time, conn *siteLifecycleReadObservation, err error) siteLifecycleIOObservation {
	return siteLifecycleIOObservation{FlowIndex: index, Network: network, OldUDP: network == "udp", Classification: classification, ErrorKind: siteLifecycleIOErrorKind(err), ReadBytes: conn.readBytes, ReadMatches: conn.prefixMatches && conn.readBytes == len(conn.expected), StartedAt: started.UTC(), ObservedAt: time.Now().UTC()}
}
func siteLifecycleRound(ctx context.Context, flows []siteLifecycleFlow, udp net.Conn, udpAlive *bool, prefix string, observers ...func(siteLifecycleIOObservation)) error {
	round, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	var work sync.WaitGroup
	ambiguous := make(chan struct{}, len(flows)+1)
	observations := make(chan siteLifecycleIOObservation, len(flows)+1)
	for i := range flows {
		flow := &flows[i]
		index := i
		if flow.ambiguous {
			ambiguous <- struct{}{}
			continue
		}
		if flow.closed {
			continue
		}
		work.Add(1)
		go func() {
			defer work.Done()
			started := time.Now()
			observed := &siteLifecycleReadObservation{Conn: flow.conn, expected: []byte(prefix + "proof"), prefixMatches: true}
			err := siteLifecycleTCPEcho(round, observed, prefix)
			classification := "alive"
			if err == nil {
				flow.echoes++
			} else if ctx.Err() == nil && round.Err() == nil && siteLifecycleRemoteTCPClosed(err) {
				classification = "confirmedClosed"
				flow.closed = true
				flow.conn.Close()
			} else {
				classification = "ambiguous"
				flow.ambiguous = true
				ambiguous <- struct{}{}
			}
			if err != nil {
				observations <- siteLifecycleObserveIO(index, "tcp", classification, started, observed, err)
			}
		}()
	}
	if *udpAlive {
		work.Add(1)
		go func() {
			defer work.Done()
			started := time.Now()
			observed := &siteLifecycleReadObservation{Conn: udp, expected: []byte(prefix + "proof"), prefixMatches: true}
			err := siteEcho(round, observed, prefix, true)
			if err != nil {
				observations <- siteLifecycleObserveIO(0, "udp", "ambiguous", started, observed, err)
				*udpAlive = false
				if errors.Is(err, errSiteEchoPayload) || ctx.Err() != nil {
					ambiguous <- struct{}{}
				}
			}
			// Keep the original UDP socket/control for the later stopped-window probe.
			// A silent datagram does not establish a remote UDP socket close.
		}()
	}
	work.Wait()
	close(observations)
	for observation := range observations {
		for _, observe := range observers {
			observe(observation)
		}
	}
	if len(ambiguous) > 0 {
		return errors.New("ambiguous lifecycle TCP or invalid UDP observation")
	}
	return nil
}
func siteLifecycleAmbiguousCount(flows []siteLifecycleFlow) int {
	count := 0
	for _, flow := range flows {
		if flow.ambiguous {
			count++
		}
	}
	return count
}
func siteLifecycleSnapshot(e *CoordinatedExecutor) (MihomoConfiguration, siteProjectionIdentity, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.proxyDesired == nil {
		return MihomoConfiguration{}, siteProjectionIdentity{}, false
	}
	c := cloneMihomoConfiguration(*e.proxyDesired)
	identity := siteProjectionIdentity{ProfileID: c.ProfileID}
	if p := c.Projection; p != nil {
		identity.BundleID = p.BundleID
		identity.Hash = p.ProjectionHash
		identity.Boot = p.ProcessEpoch
		identity.Revision = p.Revision
		identity.ActiveRevision = p.ActiveRevision
		identity.SourceRevision = p.SourceRevision
		identity.OrgRevision = p.OrgRevision
		identity.Credential = projectionCredentialKey(p)
	}
	return c, identity, true
}
func siteLifecycleSameIdentity(before, after siteProjectionIdentity, restart bool) bool {
	before.Credential = ""
	after.Credential = ""
	if restart {
		before.Boot = ""
		after.Boot = ""
	}
	return before == after
}
func siteLifecycleInvariant(t *testing.T, in siteHarnessInput, e *CoordinatedExecutor, c *MihomoController, transport *realAppCountTransport, identity siteProjectionIdentity, before MihomoProcessStatus, puts int64, allowStopped bool) bool {
	t.Helper()
	current, actual, present := siteLifecycleSnapshot(e)
	if !present {
		if allowStopped {
			return false
		}
		t.Fatal("lifecycle actual profile disappeared")
	}
	ids := configurationNodeIDs(current)
	if current.DeliveryMode != "mapped_nodes" || current.Projection == nil || len(ids) != 1 || ids[0] != in.Nodes[0].ID || !siteLifecycleSameIdentity(identity, actual, in.LifecycleScenario == "restart") {
		t.Fatal("lifecycle immutable profile/bundle/source/org or B-only scope changed")
	}
	status := c.ProcessStatus()
	if in.LifecycleScenario != "restart" && (status.PID != before.PID || status.ProcessEpoch != before.ProcessEpoch || transport.puts.Load() != puts) {
		t.Fatal("lifecycle unexpectedly restarted or reconfigured owned kernel")
	}
	return status.Ownership == "soha_owned" && status.State == "running" && status.PID > 0
}
func siteLifecycleDialTCP(ctx context.Context, native, target string) (net.Conn, error) {
	dialer, err := proxy.SOCKS5("tcp", native, nil, &net.Dialer{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	return dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", target)
}
func siteLifecycleDialUDP(ctx context.Context, native, target string) (net.Conn, error) {
	address, err := netip.ParseAddrPort(target)
	if err != nil || !address.Addr().Is4() {
		return nil, errors.New("invalid lifecycle UDP target")
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	control, err := (&net.Dialer{}).DialContext(bounded, "tcp", native)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			control.Close()
		}
	}()
	deadline, _ := bounded.Deadline()
	control.SetDeadline(deadline)
	if _, err = control.Write([]byte{5, 1, 0}); err != nil {
		return nil, err
	}
	var method [2]byte
	if _, err = io.ReadFull(control, method[:]); err != nil || method != [2]byte{5, 0} {
		return nil, errors.New("lifecycle UDP method refused")
	}
	if _, err = control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return nil, err
	}
	var reply [10]byte
	if _, err = io.ReadFull(control, reply[:]); err != nil || !bytes.Equal(reply[:4], []byte{5, 0, 0, 1}) {
		return nil, errors.New("lifecycle UDP association refused")
	}
	ip := net.IP(reply[4:8])
	if ip.IsUnspecified() {
		ip = net.ParseIP("127.0.0.1")
	}
	if !ip.IsLoopback() {
		return nil, errors.New("lifecycle UDP relay outside owned loopback")
	}
	socket, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: ip, Port: int(reply[8])<<8 | int(reply[9])})
	if err != nil {
		return nil, err
	}
	control.SetDeadline(time.Time{})
	v4 := address.Addr().As4()
	success = true
	return &realAppNativePacket{UDPConn: socket, control: control, header: []byte{0, 0, 0, 1, v4[0], v4[1], v4[2], v4[3], byte(address.Port() >> 8), byte(address.Port())}}, nil
}
func siteLifecycleFresh(ctx context.Context, native string, in siteHarnessInput) bool {
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tcp, err := siteLifecycleDialTCP(bounded, native, in.TCPDestination)
	if err != nil {
		return false
	}
	defer tcp.Close()
	udp, err := siteLifecycleDialUDP(bounded, native, in.UDPDestination)
	if err != nil {
		return false
	}
	defer udp.Close()
	return siteEcho(bounded, tcp, in.Nodes[0].EchoPrefix, false) == nil && siteEcho(bounded, udp, in.Nodes[0].EchoPrefix, true) == nil
}
func siteLifecycleStoppedProbe(ctx context.Context, native, target string) bool {
	bounded, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	conn, err := siteLifecycleDialTCP(bounded, native, target)
	if err != nil {
		return ctx.Err() == nil
	}
	defer conn.Close()
	deadline, _ := bounded.Deadline()
	conn.SetDeadline(deadline)
	if _, err = conn.Write([]byte("proof")); err != nil {
		return ctx.Err() == nil
	}
	n, readErr := conn.Read(make([]byte, 64))
	return ctx.Err() == nil && n == 0 && readErr != nil
}
func siteLifecycleUDPSilence(ctx context.Context, c net.Conn) bool {
	if ctx.Err() != nil {
		return false
	}
	bounded, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer cancel()
	deadline, _ := bounded.Deadline()
	if c.SetDeadline(deadline) != nil {
		return false
	}
	defer c.SetDeadline(time.Time{})
	_, writeErr := c.Write([]byte("proof"))
	if errors.Is(writeErr, net.ErrClosed) {
		return false
	}
	var n int
	var readErr error
	if packet, ok := c.(*realAppNativePacket); ok {
		n, readErr = packet.UDPConn.Read(make([]byte, 65536))
	} else {
		n, readErr = c.Read(make([]byte, 65536))
	}
	return ctx.Err() == nil && n == 0 && readErr != nil && !errors.Is(readErr, net.ErrClosed)
}
func siteLifecycleStoppedUDPProbe(ctx context.Context, native, target string) bool {
	bounded, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	conn, err := siteLifecycleDialUDP(bounded, native, target)
	if err != nil {
		return ctx.Err() == nil
	}
	defer conn.Close()
	return siteLifecycleUDPSilence(bounded, conn)
}

func siteLifecycle(t *testing.T, ctx context.Context, in siteHarnessInput, manager *Manager, e *CoordinatedExecutor, c *MihomoController, transport *realAppCountTransport, configuration MihomoConfiguration, identity siteProjectionIdentity, before MihomoProcessStatus, puts int64) {
	t.Helper()
	ids := configurationNodeIDs(configuration)
	if configuration.Projection == nil || len(ids) != 1 || ids[0] != in.Nodes[0].ID {
		t.Fatal("lifecycle requires actual B-only mapped profile")
	}
	if err := os.MkdirAll(in.MarkerDirectory, 0700); err != nil {
		t.Fatal("lifecycle marker directory unavailable")
	}
	if err := secureStateDirectory(in.MarkerDirectory); err != nil {
		t.Fatal("lifecycle marker directory is not private")
	}
	for _, name := range []string{"hold-ready.json", "hold-progress.json", "action-done.json", "stopped.json", "stopped-observed.json", "resume-ready.json"} {
		if _, err := os.Lstat(filepath.Join(in.MarkerDirectory, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("lifecycle requires fresh marker filenames")
		}
	}
	if _, err := e.Proxy(ctx, &ProxyAction{Kind: "select", GroupID: configuration.SelectorGroup, NodeID: in.Nodes[0].ID}, nil); err != nil {
		t.Fatal("lifecycle retained B selection failed")
	}
	native := net.JoinHostPort("127.0.0.1", fmt.Sprint(configuration.MixedPort))
	flows := make([]siteLifecycleFlow, 16)
	for i := range flows {
		conn, err := siteLifecycleDialTCP(ctx, native, in.TCPDestination)
		if err != nil {
			t.Fatal("lifecycle original TCP establishment failed")
		}
		flows[i].conn = conn
		defer conn.Close()
	}
	udp, err := siteLifecycleDialUDP(ctx, native, in.UDPDestination)
	if err != nil {
		t.Fatal("lifecycle original UDP establishment failed")
	}
	defer udp.Close()
	udpAlive := true
	round := func(roundContext context.Context) error {
		return siteLifecycleRound(roundContext, flows, udp, &udpAlive, in.Nodes[0].EchoPrefix, func(observation siteLifecycleIOObservation) {
			encoded, _ := json.Marshal(observation)
			t.Logf("SITE LIFECYCLE IO %s", encoded)
		})
	}
	rounds := 0
	for i := 0; i < 3; i++ {
		if err := round(ctx); err != nil {
			t.Fatal("lifecycle initial I/O observation ambiguous")
		}
		rounds++
		alive, closed, _ := siteLifecycleCounts(flows)
		if alive != 16 || closed != 0 || !udpAlive {
			t.Fatal("lifecycle three initial positive rounds failed")
		}
	}
	run := randomID()
	ready := struct {
		RunID        string `json:"runId"`
		Scenario     string `json:"scenario"`
		TCPCount     int    `json:"tcpCount"`
		ProfileID    string `json:"profileId"`
		BundleID     string `json:"bundleId"`
		Hash         string `json:"projectionHash"`
		ProcessEpoch string `json:"processEpoch"`
		PID          int    `json:"pid"`
	}{run, in.LifecycleScenario, 16, in.ProfileID, identity.BundleID, identity.Hash, before.ProcessEpoch, before.PID}
	if siteWriteLifecycleMarker(in.MarkerDirectory, "hold-ready.json", ready) != nil {
		t.Fatal("lifecycle hold-ready marker unavailable")
	}
	t.Logf("SITE HOLD READY scenario=%s originalTCP=16 originalUDP=1 positiveRounds=3; Root must independently witness both members", in.LifecycleScenario)
	hold, cancel := context.WithTimeout(ctx, time.Duration(in.MarkerWaitSeconds)*time.Second)
	defer cancel()
	nextCycle := time.Now().Add(5 * time.Second)
	steadyStarted := time.Now()
	var lastAxis *siteLifecycleTimeAxis
	axis := func(event string) {
		value := siteCaptureLifecycleTimeAxis(manager, e, c, transport, steadyStarted, event)
		lastAxis = &value
		encoded, _ := json.Marshal(value)
		t.Logf("SITE STEADY AXIS %s", encoded)
	}
	if in.LifecycleScenario == "steady" {
		axis("initial")
	}
	cycles, cycleErrors := 0, 0
	stoppedObserved := false
	var stoppedAt time.Time
	var action siteLifecycleMarker
	progress := func() {
		alive, closed, echoes := siteLifecycleCounts(flows)
		value := struct {
			RunID        string                 `json:"runId"`
			Scenario     string                 `json:"scenario"`
			TCPAlive     int                    `json:"tcpAlive"`
			TCPClosed    int                    `json:"tcpClosed"`
			TCPAmbiguous int                    `json:"tcpAmbiguous"`
			UDPOldAlive  bool                   `json:"udpOldAlive"`
			EchoRounds   int                    `json:"echoRounds"`
			TCPEchoes    int                    `json:"tcpEchoes"`
			CycleCount   int                    `json:"cycleCount"`
			CycleErrors  int                    `json:"cycleErrors"`
			TimeAxis     *siteLifecycleTimeAxis `json:"timeAxis,omitempty"`
		}{run, in.LifecycleScenario, alive, closed, siteLifecycleAmbiguousCount(flows), udpAlive, rounds, echoes, cycles, cycleErrors, lastAxis}
		if siteWriteLifecycleMarker(in.MarkerDirectory, "hold-progress.json", value) != nil {
			t.Fatal("lifecycle progress marker unavailable")
		}
	}
	for {
		if hold.Err() != nil {
			t.Fatal("lifecycle action marker deadline exceeded")
		}
		if err := round(hold); err != nil {
			if in.LifecycleScenario == "steady" {
				axis("failure")
			}
			progress()
			t.Fatal("lifecycle I/O ambiguous; no remote-close proof")
		}
		rounds++
		if in.LifecycleScenario == "steady" {
			alive, closed, _ := siteLifecycleCounts(flows)
			if alive != 16 || closed != 0 || siteLifecycleAmbiguousCount(flows) != 0 || !udpAlive {
				axis("failure")
				progress()
				t.Fatal("steady original TCP/UDP continuity failed without action")
			}
		}
		if !time.Now().Before(nextCycle) {
			err := manager.Cycle(hold)
			cycles++
			nextCycle = time.Now().Add(5 * time.Second)
			if in.LifecycleScenario == "steady" {
				axis("cycle")
			}
			if err != nil {
				cycleErrors++
				if in.LifecycleScenario != "restart" {
					t.Fatal("unexpected actual control error during lifecycle action")
				}
			} else {
				siteLifecycleInvariant(t, in, e, c, transport, identity, before, puts, in.LifecycleScenario == "restart")
			}
		}
		progress()
		alive, closed, _ := siteLifecycleCounts(flows)
		if in.LifecycleScenario == "steady" {
			if siteLifecycleSteadyProof(time.Since(steadyStarted), alive, closed, siteLifecycleAmbiguousCount(flows), udpAlive) {
				siteLifecycleInvariant(t, in, e, c, transport, identity, before, puts, false)
				for n := 0; n < 3; n++ {
					if !siteLifecycleFresh(hold, native, in) {
						t.Fatal("steady fresh TCP/UDP positive control failed")
					}
					if round(hold) != nil {
						axis("failure")
						progress()
						t.Fatal("steady original stream observation became ambiguous")
					}
					rounds++
					alive, closed, _ = siteLifecycleCounts(flows)
					if !siteLifecycleSteadyProof(time.Since(steadyStarted), alive, closed, siteLifecycleAmbiguousCount(flows), udpAlive) {
						axis("failure")
						progress()
						t.Fatal("steady original streams failed during fresh controls")
					}
				}
				siteLifecycleInvariant(t, in, e, c, transport, identity, before, puts, false)
				axis("complete")
				progress()
				t.Logf("SITE PASS stage=lifecycle scenario=steady elapsedMilliseconds=%d originalAlive=16 confirmedClosed=0 ambiguous=0 originalUDPPositive=true freshTCPUDPRounds=3 cycles=%d cycleErrors=%d immutableKernel=true", time.Since(steadyStarted).Milliseconds(), cycles, cycleErrors)
				return
			}
			select {
			case <-hold.Done():
				t.Fatal("steady 40s proof deadline exceeded")
			case <-time.After(250 * time.Millisecond):
			}
			continue
		}
		if in.LifecycleScenario != "restart" {
			marker, present, err := siteReadLifecycleMarker(filepath.Join(in.MarkerDirectory, "action-done.json"), run, true)
			if err != nil {
				t.Fatal("lifecycle action marker invalid")
			}
			if present {
				action = marker
				if !siteLifecyclePartialProof(alive, closed, 16) {
					if alive == 0 {
						t.Fatal("lifecycle lost every original TCP; fresh connections cannot disguise outage")
					}
				} else {
					siteLifecycleInvariant(t, in, e, c, transport, identity, before, puts, false)
					if !siteLifecycleFresh(hold, native, in) {
						t.Fatal("fresh B TCP/UDP failed after lifecycle action")
					}
					for n := 0; n < 3; n++ {
						if err := round(hold); err != nil {
							progress()
							t.Fatal("lifecycle survivor observation ambiguous")
						}
						rounds++
						select {
						case <-hold.Done():
							t.Fatal("lifecycle survivor deadline exceeded")
						case <-time.After(250 * time.Millisecond):
						}
					}
					alive, closed, _ = siteLifecycleCounts(flows)
					if !siteLifecyclePartialProof(alive, closed, 16) {
						t.Fatal("original survivor did not continue after action")
					}
					siteLifecycleInvariant(t, in, e, c, transport, identity, before, puts, false)
					progress()
					t.Logf("SITE PASS stage=lifecycle scenario=%s operation=%s originalAlive=%d originalClosed=%d freshTCPUDP=true immutableProfileKernel=true cycles=%d", in.LifecycleScenario, action.OperationID, alive, closed, cycles)
					return
				}
			}
		} else {
			_, stopped, err := siteReadLifecycleMarker(filepath.Join(in.MarkerDirectory, "stopped.json"), run, false)
			if err != nil {
				t.Fatal("lifecycle stopped marker invalid")
			}
			if stopped && !stoppedObserved {
				if stoppedAt.IsZero() {
					stoppedAt = time.Now()
				}
				if closed == 16 {
					if !siteLifecycleStoppedProbe(hold, native, in.TCPDestination) {
						t.Fatal("new B TCP returned payload while actual pool stopped")
					}
					if !siteLifecycleUDPSilence(hold, udp) {
						t.Fatal("old UDP returned payload or probe was locally invalid while stopped")
					}
					if !siteLifecycleStoppedUDPProbe(hold, native, in.UDPDestination) {
						t.Fatal("new UDP returned payload while stopped")
					}
					udpAlive = false
					observed := struct {
						RunID           string `json:"runId"`
						AllClosed       bool   `json:"allclosed"`
						OldUDPNoPayload bool   `json:"oldUDPNoPayload"`
						NewUDPNoPayload bool   `json:"newUDPNoPayload"`
					}{run, true, true, true}
					if siteWriteLifecycleMarker(in.MarkerDirectory, "stopped-observed.json", observed) != nil {
						t.Fatal("lifecycle stopped observation unavailable")
					}
					stoppedObserved = true
					t.Log("SITE STOP OBSERVED originalTCPConfirmedClosed=16 newTCPNoPayload=true oldUDPNoPayload=true newUDPNoPayload=true UDPProof=bounded-silence-or-refusal")
				} else if time.Since(stoppedAt) > 10*time.Second {
					t.Fatal("original TCP survived actual replicas zero")
				}
			}
			marker, resume, err := siteReadLifecycleMarker(filepath.Join(in.MarkerDirectory, "resume-ready.json"), run, true)
			if err != nil {
				t.Fatal("lifecycle resume marker invalid")
			}
			if resume {
				if !stoppedObserved {
					t.Fatal("lifecycle resume preceded stopped observation")
				}
				action = marker
				for {
					if hold.Err() != nil {
						t.Fatal("lifecycle actual resume deadline exceeded")
					}
					if delay := time.Until(nextCycle); delay > 0 {
						select {
						case <-hold.Done():
							t.Fatal("lifecycle actual resume deadline exceeded")
						case <-time.After(delay):
						}
					}
					nextCycle = time.Now().Add(5 * time.Second)
					if err := manager.Cycle(hold); err == nil {
						cycles++
						if siteLifecycleInvariant(t, in, e, c, transport, identity, before, puts, true) {
							if !siteLifecycleFresh(hold, native, in) {
								t.Fatal("fresh TCP/UDP failed after actual resume-ready; data errors are not retried")
							}
							status := c.ProcessStatus()
							progress()
							t.Logf("SITE PASS stage=lifecycle scenario=restart operation=%s originalConfirmedClosed=16 oldUDPNoPayload=true newUDPNoPayload=true freshTCPUDP=true immutableBundleSourceOrg=true ownedPID=%d processEpoch=%s cycles=%d cycleErrors=%d", action.OperationID, status.PID, status.ProcessEpoch, cycles, cycleErrors)
							return
						}
					} else {
						cycles++
						cycleErrors++
					}
					progress()
				}
			}
		}
		select {
		case <-hold.Done():
			t.Fatal("lifecycle action marker deadline exceeded")
		case <-time.After(250 * time.Millisecond):
		}
	}
}

type siteLifecycleTestConn struct {
	bad      bool
	closed   bool
	closes   int
	reader   bytes.Reader
	writeErr error
	readErr  error
	response []byte
}

func (c *siteLifecycleTestConn) Read(b []byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.reader.Read(b)
}
func (c *siteLifecycleTestConn) Write(b []byte) (int, error) {
	if c.bad {
		return 0, syscall.ECONNRESET
	}
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.closed {
		return 0, net.ErrClosed
	}
	response := b
	if c.response != nil {
		response = c.response
	}
	c.reader.Reset(append([]byte(nil), response...))
	return len(b), nil
}
func (c *siteLifecycleTestConn) Close() error         { c.closed = true; c.closes++; return nil }
func (c *siteLifecycleTestConn) LocalAddr() net.Addr  { return nil }
func (c *siteLifecycleTestConn) RemoteAddr() net.Addr { return nil }
func (c *siteLifecycleTestConn) SetDeadline(time.Time) error {
	if c.closed {
		return net.ErrClosed
	}
	return nil
}
func (c *siteLifecycleTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *siteLifecycleTestConn) SetWriteDeadline(time.Time) error { return nil }
func TestSiteLifecycleHelpers(t *testing.T) {
	t.Run("ambiguous-TCP-never-closed-locally", func(t *testing.T) {
		for name, conn := range map[string]*siteLifecycleTestConn{"timeout": {readErr: context.DeadlineExceeded}, "local-close": {writeErr: net.ErrClosed}, "broken-pipe": {writeErr: syscall.EPIPE}, "wrong-payload": {response: []byte("WRONG")}, "wrong-prefix-then-EOF": {response: []byte("xx")}} {
			t.Run(name, func(t *testing.T) {
				flows := []siteLifecycleFlow{{conn: conn}}
				udpAlive := false
				if siteLifecycleRound(context.Background(), flows, nil, &udpAlive, "") == nil {
					t.Fatal("ambiguous TCP observation accepted")
				}
				alive, closed, _ := siteLifecycleCounts(flows)
				if closed != 0 || alive != 0 || !flows[0].ambiguous || conn.closes != 0 {
					t.Fatal("ambiguous TCP manufactured remote-close evidence")
				}
				if siteLifecycleRound(context.Background(), flows, nil, &udpAlive, "") == nil || conn.closes != 0 {
					t.Fatal("ambiguous TCP silently recovered or retried")
				}

			})
		}
	})
	t.Run("cancelled-context-not-peer-close", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		conn := &siteLifecycleTestConn{bad: true}
		flows := []siteLifecycleFlow{{conn: conn}}
		udpAlive := false
		if siteLifecycleRound(ctx, flows, nil, &udpAlive, "") == nil || flows[0].closed || conn.closes != 0 {
			t.Fatal("cancelled context counted as peer close")
		}
	})
	t.Run("EOF-with-verified-partial-prefix", func(t *testing.T) {
		conn := &siteLifecycleTestConn{response: []byte("pr")}
		flows := []siteLifecycleFlow{{conn: conn}}
		udpAlive := false
		if siteLifecycleRound(context.Background(), flows, nil, &udpAlive, "") != nil || !flows[0].closed || conn.closes != 1 {
			t.Fatal("verified remote EOF rejected")
		}
	})
	t.Run("UDP-silence-is-not-remote-close", func(t *testing.T) {
		udp := &siteLifecycleTestConn{readErr: context.DeadlineExceeded}
		alive := true
		if siteLifecycleRound(context.Background(), nil, udp, &alive, "") != nil || alive || udp.closes != 0 {
			t.Fatal("UDP silence closed original local socket")
		}
		if !siteLifecycleUDPSilence(context.Background(), udp) {
			t.Fatal("bounded original UDP silence rejected")
		}
		payload := &siteLifecycleTestConn{}
		if siteLifecycleUDPSilence(context.Background(), payload) {
			t.Fatal("stopped UDP payload accepted")
		}
		closed := &siteLifecycleTestConn{}
		closed.Close()
		if siteLifecycleUDPSilence(context.Background(), closed) {
			t.Fatal("locally closed UDP claimed stopped evidence")
		}
	})

	t.Run("bounded-input-and-partial-proof", func(t *testing.T) {
		in := siteHarnessInput{LifecycleScenario: "shrink", DeliveryMode: "mapped_nodes", ProfileID: "profile-1", Nodes: []siteHarnessNode{{ID: "node-b"}}, MarkerDirectory: t.TempDir(), TimeoutSeconds: 240, MarkerWaitSeconds: 180, TCPDestination: "198.18.0.101:12001", UDPDestination: "198.18.0.101:12002"}
		if siteValidateLifecycle(in) != nil {
			t.Fatal("valid lifecycle input rejected")
		}
		in.MarkerWaitSeconds = 181
		if siteValidateLifecycle(in) == nil {
			t.Fatal("unbounded lifecycle accepted")
		}
		if siteLifecyclePartialProof(16, 0, 16) || siteLifecyclePartialProof(0, 16, 16) || !siteLifecyclePartialProof(15, 1, 16) {
			t.Fatal("partial action proof accepted zero closure or zero survivor")
		}
	})
	t.Run("private-atomic-marker-and-identity", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "action-done.json")
		value := siteLifecycleMarker{RunID: "run-1", OperationID: "operation-1"}
		if siteWriteLifecycleMarker(dir, "action-done.json", value) != nil {
			t.Fatal("marker write failed")
		}
		if _, present, err := siteReadLifecycleMarker(path, "run-1", true); err != nil || !present {
			t.Fatal("valid marker rejected")
		}
		if _, _, err := siteReadLifecycleMarker(path, "run-2", true); err == nil {
			t.Fatal("stale run marker accepted")
		}
		if siteWriteLifecycleMarker(dir, "action-done.json", siteLifecycleMarker{RunID: "run-1"}) != nil {
			t.Fatal("marker overwrite failed")
		}
		if _, _, err := siteReadLifecycleMarker(path, "run-1", true); err == nil {
			t.Fatal("zero-operation action marker accepted")
		}
	})
	t.Run("closed-once-no-reopen", func(t *testing.T) {
		good, bad := &siteLifecycleTestConn{}, &siteLifecycleTestConn{bad: true}
		flows := []siteLifecycleFlow{{conn: good}, {conn: bad}}
		udpAlive := false
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if siteLifecycleRound(ctx, flows, nil, &udpAlive, "") != nil || siteLifecycleRound(ctx, flows, nil, &udpAlive, "") != nil {
			t.Fatal("explicit remote reset was not classified")
		}
		alive, closed, echoes := siteLifecycleCounts(flows)
		if alive != 1 || closed != 1 || echoes != 2 || bad.closes != 1 {
			t.Fatal("closed original stream reopened or counted more than once")
		}
	})
	t.Run("immutable-identity", func(t *testing.T) {
		before := siteProjectionIdentity{ProfileID: "profile-1", BundleID: "bundle-1", Hash: "hash-1", SourceRevision: 1, OrgRevision: 1, Boot: "boot-1", Credential: "credential-1"}
		after := before
		after.Credential = "renewed"
		if !siteLifecycleSameIdentity(before, after, false) {
			t.Fatal("valid scoped renewal rejected")
		}
		after.Hash = "other"
		if siteLifecycleSameIdentity(before, after, true) {
			t.Fatal("restart accepted changed immutable bundle")
		}
	})
}

func TestSiteSafeErrorRuntimeHTTPCode(t *testing.T) {
	for _, test := range []struct{ name, code, want string }{{"stale", "stale_configuration", "stale_configuration"}, {"conflict", "configuration_ack_conflict", "configuration_ack_conflict"}, {"untrusted", "private-response-marker", "unknown"}, {"injected", "configuration_ack_conflict\nprivate-response-marker", "unknown"}, {"missing", "", "unknown"}} {
		t.Run(test.name, func(t *testing.T) {
			httpErr := &RuntimeHTTPError{StatusCode: http.StatusConflict, Code: test.code}
			wrapped := errors.Join(fmt.Errorf("report endpoint configuration: %w", httpErr), errors.New("private-body-marker"))
			diagnostic := siteSafeError(wrapped)
			if !strings.Contains(diagnostic, "runtime_http_status=409_code="+test.want) || strings.Contains(diagnostic, "private-response-marker") || strings.Contains(diagnostic, "private-body-marker") {
				t.Fatal("safe HTTP diagnostic missing or exposed untrusted content")
			}
			if httpErr.Code != test.code || httpErr.StatusCode != http.StatusConflict {
				t.Fatal("diagnostic mutated client error")
			}
		})
	}
}

// Steady diagnostics expose only whitelisted dates, opaque hashes and counts.
type siteLifecycleTimeAxis struct {
	Event                   string    `json:"event"`
	ObservedAt              time.Time `json:"observedAt"`
	ElapsedMilliseconds     int64     `json:"elapsedMilliseconds"`
	ConfigurationVersion    int       `json:"configurationVersion"`
	PID                     int       `json:"pid"`
	ProcessEpoch            string    `json:"processEpoch"`
	ConfigPUTs              int64     `json:"configPUTs"`
	ProjectionExpiresAt     time.Time `json:"projectionExpiresAt"`
	CredentialExpiresAt     time.Time `json:"credentialExpiresAt"`
	ConfigurationValidUntil time.Time `json:"configurationValidUntil"`
	CredentialKeyHash       string    `json:"credentialKeyHash"`
}

func siteBuildLifecycleTimeAxis(now, started time.Time, event string, status Status, process MihomoProcessStatus, puts int64, configuration MihomoConfiguration) siteLifecycleTimeAxis {
	value := siteLifecycleTimeAxis{Event: event, ObservedAt: now.UTC(), ElapsedMilliseconds: now.Sub(started).Milliseconds(), ConfigurationVersion: status.ConfigurationVersion, PID: process.PID, ProcessEpoch: process.ProcessEpoch, ConfigPUTs: puts, ConfigurationValidUntil: configuration.EnforcementUntil}
	if configuration.Projection != nil {
		value.ProjectionExpiresAt = configuration.Projection.ExpiresAt
		value.CredentialExpiresAt = configuration.Projection.Credential.ExpiresAt
		digest := sha256.Sum256([]byte(projectionCredentialKey(configuration.Projection)))
		value.CredentialKeyHash = fmt.Sprintf("%x", digest)
	}
	return value
}
func siteCaptureLifecycleTimeAxis(manager *Manager, e *CoordinatedExecutor, c *MihomoController, transport *realAppCountTransport, started time.Time, event string) siteLifecycleTimeAxis {
	configuration, _, _ := siteLifecycleSnapshot(e)
	return siteBuildLifecycleTimeAxis(time.Now(), started, event, manager.Status(), c.ProcessStatus(), transport.puts.Load(), configuration)
}
func siteLifecycleSteadyProof(elapsed time.Duration, alive, closed, ambiguous int, udpPositive bool) bool {
	return elapsed >= 40*time.Second && alive == 16 && closed == 0 && ambiguous == 0 && udpPositive
}
func TestSiteSteadyHelpers(t *testing.T) {
	t.Run("40s-original-continuity", func(t *testing.T) {
		if siteLifecycleSteadyProof(40*time.Second-time.Nanosecond, 16, 0, 0, true) || siteLifecycleSteadyProof(40*time.Second, 15, 1, 0, true) || siteLifecycleSteadyProof(40*time.Second, 16, 0, 1, true) || siteLifecycleSteadyProof(40*time.Second, 16, 0, 0, false) || !siteLifecycleSteadyProof(40*time.Second, 16, 0, 0, true) {
			t.Fatal("steady accepted short duration, closure, ambiguity or silent UDP")
		}
	})
	t.Run("steady-input-same-bounds", func(t *testing.T) {
		in := siteHarnessInput{LifecycleScenario: "steady", DeliveryMode: "mapped_nodes", ProfileID: "profile-1", Nodes: []siteHarnessNode{{ID: "node-b"}}, MarkerDirectory: t.TempDir(), TimeoutSeconds: 240, MarkerWaitSeconds: 180, TCPDestination: "198.18.0.101:12001", UDPDestination: "198.18.0.101:12002"}
		if siteValidateLifecycle(in) != nil {
			t.Fatal("steady rejected existing lifecycle bounds")
		}
		in.MarkerWaitSeconds = 181
		if siteValidateLifecycle(in) == nil {
			t.Fatal("steady exceeded existing lifecycle bounds")
		}
	})
	t.Run("whitelisted-axis-no-credential", func(t *testing.T) {
		now := time.Now().UTC()
		configuration, projection := bundleFixture(now)
		configuration.Projection = &projection
		axis := siteBuildLifecycleTimeAxis(now, now.Add(-5*time.Second), "cycle", Status{ConfigurationVersion: 7}, MihomoProcessStatus{PID: 17, ProcessEpoch: "owned-epoch"}, 2, configuration)
		raw, err := json.Marshal(axis)
		if err != nil || bytes.Contains(raw, []byte(projection.Credential.Secret)) || bytes.Contains(raw, []byte(projection.Credential.CredentialID)) || len(axis.CredentialKeyHash) != 64 || axis.ElapsedMilliseconds != 5000 || axis.ConfigurationVersion != 7 || axis.PID != 17 || axis.ConfigPUTs != 2 || !axis.CredentialExpiresAt.Equal(projection.Credential.ExpiresAt) || !axis.ConfigurationValidUntil.Equal(configuration.EnforcementUntil) {
			t.Fatal("steady axis missing safe fields or exposed credential material")
		}
	})
}

func TestSiteLifecycleIODiagnostics(t *testing.T) {
	for _, test := range []struct {
		name, network, kind, classification string
		conn                                *siteLifecycleTestConn
		wantBytes                           int
	}{
		{"tcp-reset", "tcp", "reset", "confirmedClosed", &siteLifecycleTestConn{bad: true}, 0},
		{"tcp-partial-EOF", "tcp", "EOF", "confirmedClosed", &siteLifecycleTestConn{response: []byte("pr")}, 2},
		{"tcp-timeout", "tcp", "timeout", "ambiguous", &siteLifecycleTestConn{readErr: context.DeadlineExceeded}, 0},
		{"tcp-payload", "tcp", "bad-prefix", "ambiguous", &siteLifecycleTestConn{response: []byte("WRONG")}, 5},
		{"udp-timeout", "udp", "timeout", "ambiguous", &siteLifecycleTestConn{readErr: context.DeadlineExceeded}, 0},
		{"udp-payload", "udp", "bad-prefix", "ambiguous", &siteLifecycleTestConn{response: []byte("WRONG")}, 5},
		{"udp-other", "udp", "other", "ambiguous", &siteLifecycleTestConn{readErr: errors.New("private-error-marker")}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			var flows []siteLifecycleFlow
			var udp net.Conn
			udpAlive := test.network == "udp"
			if udpAlive {
				udp = test.conn
			} else {
				flows = []siteLifecycleFlow{{conn: test.conn}}
			}
			var observations []siteLifecycleIOObservation
			_ = siteLifecycleRound(context.Background(), flows, udp, &udpAlive, "", func(observation siteLifecycleIOObservation) { observations = append(observations, observation) })
			if len(observations) != 1 {
				t.Fatal("failure diagnostic missing or repeated")
			}
			observation := observations[0]
			if observation.FlowIndex != 0 || observation.Network != test.network || observation.OldUDP != (test.network == "udp") || observation.ErrorKind != test.kind || observation.Classification != test.classification || observation.ReadBytes != test.wantBytes || observation.ReadMatches || observation.StartedAt.IsZero() || observation.ObservedAt.Before(observation.StartedAt) {
				t.Fatal("failure diagnostic lost typed I/O metadata")
			}
			raw, err := json.Marshal(observation)
			if err != nil || bytes.Contains(raw, []byte("private-error-marker")) || bytes.Contains(raw, []byte("WRONG")) || bytes.Contains(raw, []byte("proof")) {
				t.Fatal("diagnostic exposed payload or error text")
			}
		})
	}
	t.Run("passive-read-values-and-error", func(t *testing.T) {
		errPrivate := errors.New("private-error-marker")
		for _, test := range []struct {
			response []byte
			readErr  error
		}{{[]byte("proof"), nil}, {[]byte("pr"), nil}, {nil, errPrivate}} {
			underlying := &siteLifecycleTestConn{response: test.response, readErr: test.readErr}
			observed := &siteLifecycleReadObservation{Conn: underlying, expected: []byte("proof"), prefixMatches: true}
			if n, err := observed.Write([]byte("proof")); n != 5 || err != nil {
				t.Fatal("observer changed Write")
			}
			buffer := make([]byte, 5)
			n, err := observed.Read(buffer)
			if test.readErr != nil {
				if n != 0 || err != test.readErr {
					t.Fatal("observer changed read error")
				}
			} else if n != len(test.response) || err != nil || !bytes.Equal(buffer[:n], test.response) {
				t.Fatal("observer changed read bytes")
			}
			if observed.readBytes != n || !observed.prefixMatches {
				t.Fatal("passive read metadata incorrect")
			}
		}
	})
	t.Run("successful-round-no-failure-log", func(t *testing.T) {
		flows := []siteLifecycleFlow{{conn: &siteLifecycleTestConn{}}}
		udpAlive := true
		if siteLifecycleRound(context.Background(), flows, &siteLifecycleTestConn{}, &udpAlive, "", func(siteLifecycleIOObservation) { t.Error("successful flow reported failed") }) != nil || flows[0].echoes != 1 || !udpAlive {
			t.Fatal("diagnostics changed positive round")
		}
	})
}
