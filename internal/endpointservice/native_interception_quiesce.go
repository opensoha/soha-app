package endpointservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
)

// A connected controller socket is returned only after the exact old process
// incarnation and accepted TCP peer tuple have been proved. No HTTP secret is
// sent before this check. gone is positive proof, never a lookup failure.
type nativeOwnedControllerDialer interface {
	DialOwnedController(context.Context, nativeSession, nativeOwnedProcessIdentity, netip.AddrPort) (net.Conn, bool, error)
}

// Fixed v1.19.30 /configs Tun wire shape. Omissions normalize to zero; unknown
// fields are rejected. Source: github.com/MetaCubeX/mihomo/listener/config/tun.go.
type nativeTunReadback struct {
	Enable              bool     `yaml:"enable" json:"enable"`
	Device              string   `yaml:"device" json:"device"`
	Stack               string   `yaml:"stack" json:"stack"`
	DNSHijack           []string `yaml:"dns-hijack" json:"dns-hijack"`
	AutoRoute           bool     `yaml:"auto-route" json:"auto-route"`
	AutoDetectInterface bool     `yaml:"auto-detect-interface" json:"auto-detect-interface"`

	MTU                                   uint32         `yaml:"mtu" json:"mtu,omitempty"`
	GSO                                   bool           `yaml:"gso" json:"gso,omitempty"`
	GSOMaxSize                            uint32         `yaml:"gso-max-size" json:"gso-max-size,omitempty"`
	Inet4Address                          []netip.Prefix `yaml:"inet4-address" json:"inet4-address,omitempty"`
	Inet6Address                          []netip.Prefix `yaml:"inet6-address" json:"inet6-address,omitempty"`
	IPRoute2TableIndex                    int            `yaml:"iproute2-table-index" json:"iproute2-table-index,omitempty"`
	IPRoute2RuleIndex                     int            `yaml:"iproute2-rule-index" json:"iproute2-rule-index,omitempty"`
	AutoRedirect                          bool           `yaml:"auto-redirect" json:"auto-redirect,omitempty"`
	AutoRedirectInputMark                 uint32         `yaml:"auto-redirect-input-mark" json:"auto-redirect-input-mark,omitempty"`
	AutoRedirectOutputMark                uint32         `yaml:"auto-redirect-output-mark" json:"auto-redirect-output-mark,omitempty"`
	AutoRedirectIPRoute2FallbackRuleIndex int            `yaml:"auto-redirect-iproute2-fallback-rule-index" json:"auto-redirect-iproute2-fallback-rule-index,omitempty"`
	LoopbackAddress                       []netip.Addr   `yaml:"loopback-address" json:"loopback-address,omitempty"`
	StrictRoute                           bool           `yaml:"strict-route" json:"strict-route,omitempty"`
	RouteAddress                          []netip.Prefix `yaml:"route-address" json:"route-address,omitempty"`
	RouteAddressSet                       []string       `yaml:"route-address-set" json:"route-address-set,omitempty"`
	RouteExcludeAddress                   []netip.Prefix `yaml:"route-exclude-address" json:"route-exclude-address,omitempty"`
	RouteExcludeAddressSet                []string       `yaml:"route-exclude-address-set" json:"route-exclude-address-set,omitempty"`
	IncludeInterface                      []string       `yaml:"include-interface" json:"include-interface,omitempty"`
	ExcludeInterface                      []string       `yaml:"exclude-interface" json:"exclude-interface,omitempty"`
	IncludeUID                            []uint32       `yaml:"include-uid" json:"include-uid,omitempty"`
	IncludeUIDRange                       []string       `yaml:"include-uid-range" json:"include-uid-range,omitempty"`
	ExcludeUID                            []uint32       `yaml:"exclude-uid" json:"exclude-uid,omitempty"`
	ExcludeUIDRange                       []string       `yaml:"exclude-uid-range" json:"exclude-uid-range,omitempty"`
	ExcludeSrcPort                        []uint16       `yaml:"exclude-src-port" json:"exclude-src-port,omitempty"`
	ExcludeSrcPortRange                   []string       `yaml:"exclude-src-port-range" json:"exclude-src-port-range,omitempty"`
	ExcludeDstPort                        []uint16       `yaml:"exclude-dst-port" json:"exclude-dst-port,omitempty"`
	ExcludeDstPortRange                   []string       `yaml:"exclude-dst-port-range" json:"exclude-dst-port-range,omitempty"`
	IncludeAndroidUser                    []int          `yaml:"include-android-user" json:"include-android-user,omitempty"`
	IncludePackage                        []string       `yaml:"include-package" json:"include-package,omitempty"`
	ExcludePackage                        []string       `yaml:"exclude-package" json:"exclude-package,omitempty"`
	IncludeMACAddress                     []string       `yaml:"include-mac-address" json:"include-mac-address,omitempty"`
	ExcludeMACAddress                     []string       `yaml:"exclude-mac-address" json:"exclude-mac-address,omitempty"`
	EndpointIndependentNat                bool           `yaml:"endpoint-independent-nat" json:"endpoint-independent-nat,omitempty"`
	UDPTimeout                            int64          `yaml:"udp-timeout" json:"udp-timeout,omitempty"`
	ICMPTimeout                           int64          `yaml:"icmp-timeout" json:"icmp-timeout,omitempty"`
	DisableICMPForwarding                 bool           `yaml:"disable-icmp-forwarding" json:"disable-icmp-forwarding,omitempty"`
	FileDescriptor                        int            `yaml:"file-descriptor" json:"file-descriptor"`

	Inet4RouteAddress        []netip.Prefix `yaml:"inet4-route-address" json:"inet4-route-address,omitempty"`
	Inet6RouteAddress        []netip.Prefix `yaml:"inet6-route-address" json:"inet6-route-address,omitempty"`
	Inet4RouteExcludeAddress []netip.Prefix `yaml:"inet4-route-exclude-address" json:"inet4-route-exclude-address,omitempty"`
	Inet6RouteExcludeAddress []netip.Prefix `yaml:"inet6-route-exclude-address" json:"inet6-route-exclude-address,omitempty"`

	// darwin special config
	RecvMsgX bool `yaml:"recvmsgx" json:"recvmsgx,omitempty"`
	SendMsgX bool `yaml:"sendmsgx" json:"sendmsgx,omitempty"`
}

type nativeOwnedProcessCapturer interface {
	CaptureOwnedProcess(context.Context, nativeSession, nativeOwnedProcessProof) (nativeOwnedProcessIdentity, error)
}
type nativeDNSQuiesceState struct {
	Tun          nativeTunReadback `json:"tun"`
	Fake4        string            `json:"fake4"`
	Fake6        string            `json:"fake6,omitempty"`
	EnhancedMode string            `json:"enhancedMode"`
}
type nativeDNSQuiescePlan struct {
	DNS               bool                       `json:"dns"`
	Version           int                        `json:"version"`
	Kernel            string                     `json:"kernel"`
	Binding           string                     `json:"binding"`
	Controller        string                     `json:"controller"`
	ControllerBinding string                     `json:"controllerBinding"`
	Process           nativeOwnedProcessIdentity `json:"process"`
	Upstream          netip.AddrPort             `json:"upstream"`
	Before            nativeDNSQuiesceState      `json:"before"`
	After             nativeDNSQuiesceState      `json:"after"`
}

func nativeControllerBinding(origin, secret string) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(origin+"\x00"+secret)))
}
func normalizeNativeTun(t nativeTunReadback) nativeTunReadback {
	v := reflect.ValueOf(&t).Elem()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if field.Kind() == reflect.Slice && field.Len() == 0 {
			field.SetZero()
		}
	}
	return t
}
func nativeTunEqual(a, b nativeTunReadback) bool {
	return reflect.DeepEqual(normalizeNativeTun(a), normalizeNativeTun(b))
}
func nativeQuiesceState(c MihomoConfiguration) nativeDNSQuiesceState {
	s := nativeDNSQuiesceState{Fake4: "198.18.0.1/16", EnhancedMode: "redir-host", Tun: nativeTunReadback{Stack: "gVisor", DNSHijack: []string{"0.0.0.0:53"}, AutoRoute: true, AutoDetectInterface: true, Inet6Address: []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")}, RecvMsgX: true}}
	if c.DNSMode == "fake_ip" {
		s.Fake4 = c.FakeIPRange
		s.EnhancedMode = "fake-ip"
	}
	if p := c.NativePlan; p != nil && p.TUN {
		s.Fake4 = netip.PrefixFrom(p.FakeIPPool.Addr().Next(), p.FakeIPPool.Bits()).String()
		s.Fake6 = netip.PrefixFrom(p.FakeIPv6Pool.Addr().Next(), p.FakeIPv6Pool.Bits()).String()
		s.EnhancedMode = "fake-ip"
		s.Tun = nativeTunReadback{Enable: true, Device: p.Device, Stack: "Mixed", Inet6Address: []netip.Prefix{p.TUNAddress6}, RecvMsgX: true}
	}
	if p, err := netip.ParsePrefix(s.Fake4); err == nil {
		s.Tun.Inet4Address = []netip.Prefix{netip.PrefixFrom(p.Addr(), 30)}
	}
	return s
}
func validNativeQuiesceState(s nativeDNSQuiesceState, after bool) bool {
	p, err := netip.ParsePrefix(s.Fake4)
	if err != nil || !p.Addr().Is4() || s.EnhancedMode != "redir-host" && s.EnhancedMode != "fake-ip" {
		return false
	}
	expected := nativeDNSQuiesceState{Fake4: s.Fake4, EnhancedMode: s.EnhancedMode, Tun: nativeTunReadback{Stack: "gVisor", DNSHijack: []string{"0.0.0.0:53"}, AutoRoute: true, AutoDetectInterface: true, Inet4Address: []netip.Prefix{netip.PrefixFrom(p.Addr(), 30)}, Inet6Address: []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")}, RecvMsgX: true}}
	if after {
		if s.Fake4 != "198.18.0.1/16" && s.Fake4 != "198.19.0.1/16" || s.Fake6 != "fdfe:dcba:9876::1/48" && s.Fake6 != "fdfe:dcba:9875::1/48" || s.EnhancedMode != "fake-ip" || s.Tun.Device != "utun233" && s.Tun.Device != "SohaMihomo" {
			return false
		}
		six, _ := netip.ParsePrefix(s.Fake6)
		expected.Fake6 = s.Fake6
		expected.Tun = nativeTunReadback{Enable: true, Device: s.Tun.Device, Stack: "Mixed", Inet4Address: []netip.Prefix{netip.PrefixFrom(p.Addr(), 30)}, Inet6Address: []netip.Prefix{netip.PrefixFrom(six.Addr(), 126)}, RecvMsgX: true}
	} else if s.Fake6 != "" {
		return false
	} else if len(s.Tun.Inet6Address) == 0 {
		expected.Tun.Inet6Address = nil
	}
	return nativeTunEqual(s.Tun, expected.Tun)
}
func validNativeQuiescePlan(p *nativeDNSQuiescePlan) bool {
	if p == nil {
		return true
	}
	normalized, _, err := mihomoOrigin(p.Controller)
	proof := p.Process.Proof
	digest, hashErr := hex.DecodeString(proof.BinarySHA256)
	epoch, epochErr := hex.DecodeString(proof.ProcessEpoch)
	if err != nil || normalized != p.Controller || p.Version != 1 || p.Kernel != "v1.19.30" || !validReadbackHash(p.Binding) || !validReadbackHash(p.ControllerBinding) || hashErr != nil || len(digest) != 32 || epochErr != nil || len(epoch) != 16 || proof.PID < 2 || proof.PID > 2147483647 || len(p.Process.Incarnation) == 0 || len(p.Process.Incarnation) > 1024 || strings.IndexFunc(p.Process.Incarnation, func(r rune) bool { return r < 32 || r == 127 }) >= 0 || !filepath.IsAbs(proof.LaunchDirectory) || len(proof.LaunchDirectory) > 3000 || filepath.Dir(proof.ExecutablePath) != proof.LaunchDirectory || !slices.Equal(proof.Arguments, []string{proof.ExecutablePath, "-d", proof.LaunchDirectory, "-f", filepath.Join(proof.LaunchDirectory, "config.yaml")}) || !p.Upstream.IsValid() || !p.Upstream.Addr().IsLoopback() || p.Upstream.Port() < 1024 || !validNativeQuiesceState(p.Before, false) || p.DNS && (!validNativeQuiesceState(p.After, true) || len(p.Before.Tun.Inet6Address) != 1) || !p.DNS && !reflect.DeepEqual(p.Before, p.After) {
		return false
	}
	raw, err := json.Marshal(p)
	return err == nil && len(raw) <= 32<<10
}

var errNativeControllerGone = errors.New("exact owned controller process is gone")

func (c *MihomoController) ownedNativeHTTP(s nativeSession, platform nativePlatform, p *nativeDNSQuiescePlan) (*http.Client, func(), error) {
	if !validNativeQuiescePlan(p) || p == nil || p.Controller != c.origin || p.ControllerBinding != nativeControllerBinding(c.origin, c.secret) {
		return nil, nil, errors.New("invalid native DNS quiesce material")
	}
	dialer, ok := platform.(nativeOwnedControllerDialer)
	if !ok {
		return nil, nil, errors.New("owned native controller pin unavailable")
	}
	origin, _ := url.Parse(p.Controller)
	endpoint, err := netip.ParseAddrPort(origin.Host)
	if err != nil {
		return nil, nil, err
	}
	var transport *http.Transport
	if c.http.Transport == nil {
		t, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, nil, errors.New("owned default controller transport unavailable")
		}
		transport = t.Clone()
	} else if t, ok := c.http.Transport.(*http.Transport); ok {
		transport = t.Clone()
	} else {
		return nil, nil, errors.New("owned native controller transport unavailable")
	}
	transport.Proxy = nil
	transport.DisableKeepAlives = true
	transport.DialTLSContext = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != endpoint.String() {
			return nil, errors.New("native controller endpoint changed")
		}
		conn, gone, err := dialer.DialOwnedController(ctx, s, p.Process, endpoint)
		if gone && err == nil {
			if conn != nil {
				conn.Close()
			}
			return nil, errNativeControllerGone
		}
		if err != nil {
			if conn != nil {
				conn.Close()
			}
			return nil, err
		}
		if conn == nil {
			return nil, errors.New("owned native controller socket unavailable")
		}
		return conn, nil
	}
	client := *c.http
	client.Transport = transport
	client.CheckRedirect = rejectRedirect
	return &client, transport.CloseIdleConnections, nil
}
func nativeQuiesceRequest(ctx context.Context, client *http.Client, origin, secret, method, path string, body []byte, status int, out any) error {
	request, err := http.NewRequestWithContext(ctx, method, origin+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+secret)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != status {
		return errors.New("owned native controller rejected quiesce")
	}
	if out == nil {
		_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return err
	}
	contentType, _, contentErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if contentErr != nil || contentType != "application/json" {
		return errors.New("invalid owned native controller content type")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil || len(raw) >= 1<<20 {
		return errors.New("native controller response exceeds safe limit")
	}
	return json.Unmarshal(raw, out)
}
func nativeQuiescePayload(state nativeDNSQuiesceState, p *nativeDNSQuiescePlan, secret string) ([]byte, error) {
	raw, _ := json.Marshal(state.Tun)
	var tun map[string]any
	if json.Unmarshal(raw, &tun) != nil {
		return nil, errors.New("invalid native Tun material")
	}
	delete(tun, "inet4-address")
	if len(state.Tun.DNSHijack) == 0 {
		tun["dns-hijack"] = []string{}
	}
	origin, _ := url.Parse(p.Controller)
	dns := map[string]any{"enable": false, "ipv6": true, "enhanced-mode": state.EnhancedMode, "fake-ip-range": state.Fake4, "fake-ip-range6": state.Fake6, "nameserver": []string{p.Upstream.String()}, "default-nameserver": []string{p.Upstream.String()}}
	return json.Marshal(map[string]any{"mixed-port": 0, "port": 0, "socks-port": 0, "redir-port": 0, "tproxy-port": 0, "allow-lan": false, "bind-address": origin.Hostname(), "mode": "rule", "ipv6": true, "external-controller": origin.Host, "secret": secret, "tun": tun, "dns": dns, "proxies": []any{}, "proxy-groups": []any{}, "rules": []string{"MATCH,REJECT"}})
}

type nativeControllerControl struct {
	Plan     *nativeDNSQuiescePlan
	Platform nativePlatform
	Session  nativeSession
}
type nativeQuiesceGeneral struct {
	MixedPort int             `json:"mixed-port"`
	Port      int             `json:"port"`
	SOCKS     int             `json:"socks-port"`
	Redirect  int             `json:"redir-port"`
	TProxy    int             `json:"tproxy-port"`
	Mode      string          `json:"mode"`
	Bind      string          `json:"bind-address"`
	AllowLAN  bool            `json:"allow-lan"`
	IPv6      bool            `json:"ipv6"`
	Tun       json.RawMessage `json:"tun"`
}

func decodeNativeTun(raw json.RawMessage) (nativeTunReadback, error) {
	var t nativeTunReadback
	if len(raw) == 0 || len(raw) > 16<<10 || decodeStrict(raw, &t) != nil {
		return t, errors.New("invalid complete native Tun readback")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return t, errors.New("invalid native Tun object")
	}
	for _, name := range []string{"enable", "device", "stack", "dns-hijack", "auto-route", "auto-detect-interface", "file-descriptor"} {
		if _, ok := fields[name]; !ok {
			return t, errors.New("incomplete native Tun readback")
		}
	}
	return normalizeNativeTun(t), nil
}
func readNativeQuiesceGeneral(ctx context.Context, client *http.Client, p *nativeDNSQuiescePlan, secret string) (nativeQuiesceGeneral, nativeTunReadback, error) {
	var general nativeQuiesceGeneral
	err := nativeQuiesceRequest(ctx, client, p.Controller, secret, http.MethodGet, "/configs", nil, http.StatusOK, &general)
	if err != nil {
		return general, nativeTunReadback{}, err
	}
	tun, err := decodeNativeTun(general.Tun)
	origin, _ := url.Parse(p.Controller)
	if err != nil || !general.IPv6 || general.AllowLAN || general.Mode != "rule" || general.Bind != origin.Hostname() || general.Port != 0 || general.SOCKS != 0 || general.Redirect != 0 || general.TProxy != 0 {
		return general, tun, errors.Join(err, errors.New("native IPv6/Tun readback unavailable"))
	}
	return general, tun, nil
}
func (c *MihomoController) quiesceOwnedNativeIngress(ctx context.Context, session nativeSession, platform nativePlatform, p *nativeDNSQuiescePlan) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !validNativeQuiescePlan(p) || p == nil {
		return errors.New("native controller quiesce material unavailable")
	}
	dialer, ok := platform.(nativeOwnedControllerDialer)
	if !ok {
		return errors.New("owned controller proof unavailable")
	}
	origin, _ := url.Parse(p.Controller)
	endpoint, _ := netip.ParseAddrPort(origin.Host)
	conn, gone, err := dialer.DialOwnedController(ctx, session, p.Process, endpoint)
	if conn != nil {
		conn.Close()
	}
	if err != nil {
		return err
	}
	if gone {
		return nil
	}
	client, closeClient, err := c.ownedNativeHTTP(session, platform, p)
	if err != nil {
		return err
	}
	defer closeClient()
	// The managed gate is already blocked by the coordinator. Keep the old TUN
	// alive while closing the only remaining engine business listener.
	if err = nativeQuiesceRequest(ctx, client, p.Controller, c.secret, http.MethodPatch, "/configs", []byte(`{"mixed-port":0}`), http.StatusNoContent, nil); err != nil {
		if errors.Is(err, errNativeControllerGone) {
			return nil
		}
		return err
	}
	if err = c.egress.close(); err != nil {
		return err
	}
	c.egress = nil
	general, tun, err := readNativeQuiesceGeneral(ctx, client, p, c.secret)
	if err != nil {
		if errors.Is(err, errNativeControllerGone) {
			return nil
		}
		return err
	}
	if !nativeTunEqual(tun, p.Before.Tun) && !nativeTunEqual(tun, p.After.Tun) {
		return errors.New("owned native Tun is outside journal states")
	}
	if !p.DNS {
		if general.MixedPort != 0 || general.Port != 0 || general.SOCKS != 0 || general.Redirect != 0 || general.TProxy != 0 {
			return errors.New("native business listener is not quiesced")
		}
		return nil
	}
	state := p.Before
	if nativeTunEqual(tun, p.After.Tun) {
		state = p.After
	}
	readSnapshot := platform.Snapshot
	if reader, ok := platform.(nativeRecoverySnapshotReader); ok {
		readSnapshot = reader.RecoverySnapshot
	}
	snapshot, err := readSnapshot(ctx, session)
	if err != nil || !nativeHasGlobalIPv6(snapshot) {
		return errors.Join(err, errors.New("native Tun IPv6 parse environment changed"))
	}
	payload, err := nativeQuiescePayload(state, p, c.secret)
	if err != nil {
		return err
	}
	defer clear(payload)
	envelope, err := json.Marshal(struct {
		Payload string `json:"payload"`
	}{string(payload)})
	if err != nil {
		return err
	}
	defer clear(envelope)
	if err = nativeQuiesceRequest(ctx, client, p.Controller, c.secret, http.MethodPut, "/configs?force=true", envelope, http.StatusNoContent, nil); err != nil {
		if errors.Is(err, errNativeControllerGone) {
			return nil
		}
		return err
	}
	after, afterTun, err := readNativeQuiesceGeneral(ctx, client, p, c.secret)
	if err != nil {
		if errors.Is(err, errNativeControllerGone) {
			return nil
		}
		return err
	}
	expectedOrigin, _ := url.Parse(p.Controller)
	if !nativeTunEqual(tun, afterTun) || after.MixedPort != 0 || after.Port != 0 || after.SOCKS != 0 || after.Redirect != 0 || after.TProxy != 0 || after.AllowLAN || after.Bind != expectedOrigin.Hostname() || after.Mode != "rule" {
		return errors.New("native DNS stop changed Tun or listener state")
	}
	return nil
}
func (e *CoordinatedExecutor) prepareNativeQuiesce(ctx context.Context, c MihomoConfiguration) error {
	controller, ok := e.mihomo.(*MihomoController)
	if !ok {
		return nil
	}
	// Once native ownership checks begin, no consumer may fall back to the
	// ordinary client if preparation fails before a pinned scope is attached.
	controller.mu.Lock()
	controller.nativeControlRequired = true
	controller.mu.Unlock()
	n := e.native
	status := controller.ProcessStatus()
	if status.Ownership != "soha_owned" || !nativeKernelSupported(status.Version) {
		return errors.New("native DNS stop requires the approved v1.19.30 owned engine")
	}
	proof, err := controller.nativeOwnedProof()
	if err != nil {
		return err
	}
	capturer, ok := n.platform.(nativeOwnedProcessCapturer)
	if !ok {
		return errors.New("owned native process capture unavailable")
	}
	var record nativeOwnedProcessIdentity
	if n.journal.Process != nil && reflect.DeepEqual(n.journal.Process.Proof, proof) {
		record = *n.journal.Process
	} else {
		record, err = capturer.CaptureOwnedProcess(ctx, n.session, proof)
		if err != nil {
			return err
		}
	}
	if !reflect.DeepEqual(record.Proof, proof) {
		return errors.New("owned native process proof changed")
	}
	plan := &nativeDNSQuiescePlan{Version: 1, Kernel: "v1.19.30", Binding: n.journal.Binding, Controller: controller.origin, ControllerBinding: nativeControllerBinding(controller.origin, controller.secret), Process: record, Upstream: c.NativePlan.DNSUpstream, Before: nativeQuiesceState(*n.base), After: nativeQuiesceState(c), DNS: c.NativePlan.TUN}
	n.guard.mu.Lock()
	binding := n.guard.binding
	n.guard.mu.Unlock()
	if binding == nil {
		return errors.New("native network snapshot unavailable")
	}
	if !nativeHasGlobalIPv6(binding.snapshot) && !plan.DNS {
		plan.Before.Tun.Inet6Address = nil
		plan.After.Tun.Inet6Address = nil
	}
	if !validNativeQuiescePlan(plan) {
		return errors.New("generated native quiesce material invalid")
	}
	controller.mu.Lock()
	client, closeClient, err := controller.ownedNativeHTTP(n.session, n.platform, plan)
	if err == nil {
		var actual nativeTunReadback
		_, actual, err = readNativeQuiesceGeneral(ctx, client, plan, controller.secret)
		closeClient()
		if err == nil && !nativeTunEqual(actual, plan.Before.Tun) {
			err = errors.New("native before Tun readback mismatch")
		}
	}
	controller.mu.Unlock()
	if err != nil {
		return err
	}
	n.journal.Quiesce = plan
	if err = saveNativeJournal(n.path, n.journal); err != nil {
		return err
	}
	controller.mu.Lock()
	controller.nativeControl = &nativeControllerControl{Plan: plan, Platform: n.platform, Session: n.session}
	controller.mu.Unlock()
	return nil
}
func (e *CoordinatedExecutor) nativeRestoreOwnerLock() (func(), error) {
	n := e.native
	controller, ok := e.mihomo.(*MihomoController)
	if !ok {
		return func() {}, nil
	}
	var proof *nativeOwnedProcessProof
	if n.journal.Quiesce != nil {
		proof = &n.journal.Quiesce.Process.Proof
	} else if n.journal.Process != nil {
		proof = &n.journal.Process.Proof
	}
	if proof == nil {
		return func() {}, nil
	}
	// Cleanup may retry while a failed stop still owns cmd and owner.lock.
	// This is an identity read, not active/capture authorization: only an absent
	// cmd may enter orphan recovery and acquire a new lock.
	hasCommand, err := func() (bool, error) {
		controller.mu.Lock()
		defer controller.mu.Unlock()
		if controller.process == nil {
			return false, errors.New("owned process recovery lock unavailable")
		}
		p := controller.process
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.cmd == nil {
			return false, nil
		}
		if p.cmd.Process == nil || p.status.PID <= 0 || p.status.ProcessEpoch == "" || p.cmd.Process.Pid != p.status.PID {
			return true, errors.New("native owned process changed before restore")
		}
		current := nativeOwnedProcessProof{PID: uint32(p.status.PID), ProcessEpoch: p.status.ProcessEpoch, BinarySHA256: p.status.BinarySHA256, ExecutablePath: p.cmd.Path, LaunchDirectory: filepath.Dir(p.cmd.Path), Arguments: append([]string(nil), p.cmd.Args...)}
		if !reflect.DeepEqual(current, *proof) {
			return true, errors.New("native owned process changed before restore")
		}
		return true, nil
	}()
	if err != nil {
		return nil, err
	}
	if hasCommand {
		return func() {}, nil
	}
	unlock, err := controller.nativeRecoveryLock(*proof)
	if err != nil {
		return nil, err
	}
	n.recoveryLockHeld = true
	var once sync.Once
	return func() { once.Do(func() { n.recoveryLockHeld = false; unlock() }) }, nil
}
func nativeHasGlobalIPv6(s nativeSnapshot) bool {
	for _, iface := range s.Interfaces {
		for _, prefix := range iface.Addresses {
			a := prefix.Addr()
			if a.Is6() && !a.Is4In6() && a.IsGlobalUnicast() {
				return true
			}
		}
	}
	return false
}

// Native staging must not insert disable()'s third Tun/IPv6 state between the
// two durably prepared states. The real staged PUT still verifies all new rules.
func (c *MihomoController) stageNativeIngress(ctx context.Context) error {
	scope := c.nativeControl
	if scope == nil || c.current == nil {
		return errors.New("native controller scope unavailable")
	}
	gateErr := c.egress.close()
	c.egress = nil
	patchErr := c.request(ctx, http.MethodPatch, "/configs", []byte(`{"mixed-port":0}`), http.StatusNoContent, nil)
	closeErr := c.closeConnections(ctx)
	listenerErr := c.verifyManagedListener(ctx, 0, *c.current)
	rulesErr := c.verifyRules(ctx, mihomoRules(*c.current))
	client, closeClient, err := c.ownedNativeHTTP(scope.Session, scope.Platform, scope.Plan)
	if err == nil {
		_, actual, readErr := readNativeQuiesceGeneral(ctx, client, scope.Plan, c.secret)
		closeClient()
		err = readErr
		if err == nil && !nativeTunEqual(actual, scope.Plan.Before.Tun) {
			err = errors.New("native staging changed before Tun")
		}
	}
	if err = errors.Join(gateErr, patchErr, closeErr, listenerErr, rulesErr, err); err != nil {
		return err
	}
	c.applied = MihomoReadback{}
	return nil
}

func (c *MihomoController) verifyNativeCompleteTun(ctx context.Context) error {
	scope := c.nativeControl
	if scope == nil {
		return errors.New("native controller scope unavailable")
	}
	client, closeClient, err := c.ownedNativeHTTP(scope.Session, scope.Platform, scope.Plan)
	if err != nil {
		return err
	}
	defer closeClient()
	_, actual, err := readNativeQuiesceGeneral(ctx, client, scope.Plan, c.secret)
	if err != nil {
		return err
	}
	if !nativeTunEqual(actual, scope.Plan.After.Tun) {
		return errors.New("native complete after Tun readback mismatch")
	}
	return nil
}
