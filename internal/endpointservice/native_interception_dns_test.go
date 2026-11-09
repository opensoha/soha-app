package endpointservice

import (
	"context"
	"encoding/binary"
	"errors"
	"go.yaml.in/yaml/v3"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func nativeTestDNSQuery(t *testing.T, host string, kind dnsmessage.Type) []byte {
	t.Helper()
	name, e := dnsmessage.NewName(host + ".")
	if e != nil {
		t.Fatal(e)
	}
	raw, e := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 234, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Class: dnsmessage.ClassINET, Type: kind}}}).Pack()
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestNativeInterceptionDNSRejectsMalformedAndTransferQueries(t *testing.T) {
	for _, kind := range []dnsmessage.Type{251, 252} {
		if _, e := nativeDNSQuestion(nativeTestDNSQuery(t, "example.test", kind)); e == nil {
			t.Fatal("transfer accepted")
		}
	}
	for _, raw := range [][]byte{nil, make([]byte, 4097), {0, 1, 2}, {0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0}} {
		if _, e := nativeDNSQuestion(raw); e == nil {
			t.Fatal("malformed accepted")
		}
	}
	raw := nativeTestDNSQuery(t, "example.test", dnsmessage.TypeA)
	var m dnsmessage.Message
	_ = m.Unpack(raw)
	m.Questions = append(m.Questions, m.Questions[0])
	raw, _ = m.Pack()
	if _, e := nativeDNSQuestion(raw); e == nil {
		t.Fatal("multiple questions accepted")
	}
}
func TestNativeInterceptionDNSNamespaceHasNoPublicFallback(t *testing.T) {
	calls := 0
	p := &nativeDNSProxy{until: time.Now().Add(time.Minute), scopes: []nativeResolverScope{{ID: "private", Domains: []string{"internal.test"}, Servers: []netip.Addr{netip.MustParseAddr("192.0.2.53")}}, {ID: "public", Default: true, Servers: []netip.Addr{netip.MustParseAddr("192.0.2.54")}}}, dial: func(_ context.Context, _ string, remote netip.AddrPort) (net.Conn, error) {
		calls++
		if remote.Addr() != netip.MustParseAddr("192.0.2.53") {
			t.Fatal("namespace failed open")
		}
		return nil, errors.New("private resolver unavailable")
	}}
	if _, e := p.exchange(context.Background(), nativeTestDNSQuery(t, "host.internal.test", dnsmessage.TypeA)); e == nil || calls != 1 {
		t.Fatal("namespace failure did not remain scoped", e, calls)
	}
	p.scopes = append(p.scopes, nativeResolverScope{ID: "ambiguous", Domains: []string{"internal.test"}, Servers: []netip.Addr{netip.MustParseAddr("192.0.2.55")}})
	if _, e := p.scopeFor("host.internal.test"); e == nil {
		t.Fatal("ambiguous namespace accepted")
	}
}
func TestNativeInterceptionDNSValidatesUpstreamIdentityAndQuestion(t *testing.T) {
	server, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	remote := server.LocalAddr().(*net.UDPAddr).AddrPort()
	go func() {
		buf := make([]byte, 4096)
		n, peer, e := server.ReadFromUDPAddrPort(buf)
		if e != nil {
			return
		}
		raw := append([]byte(nil), buf[:n]...)
		raw[2] |= 0x80
		binary.BigEndian.PutUint16(raw[:2], 999)
		_, _ = server.WriteToUDPAddrPort(raw, peer)
	}()
	p := &nativeDNSProxy{dial: func(ctx context.Context, network string, endpoint netip.AddrPort) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, endpoint.String())
	}}
	raw := nativeTestDNSQuery(t, "a.test", dnsmessage.TypeA)
	m, _ := nativeDNSQuestion(raw)
	if _, err = p.query(context.Background(), "udp", remote, raw, m); err == nil {
		t.Fatal("wrong response ID accepted")
	}
}
func TestNativeInterceptionDNSRecordsAndExpiry(t *testing.T) {
	p := &nativeDNSProxy{until: time.Now().Add(time.Minute), records: []DNSRecord{{Hostname: "host.internal.test", Addresses: []string{"10.0.0.2", "fd00::2"}, ExpiresAt: time.Now().Add(time.Minute)}}}
	for _, kind := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		reply, e := p.exchange(context.Background(), nativeTestDNSQuery(t, "host.internal.test", kind))
		var m dnsmessage.Message
		if e != nil || m.Unpack(reply) != nil || len(m.Answers) != 1 || m.Questions[0].Type != kind {
			t.Fatal("managed dual-stack record failed", e)
		}
	}
	p.renew(time.Now().Add(-time.Second), p.records)
	if _, e := p.lookup(context.Background(), "ip", "host.internal.test"); e == nil {
		t.Fatal("expired DNS answered")
	}
}
func TestNativeInterceptionGeneratedTUNConfigurationAndLegacyIsolation(t *testing.T) {
	c := managedMihomoConfiguration(9090)
	c.SourceType = "manual_node"
	c.SubscriptionURL = ""
	c.SelectedProxy = ""
	c.ManualNode = &MihomoManualNode{Protocol: "http", Server: "192.0.2.8", Port: 8443}
	c.GuardPort, c.GuardProxyPort, c.GuardDirectPort = 18080, 18081, 18082
	c.GuardProxySecret, c.GuardDirectSecret = strings.Repeat("p", 32), strings.Repeat("d", 32)
	c.BootstrapNodes = []map[string]any{{"name": mihomoManualProxyName, "type": "http", "server": "192.0.2.8", "port": 8443}}
	plain, e := renderMihomoConfiguration(c, "", "127.0.0.1", "127.0.0.1:9090", strings.Repeat("s", 32))
	if e != nil || !strings.Contains(plain, "tun:\n  enable: false") || strings.Contains(plain, "inet6-address") {
		t.Fatal("legacy render changed", e)
	}
	c.DNSMode = "fake_ip"
	c.FakeIPRange = "198.18.0.0/16"
	c.NativePlan = &nativeEnginePlan{TUN: true, Device: "soha-test", DNSBypassHosts: []string{"control.example.test", "wg.example.test", "ui.example.test"}, ProbeHost: "soha-egress-private-probe.invalid", FakeIPPool: netip.MustParsePrefix("198.18.0.0/16"), FakeIPv6Pool: netip.MustParsePrefix("fdfe:dcba:9876::/48"), TUNAddress: netip.MustParsePrefix("198.18.0.1/30"), TUNAddress6: netip.MustParsePrefix("fdfe:dcba:9876::1/126"), PhysicalInterface: "en0", DNSUpstream: netip.MustParseAddrPort("127.0.0.1:32001"), NodeInterfaces: map[string]string{mihomoManualProxyName: "en0"}}
	raw, e := renderMihomoConfiguration(c, "", "127.0.0.1", "127.0.0.1:9090", strings.Repeat("s", 32))
	if e != nil {
		t.Fatal(e)
	}
	var doc struct {
		Tun struct {
			Enable, AutoRoute, AutoDetect bool
			Device                        string
			Inet6                         []string `yaml:"inet6-address"`
		}
		DNS struct {
			Listen string `yaml:"listen"`
			Fake   string `yaml:"fake-ip-range"`
			Fake6  string `yaml:"fake-ip-range6"`
		}
		Proxies []map[string]any
	}
	if yaml.Unmarshal([]byte(raw), &doc) != nil || !doc.Tun.Enable || doc.Tun.AutoRoute || doc.Tun.AutoDetect || len(doc.Tun.Inet6) != 1 || doc.DNS.Fake != "198.18.0.1/16" || doc.DNS.Fake6 != "fdfe:dcba:9876::1/48" || strings.Contains(raw, "- system") || strings.Contains(raw, "dns-mode:") {
		t.Fatal("unsafe native render", raw)
	}
	bound := false
	for _, p := range doc.Proxies {
		if p["name"] == mihomoManualProxyName && p["interface-name"] == "en0" {
			bound = true
		}
	}
	if !bound {
		t.Fatal("native node was not interface bound")
	}
	if !strings.Contains(raw, "fake-ip-filter:") || !strings.Contains(raw, "wg.example.test") || !strings.Contains(raw, "ui.example.test") {
		t.Fatal("control/peer DNS can become fake-IP")
	}
	rules := mihomoRules(c)
	if len(rules) == 0 || rules[0].Type != "Domain" || rules[0].Payload != c.NativePlan.ProbeHost || rules[0].Proxy != mihomoGuardProxyName {
		t.Fatal("owned health probe is not a guarded DOMAIN rule")
	}

}
