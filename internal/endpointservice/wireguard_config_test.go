package endpointservice

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRenderWireGuardConfigUsesOnlySplitTunnelFields(t *testing.T) {
	t.Parallel()
	plan := TunnelPlan{PrivateKey: "private-key", PublicKey: "public-key", Addresses: []string{"100.96.0.2/32"}, MTU: 1380, Peer: TunnelPeer{PublicKey: "peer-key", Endpoint: "vpn.example.com:51820", AllowedIPs: []string{"10.20.0.0/24"}, PersistentKeepaliveSeconds: 25}, Routes: []string{"10.20.0.0/24"}, DNSServers: []string{"10.20.0.53"}}
	config := string(renderWireGuardConfig(plan))
	for _, expected := range []string{"PrivateKey = private-key", "Address = 100.96.0.2/32", "DNS = 10.20.0.53", "MTU = 1380", "PublicKey = peer-key", "AllowedIPs = 10.20.0.0/24", "Endpoint = vpn.example.com:51820", "PersistentKeepalive = 25"} {
		if !strings.Contains(config, expected) {
			t.Fatalf("config missing %q:\n%s", expected, config)
		}
	}
	if strings.Contains(config, "0.0.0.0/0") || strings.Contains(config, "PreUp") || strings.Contains(config, "PostUp") {
		t.Fatalf("unsafe config:\n%s", config)
	}
}

func TestVerifyRouteSetRejectsUnexpectedUnicastRoute(t *testing.T) {
	t.Parallel()
	required := []string{"10.20.0.0/24"}
	allowed := []string{"100.96.0.2/32"}
	actual := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24"), netip.MustParsePrefix("100.96.0.2/32"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("255.255.255.255/32")}
	if err := verifyRouteSet(actual, required, allowed); err != nil {
		t.Fatal(err)
	}
	actual = append(actual, netip.MustParsePrefix("172.16.0.0/16"))
	if err := verifyRouteSet(actual, required, allowed); err == nil {
		t.Fatal("verifyRouteSet() accepted an unexpected route")
	}
}
