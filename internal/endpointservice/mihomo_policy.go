package endpointservice

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

type mihomoRule struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Proxy   string `json:"proxy"`
	Extra   struct {
		Disabled bool `json:"disabled"`
	} `json:"extra"`
}

func (rule mihomoRule) configurationLine() string {
	types := map[string]string{"IPCIDR": "IP-CIDR", "Domain": "DOMAIN", "DomainSuffix": "DOMAIN-SUFFIX", "Match": "MATCH"}
	if rule.Type == "Match" {
		return "MATCH," + rule.Proxy
	}
	return types[rule.Type] + "," + rule.Payload + "," + rule.Proxy
}

func mihomoRules(configuration MihomoConfiguration) []mihomoRule {
	// Resolve CIDR rules locally; no-resolve would allow a protected destination
	// named by a host to fall through to the remote proxy's DNS and MATCH rule.
	rules := []mihomoRule{}
	for _, cidr := range configuration.VPNRoutes {
		rules = append(rules, mihomoRule{Type: "IPCIDR", Payload: cidr, Proxy: mihomoVPNProxyName})
	}
	for _, host := range configuration.Protection.Hosts {
		rules = append(rules, mihomoRule{Type: "DomainSuffix", Payload: host, Proxy: "REJECT"})
	}
	for _, cidr := range configuration.Protection.CIDRs {
		rules = append(rules, mihomoRule{Type: "IPCIDR", Payload: cidr, Proxy: "REJECT"})
	}
	for _, cidr := range configuration.BypassCIDRs {
		rules = append(rules, mihomoRule{Type: "IPCIDR", Payload: cidr, Proxy: mihomoGuardDirectName})
	}
	for _, host := range configuration.BypassHosts {
		rule := mihomoRule{Type: "Domain", Payload: host, Proxy: mihomoGuardDirectName}
		if address, err := netip.ParseAddr(host); err == nil {
			rule.Type, rule.Payload = "IPCIDR", netip.PrefixFrom(address, address.BitLen()).String()
		}
		rules = append(rules, rule)
	}
	return append(rules, mihomoRule{Type: "Match", Proxy: mihomoGuardProxyName})
}

func mihomoProtectionHash(configuration MihomoConfiguration) string {
	raw, _ := json.Marshal(struct {
		Protection  *MihomoProtection `json:"protection"`
		Interface   string            `json:"interface"`
		Routes      []string          `json:"routes"`
		BypassCIDRs []string          `json:"bypassCidrs"`
		BypassHosts []string          `json:"bypassHosts"`
	}{configuration.Protection, configuration.VPNInterface, configuration.VPNRoutes, configuration.BypassCIDRs, configuration.BypassHosts})
	digest := sha256.Sum256(raw)
	return fmt.Sprintf("sha256:%x", digest)
}

func validateMihomoProtection(configuration *MihomoConfiguration, fakeIP netip.Prefix) error {
	protection := configuration.Protection
	if protection == nil || protection.PolicyVersion < 1 || protection.CIDRs == nil || protection.Hosts == nil || len(protection.CIDRs) > 4096 || len(protection.Hosts) > 2048 || reservedMihomoName(configuration.SelectorGroup) {
		return errors.New("mihomo protected policy is missing or invalid")
	}
	for _, list := range [][]string{protection.CIDRs, configuration.VPNRoutes} {
		seen := map[string]bool{}
		for _, raw := range list {
			prefix, err := canonicalMihomoPrefix(raw)
			if err != nil || seen[raw] || fakeIP.IsValid() && fakeIP.Overlaps(prefix) {
				return errors.New("mihomo protected CIDR or VPN route is invalid")
			}
			seen[raw] = true
		}
	}
	seen := map[string]bool{}
	for _, host := range protection.Hosts {
		_, addressErr := netip.ParseAddr(host)
		if !validEndpointHost(host) || addressErr == nil || host != strings.ToLower(host) || seen[host] {
			return errors.New("mihomo protected host is invalid")
		}
		seen[host] = true
	}
	if len(configuration.VPNRoutes) > 256 || len(configuration.VPNRoutes) > 0 && !validVPNInterfaceName(configuration.VPNInterface) || len(configuration.VPNRoutes) == 0 && configuration.VPNInterface != "" {
		return errors.New("mihomo VPN interface binding is invalid")
	}
	return nil
}

func reservedMihomoName(name string) bool {
	switch strings.ToUpper(name) {
	case strings.ToUpper(mihomoGuardProxyName), strings.ToUpper(mihomoGuardDirectName), "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL", strings.ToUpper(mihomoVPNProxyName), strings.ToUpper(mihomoManualProxyName), strings.ToUpper(mihomoProviderName):
		return true
	}
	return false
}

func (controller *MihomoController) verifyRules(ctx context.Context, expected []mihomoRule) error {
	var state struct {
		Rules []mihomoRule `json:"rules"`
	}
	if err := controller.request(ctx, http.MethodGet, "/rules", nil, http.StatusOK, &state); err != nil {
		return err
	}
	if len(state.Rules) != len(expected) {
		return errors.New("mihomo rule count changed")
	}
	for index, rule := range state.Rules {
		want := expected[index]
		if rule.Type != want.Type || rule.Payload != want.Payload || rule.Proxy != want.Proxy || rule.Extra.Disabled {
			return errors.New("mihomo rule order or target changed")
		}
	}
	return nil
}

type mihomoProxyState struct {
	Type      string   `json:"type"`
	Interface string   `json:"interface"`
	Dialer    string   `json:"dialer-proxy"`
	All       []string `json:"all"`
	Now       string   `json:"now"`
}

func (controller *MihomoController) proxyGroup(ctx context.Context, configuration MihomoConfiguration) (mihomoProxyState, error) {
	var state struct {
		Proxies map[string]mihomoProxyState `json:"proxies"`
	}
	if err := controller.request(ctx, http.MethodGet, "/proxies", nil, http.StatusOK, &state); err != nil {
		return mihomoProxyState{}, err
	}
	group := state.Proxies[configuration.SelectorGroup]
	if group.Type != "Selector" || len(group.All) == 0 || len(group.All) > 2048 {
		return mihomoProxyState{}, errors.New("mihomo selector group is invalid")
	}
	seen := map[string]bool{}
	for _, name := range group.All {
		node, exists := state.Proxies[name]
		manual := configuration.SourceType == "manual_node" && name == mihomoManualProxyName
		if !exists || !validMihomoName(name) || seen[name] || reservedMihomoName(name) && !manual || name == configuration.SelectorGroup || !mihomoTransportType(node.Type) || len(node.All) != 0 || node.Dialer != "" || node.Interface != "" {
			return mihomoProxyState{}, errors.New("mihomo node type, binding or name is unsafe")
		}
		seen[name] = true
	}
	if len(configuration.VPNRoutes) > 0 {
		vpn, exists := state.Proxies[mihomoVPNProxyName]
		if !exists || vpn.Type != "Direct" || vpn.Interface != configuration.VPNInterface || vpn.Dialer != "" || len(vpn.All) != 0 {
			return mihomoProxyState{}, errors.New("mihomo VPN exit binding changed")
		}
	}
	return group, nil
}

func (controller *MihomoController) Verify(ctx context.Context, configuration *MihomoConfiguration) error {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if configuration != nil && (controller.egress == nil || !controller.egress.handler.Ready()) {
		return errors.New("mihomo egress lease is not active")
	}
	if configuration == nil {
		return errors.Join(controller.verifyListener(ctx, 0), controller.verifyRules(ctx, []mihomoRule{{Type: "Match", Proxy: "REJECT"}}))
	}
	if err := validateMihomoConfiguration(configuration, nil, false); err != nil {
		return err
	}
	if err := controller.verifyListener(ctx, configuration.MixedPort, mihomoIPv6(*configuration)); err != nil {
		return err
	}
	if err := controller.verifyRules(ctx, mihomoRules(*configuration)); err != nil {
		return err
	}
	if err := controller.verifyEgress(ctx); err != nil {
		return err
	}
	group, err := controller.proxyGroup(ctx, *configuration)
	if err != nil || group.Now != controller.applied.SelectedProxy {
		return errors.New("mihomo selected node or VPN binding changed")
	}
	return nil
}

func mihomoTransportType(kind string) bool {
	return slices.Contains([]string{"Http", "Socks5", "Shadowsocks", "ShadowsocksR", "Snell", "Vmess", "Vless", "Trojan", "Hysteria", "Hysteria2", "Tuic", "AnyTLS"}, kind)
}

func (controller *MihomoController) verifyListener(ctx context.Context, port int, ipv6 ...bool) error {
	expectedIPv6 := len(ipv6) == 1 && ipv6[0]
	var configuration struct {
		MixedPort    int    `json:"mixed-port"`
		HTTPPort     int    `json:"port"`
		SOCKSPort    int    `json:"socks-port"`
		RedirectPort int    `json:"redir-port"`
		TProxyPort   int    `json:"tproxy-port"`
		Mode         string `json:"mode"`
		AllowLAN     bool   `json:"allow-lan"`
		BindAddress  string `json:"bind-address"`
		IPv6         bool   `json:"ipv6"`
		Tun          struct {
			Enable bool `json:"enable"`
		} `json:"tun"`
	}
	if err := controller.request(ctx, http.MethodGet, "/configs", nil, http.StatusOK, &configuration); err != nil {
		return err
	}
	if configuration.MixedPort != port || configuration.Mode != "rule" || configuration.AllowLAN || configuration.BindAddress != controller.address || configuration.HTTPPort != 0 || configuration.SOCKSPort != 0 || configuration.RedirectPort != 0 || configuration.TProxyPort != 0 || configuration.IPv6 != expectedIPv6 || configuration.Tun.Enable {
		return errors.New("mihomo listener state does not match the managed profile")
	}
	return nil
}

func (controller *MihomoController) closeConnections(ctx context.Context) error {
	if err := controller.request(ctx, http.MethodDelete, "/connections", nil, http.StatusNoContent, nil); err != nil {
		return err
	}
	var state struct {
		Connections []json.RawMessage `json:"connections"`
	}
	if err := controller.request(ctx, http.MethodGet, "/connections", nil, http.StatusOK, &state); err != nil {
		return err
	}
	if len(state.Connections) != 0 {
		return errors.New("mihomo connections are still draining")
	}
	return nil
}

// Ordinary TCP and authorized VPN routes share the same destination guard.
func mihomoIPv6(_ MihomoConfiguration) bool { return true }
