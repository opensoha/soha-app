package endpointservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/opensoha/soha-contracts/proxytransport"
	"go.yaml.in/yaml/v3"
)

// Fetch and pin transport nodes before handing anything to the engine. The
// subscription can supply nodes, never providers, DNS, routes, or rule sources.
func prepareMihomoBootstrap(ctx context.Context, configuration *MihomoConfiguration, subscriptionURL string) error {
	var nodes []map[string]any
	if configuration.SourceType == "manual_node" {
		node := configuration.ManualNode
		if node == nil {
			return errors.New("manual proxy node missing")
		}
		kind := node.Protocol
		if kind == "https" {
			kind = "http"
		}
		value := map[string]any{"name": mihomoManualProxyName, "type": kind, "server": node.Server, "port": node.Port}
		if node.Protocol == "https" {
			value["tls"] = true
		}
		if node.Username != "" {
			value["username"], value["password"] = node.Username, node.Password
		}
		nodes = []map[string]any{value}
	} else {
		raw, err := fetchMihomoSubscription(ctx, subscriptionURL, configuration.Protection)
		if err != nil {
			return err
		}
		defer clear(raw)
		var document struct {
			Proxies []map[string]any `yaml:"proxies"`
		}
		decoder := yaml.NewDecoder(bytes.NewReader(raw))
		if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			return errors.New("subscription must contain one bounded proxy document")
		}
		nodes = document.Proxies
	}
	if len(nodes) == 0 || len(nodes) > 2048 {
		return errors.New("subscription node count is invalid")
	}
	seen := map[string]bool{}
	for _, node := range nodes {
		name, _ := node["name"].(string)
		if !validMihomoName(name) || seen[name] || name == configuration.SelectorGroup || reservedMihomoName(name) && !(configuration.SourceType == "manual_node" && name == mihomoManualProxyName) {
			return errors.New("subscription node identity is unsafe")
		}
		seen[name] = true
		if err := pinMihomoNode(ctx, node, configuration.Protection); err != nil {
			return err
		}
	}
	configuration.BootstrapNodes = nodes
	return nil
}

func fetchMihomoSubscription(ctx context.Context, rawURL string, protection *MihomoProtection) ([]byte, error) {
	if !validSubscriptionURL(rawURL) {
		return nil, errors.New("invalid subscription URL")
	}
	transport := &http.Transport{Proxy: nil, ResponseHeaderTimeout: 5 * time.Second, TLSHandshakeTimeout: 5 * time.Second, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ip, err := mihomoBootstrapAddress(ctx, host, protection)
		if err != nil {
			return nil, err
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("subscription download failed")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subscription returned HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(raw) > 1<<20 {
		return nil, errors.New("subscription exceeds its size limit")
	}
	return raw, nil
}

func pinMihomoNode(ctx context.Context, node map[string]any, protection *MihomoProtection) error {
	kind, _ := node["type"].(string)
	if !slices.Contains([]string{"http", "socks5", "ss", "ssr", "snell", "vmess", "vless", "trojan", "hysteria", "hysteria2", "tuic", "anytls"}, kind) {
		return errors.New("unsupported subscription node type")
	}
	allowed := map[string]bool{}
	for _, key := range strings.Fields("name type server port skip-cert-verify cipher password username uuid alterId udp network tls servername sni alpn client-fingerprint fingerprint flow packet-encoding ws-opts grpc-opts http-opts h2-opts reality-opts obfs obfs-param protocol protocol-param psk version up down auth auth-str obfs-password congestion-controller reduce-rtt fast-open heartbeat-interval request-timeout udp-relay-mode udp-over-tcp udp-over-stream") {
		allowed[key] = true
	}
	for key := range node {
		if !allowed[key] {
			return errors.New("subscription node contains an unmanaged option")
		}
	}
	if node["skip-cert-verify"] == true {
		return errors.New("subscription cannot disable TLS verification")
	}
	host, ok := node["server"].(string)
	if !ok {
		return errors.New("subscription node server is missing")
	}
	port, err := strconv.Atoi(fmt.Sprint(node["port"]))
	if err != nil || port < 1 || port > 65535 {
		return errors.New("subscription node port is invalid")
	}
	address, err := mihomoBootstrapAddress(ctx, host, protection)
	if err != nil {
		return err
	}
	if _, err := netip.ParseAddr(host); err != nil {
		if node["servername"] == nil {
			node["servername"] = host
		}
		if node["sni"] == nil {
			node["sni"] = host
		}
	}
	node["server"], node["port"] = address.String(), port
	return nil
}

func mihomoBootstrapAddress(ctx context.Context, host string, protection *MihomoProtection) (netip.Addr, error) {
	if protection == nil {
		return netip.Addr{}, errors.New("bootstrap protected scope missing")
	}
	scope, err := proxytransport.NewScope(protection.CIDRs, protection.Hosts)
	if err != nil {
		return netip.Addr{}, err
	}
	return scope.Resolve(ctx, host)
}
