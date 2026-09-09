package endpointservice

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const endpointInterfaceName = "soha0"

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type TunnelPeer struct {
	PublicKey                  string   `json:"publicKey"`
	Endpoint                   string   `json:"endpoint"`
	AllowedIPs                 []string `json:"allowedIPs"`
	PersistentKeepaliveSeconds int      `json:"persistentKeepaliveSeconds"`
}

type TunnelPlan struct {
	PrivateKey string     `json:"-"`
	PublicKey  string     `json:"publicKey"`
	Addresses  []string   `json:"addresses"`
	MTU        int        `json:"mtu"`
	Peer       TunnelPeer `json:"peer"`
	Routes     []string   `json:"routes"`
	DNSServers []string   `json:"dnsServers"`
}

type TunnelReadback struct {
	PublicKey  string     `json:"publicKey,omitempty"`
	Addresses  []string   `json:"addresses,omitempty"`
	MTU        int        `json:"mtu,omitempty"`
	Peer       TunnelPeer `json:"peer,omitempty"`
	Routes     []string   `json:"routes,omitempty"`
	DNSServers []string   `json:"dnsServers,omitempty"`
}

func (plan TunnelPlan) Readback() TunnelReadback {
	return TunnelReadback{PublicKey: plan.PublicKey, Addresses: slices.Clone(plan.Addresses), MTU: plan.MTU, Peer: plan.Peer, Routes: slices.Clone(plan.Routes), DNSServers: slices.Clone(plan.DNSServers)}
}

type System interface {
	Apply(context.Context, TunnelPlan) error
	Readback(context.Context) (TunnelReadback, error)
	Disable(context.Context) error
}

type ApplyOutcome struct {
	Status       string
	ReadbackHash string
	ReasonCode   string
}

type Executor struct {
	mu         sync.Mutex
	privateKey wgtypes.Key
	publicKey  string
	system     System
	previous   *TunnelPlan
}

func NewExecutor(privateKey wgtypes.Key, system System) (*Executor, error) {
	if privateKey == (wgtypes.Key{}) || system == nil {
		return nil, errors.New("endpoint executor dependencies are invalid")
	}
	return &Executor{privateKey: privateKey, publicKey: privateKey.PublicKey().String(), system: system}, nil
}

func (executor *Executor) Apply(ctx context.Context, desired ConfigurationDesired, now time.Time) ApplyOutcome {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if desired.WireGuard == nil {
		if err := executor.disable(ctx); err != nil {
			return ApplyOutcome{Status: "rejected", ReadbackHash: emptyReadbackHash(), ReasonCode: "endpoint_disable_failed"}
		}
		return ApplyOutcome{Status: "applied", ReadbackHash: emptyReadbackHash()}
	}
	plan, err := buildTunnelPlan(desired, executor.privateKey, executor.publicKey, now.UTC())
	if err != nil {
		return ApplyOutcome{Status: "rejected", ReadbackHash: emptyReadbackHash(), ReasonCode: "unsafe_endpoint_configuration"}
	}
	if err := executor.system.Apply(ctx, plan); err != nil {
		return executor.recover(ctx, "endpoint_apply_failed")
	}
	readback, err := executor.system.Readback(ctx)
	if err != nil || !reflect.DeepEqual(readback, plan.Readback()) {
		return executor.recover(ctx, "endpoint_readback_mismatch")
	}
	executor.previous = &plan
	return ApplyOutcome{Status: "applied", ReadbackHash: readbackHash(readback)}
}

func (executor *Executor) Disable(ctx context.Context) error {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	return executor.disable(ctx)
}

func (executor *Executor) disable(ctx context.Context) error {
	err := executor.system.Disable(ctx)
	readback, readErr := executor.system.Readback(ctx)
	if readErr == nil && !reflect.DeepEqual(readback, TunnelReadback{}) {
		readErr = errors.New("endpoint tunnel still exists after disable")
	}
	executor.previous = nil
	return errors.Join(err, readErr)
}

func (executor *Executor) recover(ctx context.Context, reason string) ApplyOutcome {
	if executor.previous == nil {
		_ = executor.disable(ctx)
		return ApplyOutcome{Status: "rejected", ReadbackHash: emptyReadbackHash(), ReasonCode: reason}
	}
	previous := *executor.previous
	if err := executor.system.Apply(ctx, previous); err == nil {
		if readback, readErr := executor.system.Readback(ctx); readErr == nil && reflect.DeepEqual(readback, previous.Readback()) {
			return ApplyOutcome{Status: "rolled-back", ReadbackHash: readbackHash(readback), ReasonCode: reason}
		}
	}
	_ = executor.disable(ctx)
	return ApplyOutcome{Status: "rejected", ReadbackHash: emptyReadbackHash(), ReasonCode: "endpoint_rollback_failed"}
}

func buildTunnelPlan(desired ConfigurationDesired, privateKey wgtypes.Key, publicKey string, now time.Time) (TunnelPlan, error) {
	wg := desired.WireGuard
	if desired.ConfigurationVersion < 1 || desired.PolicyVersion < 1 || !desired.ValidUntil.After(now) || wg.Role != "endpoint" || wg.InterfaceName != endpointInterfaceName || wg.PublicKey != publicKey || wg.FirewallDefault != "deny" || (wg.RoutingMode != "routed" && wg.RoutingMode != "snat") || wg.MTU < 1280 || wg.MTU > 1500 || len(wg.Peers) != 1 {
		return TunnelPlan{}, errors.New("invalid endpoint configuration")
	}
	addresses, err := canonicalPrefixes(wg.Addresses, true)
	if err != nil || len(addresses) == 0 || len(addresses) > 8 {
		return TunnelPlan{}, errors.New("invalid endpoint addresses")
	}
	routes, err := canonicalPrefixes(wg.Routes, false)
	if err != nil || len(routes) == 0 || len(routes) > 256 {
		return TunnelPlan{}, errors.New("invalid endpoint routes")
	}
	peer := wg.Peers[0]
	peerKey, err := wgtypes.ParseKey(peer.PublicKey)
	if err != nil || peerKey == privateKey.PublicKey() || !identifierPattern.MatchString(peer.RuntimeID) || peer.EndpointPort < 1 || peer.EndpointPort > 65535 || peer.PersistentKeepaliveSeconds < 0 || peer.PersistentKeepaliveSeconds > 300 || !validEndpointHost(peer.EndpointHost) {
		return TunnelPlan{}, errors.New("invalid endpoint peer")
	}
	allowedIPs, err := canonicalPrefixes(peer.AllowedIPs, false)
	if err != nil || !slices.Equal(routes, allowedIPs) {
		return TunnelPlan{}, errors.New("peer routes do not match endpoint routes")
	}
	dnsServers := make([]string, 0, len(wg.DNSServers))
	seenDNS := map[string]struct{}{}
	for _, raw := range wg.DNSServers {
		address, parseErr := netip.ParseAddr(raw)
		if parseErr != nil || !address.Is4() || address.String() != raw || !prefixWithinAny(netip.PrefixFrom(address, 32), routes) {
			return TunnelPlan{}, errors.New("invalid endpoint DNS server")
		}
		if _, exists := seenDNS[raw]; exists {
			return TunnelPlan{}, errors.New("duplicate endpoint DNS server")
		}
		seenDNS[raw] = struct{}{}
		dnsServers = append(dnsServers, raw)
	}
	if len(dnsServers) > 8 || !validFirewallRules(wg.FirewallRules, addresses, desired.NetworkLeases, desired.ResourceLeases, routes, now) || !routesCoveredByLeases(routes, desired.NetworkLeases, desired.ResourceLeases, wg.FirewallRules, now) {
		return TunnelPlan{}, errors.New("endpoint authorization scope is invalid")
	}
	slices.Sort(dnsServers)
	return TunnelPlan{PrivateKey: privateKey.String(), PublicKey: publicKey, Addresses: addresses, MTU: wg.MTU, Peer: TunnelPeer{PublicKey: peer.PublicKey, Endpoint: net.JoinHostPort(peer.EndpointHost, fmt.Sprint(peer.EndpointPort)), AllowedIPs: allowedIPs, PersistentKeepaliveSeconds: peer.PersistentKeepaliveSeconds}, Routes: routes, DNSServers: dnsServers}, nil
}

func canonicalPrefixes(raw []string, requireHost bool) ([]string, error) {
	result := make([]string, 0, len(raw))
	seen := map[string]struct{}{}
	for _, value := range raw {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() || prefix.Masked() != prefix || prefix.Bits() == 0 || (requireHost && prefix.Bits() != 32) {
			return nil, errors.New("invalid IPv4 split route")
		}
		canonical := prefix.String()
		if canonical != value {
			return nil, errors.New("non-canonical IPv4 split route")
		}
		if _, exists := seen[canonical]; exists {
			return nil, errors.New("duplicate IPv4 split route")
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
	}
	slices.Sort(result)
	// ponytail: O(n²) is simpler and exact; the contract caps this list at 256 routes.
	for index, raw := range result {
		left := netip.MustParsePrefix(raw)
		for _, candidate := range result[index+1:] {
			right := netip.MustParsePrefix(candidate)
			if left.Contains(right.Addr()) || right.Contains(left.Addr()) {
				return nil, errors.New("overlapping IPv4 split routes")
			}
		}
	}
	return result, nil
}

func routesCoveredByLeases(routes []string, networkLeases []NetworkLease, resourceLeases []ResourceLease, rules []WireGuardFirewallRule, now time.Time) bool {
	for _, route := range routes {
		prefix := netip.MustParsePrefix(route)
		covered := false
		for _, lease := range networkLeases {
			if !identifierPattern.MatchString(lease.ID) || !lease.ExpiresAt.After(now) {
				continue
			}
			for _, cidr := range lease.CIDRs {
				leasePrefix, err := netip.ParsePrefix(cidr)
				if err == nil && leasePrefix.IsValid() && leasePrefix.Addr().Is4() && leasePrefix.Masked() == leasePrefix && leasePrefix.Bits() <= prefix.Bits() && leasePrefix.Contains(prefix.Addr()) {
					covered = true
				}
			}
		}
		for _, rule := range rules {
			if rule.Effect != "allow" || !resourceLeaseLive(resourceLeases, rule.LeaseID, now) {
				continue
			}
			destination := netip.MustParsePrefix(rule.DestinationCIDR)
			if destination.Bits() <= prefix.Bits() && destination.Contains(prefix.Addr()) {
				covered = true
			}
		}
		if !covered {
			return false
		}
	}
	return len(networkLeases)+len(resourceLeases) > 0
}

func validFirewallRules(rules []WireGuardFirewallRule, addresses []string, networkLeases []NetworkLease, resourceLeases []ResourceLease, routes []string, now time.Time) bool {
	if len(rules) > 4096 {
		return false
	}
	type leaseState struct {
		kind   string
		expiry time.Time
	}
	leases := map[string]leaseState{}
	for _, lease := range networkLeases {
		if !identifierPattern.MatchString(lease.ID) || !lease.ExpiresAt.After(now) {
			return false
		}
		leases[lease.ID] = leaseState{kind: "network", expiry: lease.ExpiresAt}
	}
	for _, lease := range resourceLeases {
		if !identifierPattern.MatchString(lease.ID) || !lease.ExpiresAt.After(now) {
			return false
		}
		if _, exists := leases[lease.ID]; exists {
			return false
		}
		leases[lease.ID] = leaseState{kind: "resource", expiry: lease.ExpiresAt}
	}
	seen := map[string]struct{}{}
	phase := 0 // resource allow, protected deny, broad network allow
	for _, rule := range rules {
		if !identifierPattern.MatchString(rule.ID) || !slices.Contains(addresses, rule.SourceCIDR) || (rule.Effect != "allow" && rule.Effect != "deny") || !slices.Contains([]string{"any", "tcp", "udp", "icmp"}, rule.Protocol) {
			return false
		}
		if _, exists := seen[rule.ID]; exists {
			return false
		}
		seen[rule.ID] = struct{}{}
		destination, err := netip.ParsePrefix(rule.DestinationCIDR)
		if err != nil || destination.Masked() != destination || destination.Bits() == 0 || !destination.Addr().Is4() || !prefixWithinAny(destination, routes) {
			return false
		}
		if (rule.Protocol == "any" || rule.Protocol == "icmp") && len(rule.Ports) != 0 {
			return false
		}
		if len(rule.Ports) > 64 {
			return false
		}
		seenPorts := map[int]struct{}{}
		for _, port := range rule.Ports {
			if port < 1 || port > 65535 {
				return false
			}
			if _, exists := seenPorts[port]; exists {
				return false
			}
			seenPorts[port] = struct{}{}
		}
		if rule.Effect == "deny" {
			if phase == 2 || rule.LeaseID != "" || rule.ExpiresAt != nil || rule.Protocol != "any" || len(rule.Ports) != 0 {
				return false
			}
			phase = 1
			continue
		}
		lease, exists := leases[rule.LeaseID]
		if !exists || rule.ExpiresAt == nil || !rule.ExpiresAt.After(now) || rule.ExpiresAt.After(lease.expiry) {
			return false
		}
		if lease.kind == "resource" {
			if phase != 0 || !slices.Contains([]string{"any", "tcp", "udp"}, rule.Protocol) || ((rule.Protocol == "tcp" || rule.Protocol == "udp") && len(rule.Ports) == 0) {
				return false
			}
		} else {
			if rule.Protocol != "any" || len(rule.Ports) != 0 {
				return false
			}
			phase = 2
		}
	}
	return true
}

func resourceLeaseLive(leases []ResourceLease, leaseID string, now time.Time) bool {
	for _, lease := range leases {
		if lease.ID == leaseID && identifierPattern.MatchString(lease.ID) && lease.ExpiresAt.After(now) {
			return true
		}
	}
	return false
}

func prefixWithinAny(prefix netip.Prefix, routes []string) bool {
	for _, raw := range routes {
		route := netip.MustParsePrefix(raw)
		if route.Bits() <= prefix.Bits() && route.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

func validEndpointHost(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "\r\n\t /\\[]") {
		return false
	}
	if address := net.ParseIP(host); address != nil {
		return address.To4() != nil
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func readbackHash(readback TunnelReadback) string {
	raw, _ := json.Marshal(readback)
	digest := sha256.Sum256(raw)
	return fmt.Sprintf("sha256:%x", digest)
}

func emptyReadbackHash() string { return readbackHash(TunnelReadback{}) }
