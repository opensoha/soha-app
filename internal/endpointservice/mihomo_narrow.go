package endpointservice

import (
	"context"
	"encoding/json"
	"errors"
	api "github.com/opensoha/soha-contracts/gen/go/sohaapi"
	"github.com/opensoha/soha-contracts/proxypolicy"
	"go.yaml.in/yaml/v3"
	"io"
	"net"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type gatePolicy struct {
	Allowed map[string]bool
	Rules   []api.NetworkProxyRule
	Groups  []api.NetworkProxyGroup
}
type nodeConnection struct {
	net.Conn
	gate   *mihomoEgress
	nodeID string
	once   sync.Once
	closed atomic.Bool
}

func (c *nodeConnection) Close() error {
	var err error
	c.once.Do(func() {
		c.closed.Store(true)
		c.gate.connectionsMu.Lock()
		delete(c.gate.nodeConnections, c)
		c.gate.connectionsMu.Unlock()
		err = c.Conn.Close()
	})
	return err
}
func (c *nodeConnection) Refresh(until time.Time) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	if r, ok := c.Conn.(interface{ Refresh(time.Time) error }); ok {
		return r.Refresh(until)
	}
	return c.SetDeadline(until)
}
func (c *nodeConnection) SetDeadline(deadline time.Time) error {
	if c.closed.Load() {
		return nil
	}
	err := c.Conn.SetDeadline(deadline)
	if c.closed.Load() {
		return nil
	}
	return err
}
func (g *mihomoEgress) trackNode(nodeID string, conn net.Conn) (net.Conn, error) {
	g.connectionsMu.Lock()
	defer g.connectionsMu.Unlock()
	policy := g.policy.Load()
	if policy != nil && nodeID != "" && !policy.Allowed[nodeID] {
		conn.Close()
		return nil, errors.New("proxy node revoked")
	}
	c := &nodeConnection{Conn: conn, gate: g, nodeID: nodeID}
	if g.nodeConnections == nil {
		g.nodeConnections = map[*nodeConnection]bool{}
	}
	g.nodeConnections[c] = true
	return c, nil
}
func (g *mihomoEgress) publishPolicy(configuration MihomoConfiguration) []*nodeConnection {
	allowed := map[string]bool{}
	for _, id := range configurationNodeIDs(configuration) {
		allowed[id] = true
	}
	next := &gatePolicy{Allowed: allowed, Rules: append([]api.NetworkProxyRule(nil), configuration.EffectiveRules...), Groups: configurationGroups(configuration)}
	g.connectionsMu.Lock()
	g.policy.Store(next)
	removed := []*nodeConnection{}
	for c := range g.nodeConnections {
		if c.nodeID != "" && !allowed[c.nodeID] {
			removed = append(removed, c)
		}
	}
	g.connectionsMu.Unlock()
	return removed
}
func (g *mihomoEgress) updatePolicy(configuration MihomoConfiguration) {
	for _, conn := range g.publishPolicy(configuration) {
		_ = conn.Close()
	}
}
func subsetIDs(next, old []string) bool {
	allowed := map[string]bool{}
	for _, id := range old {
		allowed[id] = true
	}
	seen := map[string]bool{}
	for _, id := range next {
		if !allowed[id] || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}
func directCanonical(p *api.NetworkProxyDirectProjection) (map[string]map[string]any, error) {
	var document struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	decoder := yaml.NewDecoder(strings.NewReader(p.Content))
	decoder.KnownFields(true)
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("invalid direct backend subset")
	}
	out := map[string]map[string]any{}
	for _, node := range document.Proxies {
		id, ok := node["name"].(string)
		if !ok || out[id] != nil {
			return nil, errors.New("invalid direct backend identity")
		}
		if node["type"] == "socks5" && node["udp"] != false {
			if _, err := parseSOCKSBridgeOptions(node); err != nil {
				if node["udp"] == true {
					return nil, err
				}
				node["udp"] = false
			}
		}
		if err := normalizeDirectUDP(node); err != nil {
			return nil, err
		}
		out[id] = node
	}
	return out, nil
}
func narrowProjection(old, next, template MihomoConfiguration, cold bool) error {
	if old.FailClosed != next.FailClosed || old.SourceType != next.SourceType || old.Mode != next.Mode || old.DeliveryMode != next.DeliveryMode || old.ProfileID != next.ProfileID || old.ProfileRevision != next.ProfileRevision || old.BundleID != next.BundleID || old.SourceRevision != next.SourceRevision || old.OrgRevision != next.OrgRevision || old.ControllerPort != next.ControllerPort || old.MixedPort != next.MixedPort || old.SelectorGroup != next.SelectorGroup || old.DNSMode != next.DNSMode || old.FakeIPRange != next.FakeIPRange || !reflect.DeepEqual(old.Protection, next.Protection) || !reflect.DeepEqual(old.BypassCIDRs, next.BypassCIDRs) || !reflect.DeepEqual(old.BypassHosts, next.BypassHosts) {
		return errors.New("projection narrowing changed endpoint policy")
	}
	ids := configurationNodeIDs(next)
	if !subsetIDs(ids, configurationNodeIDs(old)) {
		return errors.New("projection widening rejected")
	}
	expected, err := proxypolicy.NarrowTargets(configurationGroups(template), projectionRules(template), ids)
	if err != nil {
		return err
	}
	if !sameJSON(expected.Groups, configurationGroups(next)) || !sameJSON(expected.Rules, projectionRules(next)) {
		return errors.New("projection is not deterministic target narrowing")
	}
	if old.Projection != nil && next.Projection != nil {
		a, b := *old.Projection, *next.Projection
		if !subsetIDs(b.Credential.NodeIDs, ids) || !subsetIDs(ids, b.Credential.NodeIDs) {
			return errors.New("narrowing credential scope mismatch")
		}
		if !cold && (a.Credential.CredentialID != b.Credential.CredentialID || a.Credential.Secret != b.Credential.Secret) {
			return errors.New("narrowing changed credential")
		}
		nodes := map[string]api.NetworkProxyEmployeeNode{}
		endpoints := map[string]string{}
		for _, n := range a.Nodes {
			nodes[n.NodeID] = n
		}
		for _, e := range a.Endpoints {
			endpoints[e.EndpointID] = e.URL
		}
		for _, n := range b.Nodes {
			prior, ok := nodes[n.NodeID]
			if !ok || prior.EndpointID != n.EndpointID {
				return errors.New("narrowing changed node transport")
			}
		}
		for _, endpoint := range b.Endpoints {
			if endpoints[endpoint.EndpointID] != endpoint.URL {
				return errors.New("narrowing changed endpoint")
			}
		}
		a.ExpiresAt, b.ExpiresAt = time.Time{}, time.Time{}
		a.Nodes, b.Nodes = nil, nil
		a.Endpoints, b.Endpoints = nil, nil
		a.Groups, b.Groups = nil, nil
		a.Rules, b.Rules = nil, nil
		if cold {
			a.Credential.CredentialID, b.Credential.CredentialID = "", ""
			a.Credential.Secret, b.Credential.Secret = "", ""
		}
		a.Credential.NodeIDs, b.Credential.NodeIDs = nil, nil
		a.Credential.ExpiresAt, b.Credential.ExpiresAt = time.Time{}, time.Time{}
		if !reflect.DeepEqual(a, b) {
			return errors.New("narrowing changed projection identity")
		}
	} else if old.DirectProjection != nil && next.DirectProjection != nil {
		a, b := *old.DirectProjection, *next.DirectProjection
		previous, err := directCanonical(&a)
		if err != nil {
			return err
		}
		current, err := directCanonical(&b)
		if err != nil {
			return err
		}
		for id, node := range current {
			if !reflect.DeepEqual(node, previous[id]) {
				return errors.New("narrowing changed direct backend parameters")
			}
		}
		a.Content, b.Content = "", ""
		a.ExpiresAt, b.ExpiresAt = time.Time{}, time.Time{}
		a.Groups, b.Groups = nil, nil
		a.Rules, b.Rules = nil, nil
		if !reflect.DeepEqual(a, b) {
			return errors.New("narrowing changed direct identity")
		}
	} else {
		return errors.New("projection mode changed")
	}
	return nil
}
func projectionRules(c MihomoConfiguration) []api.NetworkProxyRule {
	if c.Projection != nil {
		return c.Projection.Rules
	}
	if c.DirectProjection != nil {
		return c.DirectProjection.Rules
	}
	return nil
}
func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// Native rules remain a readback snapshot until an explicit full application.
// The independent gate enforces the effective narrowed mandatory rules/scope.
func (e *CoordinatedExecutor) tryNarrowProjection(ctx context.Context, desired ConfigurationDesired, now time.Time) (bool, error) {
	stopped := e.locallyStopped()
	if (!e.mihomoActive && !stopped) || e.proxyDesired == nil || desired.Mihomo == nil || e.narrowTemplate == nil {
		return false, nil
	}
	old := cloneMihomoConfiguration(*e.proxyDesired)
	next := cloneMihomoConfiguration(*desired.Mihomo)
	next.DNSRecords = old.DNSRecords
	next.VPNRoutes = old.VPNRoutes
	next.VPNInterface = old.VPNInterface
	if old.BundleID == "" || old.BundleID != next.BundleID {
		return false, nil
	}
	cold := stopped && old.Projection != nil && !old.Projection.Credential.ExpiresAt.After(now)
	if err := narrowProjection(old, next, *e.narrowTemplate, cold); err != nil {
		return false, err
	}
	c, ok := e.mihomo.(*MihomoController)
	if !ok || c.process == nil {
		return false, errors.New("owned process required for narrowing")
	}
	if !stopped && !old.EnforcementUntil.After(now) {
		return false, errors.New("expired projection cannot narrow")
	}
	if stopped {
		if err := c.Verify(ctx, nil); err != nil {
			return false, err
		}
		verifier, ok := e.wireGuard.(interface {
			Verify(context.Context, ConfigurationDesired, time.Time) ApplyOutcome
		})
		if !ok {
			return false, errors.New("WireGuard readback unavailable")
		}
		if result := verifier.Verify(ctx, desired, now); result.Status != "applied" {
			return false, errors.New("WireGuard readback mismatch")
		}
		next.EnforcementUntil = projectionLease(next, desired.ValidUntil)
		if !next.EnforcementUntil.After(now) {
			return false, errors.New("narrow grant expired")
		}
		if err := e.composePersonal(&next); err != nil {
			return false, err
		}
		e.proxyDesired = &next
		return true, nil
	}
	if e.previousMihomo == nil {
		return false, errors.New("native readback snapshot unavailable")
	}
	native := cloneMihomoConfiguration(e.previousMihomo.Configuration)
	if err := e.bindMihomoVPN(ctx, &native); err != nil {
		return false, err
	}
	if err := c.Verify(ctx, &native); err != nil {
		return false, err
	}
	next.DNSRecords = old.DNSRecords
	next.VPNRoutes = old.VPNRoutes
	next.VPNInterface = old.VPNInterface
	next.EnforcementUntil = projectionLease(next, desired.ValidUntil)
	if !next.EnforcementUntil.After(now) {
		return false, errors.New("narrow grant expired")
	}
	if err := e.composePersonal(&next); err != nil {
		return false, err
	}
	// Keep revoked selections empty. No automatic alternate-node selection.
	if !slices.Contains(configurationNodeIDs(next), old.SelectedProxy) {
		next.SelectedProxy = ""
	} else {
		next.SelectedProxy = old.SelectedProxy
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.process.mu.Lock()
	owned := c.process.cmd != nil && c.process.status.State == "running" && !c.process.stopped
	c.process.mu.Unlock()
	if !owned || c.egress == nil {
		return false, errors.New("owned process changed during narrowing")
	}
	removed := c.egress.publishPolicy(next)
	c.egress.refreshProjection(next.Projection)
	refreshErr := c.egress.refreshLease(next.EnforcementUntil)
	for _, conn := range removed {
		_ = conn.Close()
	}
	if refreshErr != nil {
		return false, refreshErr
	}
	e.proxyDesired = &next
	e.proxyNarrowed = true
	return true, nil
}
