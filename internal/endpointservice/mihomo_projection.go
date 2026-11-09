package endpointservice

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	api "github.com/opensoha/soha-contracts/gen/go/sohaapi"
	"github.com/opensoha/soha-contracts/proxytransport"
	"go.yaml.in/yaml/v3"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

func (client *ControlClient) projectionPath(id string) string {
	return client.origin + "/api/network-control/v1/runtimes/" + url.PathEscape(client.runtimeID) + "/mihomo-profiles/" + url.PathEscape(id) + "/projection"
}
func (client *ControlClient) MihomoProjection(ctx context.Context, id string) (api.NetworkProxyEmployeeProjection, error) {
	var p api.NetworkProxyEmployeeProjection
	if !identifierPattern.MatchString(id) {
		return p, errors.New("invalid projection identity")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.projectionPath(id)+"?processEpoch="+url.QueryEscape(client.processEpoch), nil)
	if err != nil {
		return p, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	response, err := client.http.Do(request)
	if err != nil {
		return p, errors.New("projection unavailable")
	}
	cache := strings.FieldsFunc(strings.ToLower(response.Header.Get("Cache-Control")), func(r rune) bool { return r == ',' || r == ' ' })
	if !slices.Contains(cache, "private") || !slices.Contains(cache, "no-store") {
		response.Body.Close()
		return p, errors.New("projection requires private no-store")
	}
	raw, err := readRuntimeResponse(response, http.StatusOK)
	if err != nil {
		return p, errors.New("projection unavailable")
	}
	defer clear(raw)
	if decodeStrict(raw, &p) != nil || p.RuntimeID != client.runtimeID || p.ProfileID != id || p.ProcessEpoch != client.processEpoch {
		return api.NetworkProxyEmployeeProjection{}, errors.New("invalid projection identity")
	}
	return p, nil
}
func (client *ControlClient) ReportMihomoProjection(ctx context.Context, id string, receipt api.NetworkProxyProjectionApplied) error {
	raw, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.projectionPath(id)+"/receipt", strings.NewReader(string(raw)))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.http.Do(request)
	if err != nil {
		return errors.New("projection receipt unavailable")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent {
		return errors.New("projection receipt rejected")
	}
	return nil
}
func validateEmployeeProjection(p api.NetworkProxyEmployeeProjection, c MihomoConfiguration, runtimeID, deviceID string, until, now time.Time) error {
	if p.SchemaVersion != "proxy-projection/v1" || p.RuntimeID != runtimeID || p.ProfileID != c.ProfileID || p.BundleID != c.BundleID || p.OrgRevision != c.OrgRevision || p.SourceRevision != c.SourceRevision || string(p.DeliveryMode) != c.DeliveryMode || p.Revision <= 0 || p.ActiveRevision != p.Revision || p.ProcessEpoch == "" || !validProjectionHash(p.ProjectionHash) || !p.ExpiresAt.After(now) || p.ExpiresAt.After(until) || p.ExpiresAt.After(now.Add(5*time.Minute)) {
		return errors.New("projection binding invalid")
	}
	cr := p.Credential
	if cr.DeviceID != deviceID || cr.UserID == "" || cr.CredentialID == "" || cr.CredentialEpoch != p.CredentialEpoch || len(cr.Secret) < 16 || len(cr.Secret) > 4096 || !cr.ExpiresAt.After(now) || cr.ExpiresAt.After(p.ExpiresAt) {
		return errors.New("projection credential invalid")
	}
	if len(p.Nodes) < 1 || len(p.Nodes) > 128 || len(p.Endpoints) < 1 || len(p.Endpoints) > 128 || len(p.Groups) > 128 || len(p.Rules) > 10240 || p.DeliveryMode == "gateway" && len(p.Nodes) != 1 {
		return errors.New("projection limits invalid")
	}
	endpoints, nodes, groups := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, e := range p.Endpoints {
		if endpoints[e.EndpointID] || !identifierPattern.MatchString(e.EndpointID) {
			return errors.New("invalid endpoint identity")
		}
		if _, err := projectionEndpoint(e.URL); err != nil {
			return err
		}
		endpoints[e.EndpointID] = true
	}
	for _, n := range p.Nodes {
		if !identifierPattern.MatchString(n.NodeID) || nodes[n.NodeID] || reservedMihomoName(n.NodeID) || n.NodeID == c.SelectorGroup || !endpoints[n.EndpointID] || len(n.Label) == 0 || len(n.Label) > 128 || strings.ContainsAny(n.Label, "\r\n\x00") || !slices.Contains(cr.NodeIDs, n.NodeID) {
			return errors.New("invalid projection node")
		}
		nodes[n.NodeID] = true
	}
	credentialIDs := map[string]bool{}
	for _, id := range cr.NodeIDs {
		if !nodes[id] || credentialIDs[id] {
			return errors.New("projection credential node scope invalid")
		}
		credentialIDs[id] = true
	}
	if len(credentialIDs) != len(nodes) {
		return errors.New("projection credential node scope incomplete")
	}
	for _, g := range p.Groups {
		if g.Type != "select" || len(g.Label) > 128 || strings.ContainsAny(g.Label, "\r\n\x00") {
			return errors.New("projection group type unsupported")
		}
		if !identifierPattern.MatchString(g.GroupID) || nodes[g.GroupID] || groups[g.GroupID] || reservedMihomoName(g.GroupID) || len(g.NodeIDs) == 0 || len(g.NodeIDs) > 128 {
			return errors.New("invalid projection group")
		}
		groups[g.GroupID] = true
		seen := map[string]bool{}
		for _, id := range g.NodeIDs {
			if !nodes[id] || seen[id] {
				return errors.New("invalid group node")
			}
			seen[id] = true
		}
		if g.GroupID == c.SelectorGroup && len(seen) != len(nodes) {
			return errors.New("primary projection group must cover projected inventory")
		}
		if g.SelectedNodeID != "" && !slices.Contains(g.NodeIDs, g.SelectedNodeID) {
			return errors.New("invalid group selection")
		}
	}
	for _, r := range p.Rules {
		if r.Source == "personal" {
			return errors.New("projection cannot overwrite personal rules")
		}
	}
	return nil
}
func validProjectionHash(hash string) bool {
	if len(hash) != 71 || !strings.HasPrefix(hash, "sha256:") {
		return false
	}
	for _, c := range hash[7:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func projectionEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return nil, errors.New("projection endpoint must be internal HTTPS origin")
	}
	if u.Port() != "" {
		n, e := strconv.Atoi(u.Port())
		if e != nil || n < 1 || n > 65535 {
			return nil, errors.New("invalid projection endpoint port")
		}
	}
	return u, nil
}
func projectionNodeUser(id string) string {
	return "node." + base64.RawURLEncoding.EncodeToString([]byte(id))
}
func projectionGuardNodes(c MihomoConfiguration) []map[string]any {
	nodes := make([]map[string]any, 0, len(c.Projection.Nodes))
	for _, n := range c.Projection.Nodes {
		nodes = append(nodes, map[string]any{"name": n.NodeID, "type": guardNodeType(c), "server": "127.0.0.1", "port": guardNodePort(c), "username": projectionNodeUser(n.NodeID), "password": c.GuardProxySecret, "udp": c.GuardSOCKSPort > 0})
	}
	return nodes
}
func (c *MihomoController) projectionTLS(ctx context.Context, p *api.NetworkProxyEmployeeProjection, nodeID string) (*tls.Conn, error) {
	var endpointID, rawURL string
	for _, n := range p.Nodes {
		if n.NodeID == nodeID {
			endpointID = n.EndpointID
		}
	}
	for _, e := range p.Endpoints {
		if e.EndpointID == endpointID && endpointID != "" {
			rawURL = e.URL
		}
	}
	u, err := projectionEndpoint(rawURL)
	if err != nil {
		return nil, err
	}
	addresses, err := nativeLookup(MihomoConfiguration{Egress: c.nativeEgress})(ctx, "ip", u.Hostname())
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("internal endpoint unavailable")
	}
	for _, a := range addresses {
		if !a.IsPrivate() && !a.IsLoopback() {
			return nil, errors.New("internal endpoint resolved outside private network")
		}
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	var conn net.Conn
	if guard, ok := c.nativeEgress.(*nativeGuard); ok && addresses[0].IsLoopback() {
		endpoint, parseErr := netip.ParseAddrPort(net.JoinHostPort(addresses[0].String(), port))
		if parseErr != nil {
			return nil, parseErr
		}
		conn, err = guard.dialInternal(ctx, "tcp", endpoint)
	} else {
		conn, err = nativeDial(MihomoConfiguration{Egress: c.nativeEgress}, ctx, "tcp", net.JoinHostPort(addresses[0].String(), port))
	}
	if err != nil {
		return nil, errors.New("internal endpoint unavailable")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
	if c.transportTLS != nil {
		config = c.transportTLS.Clone()
		config.ServerName = u.Hostname()
	}
	secured := tls.Client(conn, config)
	if err = secured.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, errors.New("internal endpoint TLS rejected")
	}
	return secured, nil
}
func (c *MihomoController) dialProjection(ctx context.Context, p *api.NetworkProxyEmployeeProjection, nodeID, target string) (net.Conn, error) {
	secured, err := c.projectionTLS(ctx, p, nodeID)
	if err != nil {
		return nil, err
	}
	username, err := proxytransport.EncodeMappedUsername(p.Credential.CredentialID, nodeID)
	if err != nil {
		secured.Close()
		return nil, errors.New("invalid scoped credential identity")
	}
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = secured.SetDeadline(deadline)
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: target}, Host: target, Header: http.Header{}}
	request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+p.Credential.Secret)))
	if err = request.Write(secured); err != nil {
		secured.Close()
		return nil, errors.New("internal endpoint handshake failed")
	}
	bounded := &projectionHeaderReader{reader: secured, remaining: 16 << 10, header: true}
	reader := bufio.NewReader(bounded)
	response, err := http.ReadResponse(reader, request)
	if err != nil || response.StatusCode != http.StatusOK {
		secured.Close()
		return nil, errors.New("internal endpoint authorization rejected")
	}
	bounded.header = false
	_ = secured.SetDeadline(time.Time{})
	until := p.Credential.ExpiresAt
	if p.ExpiresAt.Before(until) {
		until = p.ExpiresAt
	}
	return &projectionConnection{Conn: secured, reader: reader, validUntil: until}, nil
}

type projectionHeaderReader struct {
	reader    io.Reader
	remaining int
	header    bool
}

func (r *projectionHeaderReader) Read(p []byte) (int, error) {
	if r.header {
		if r.remaining <= 0 {
			return 0, errors.New("proxy response headers exceed limit")
		}
		if len(p) > r.remaining {
			p = p[:r.remaining]
		}
	}
	n, e := r.reader.Read(p)
	if r.header {
		r.remaining -= n
	}
	return n, e
}

type projectionConnection struct {
	net.Conn
	reader          *bufio.Reader
	validUntil      time.Time
	credentialLease *atomic.Int64
}

func (c *projectionConnection) SetDeadline(deadline time.Time) error {
	until := c.validUntil
	if c.credentialLease != nil {
		until = time.Unix(0, c.credentialLease.Load())
	}
	if deadline.IsZero() || until.Before(deadline) {
		deadline = until
	}
	return c.Conn.SetDeadline(deadline)
}
func (c *projectionConnection) Read(p []byte) (int, error) { return c.reader.Read(p) }

type projectionFloor struct {
	CredentialID        string    `json:"credentialId,omitempty"`
	CredentialExpiresAt time.Time `json:"credentialExpiresAt,omitempty"`
	CredentialKey       string    `json:"credentialKey,omitempty"`
	ProcessEpoch        string    `json:"processEpoch,omitempty"`
	AllowedNodes        []string  `json:"allowedNodes,omitempty"`
	CeilingKnown        bool      `json:"ceilingKnown,omitempty"`
	DeliveryMode        string    `json:"deliveryMode"`
	BundleID            string    `json:"bundleId"`
	Revision            int64     `json:"revision"`
	OrgRevision         int64     `json:"orgRevision"`
	SourceRevision      int64     `json:"sourceRevision"`
	CredentialEpoch     int64     `json:"credentialEpoch"`
	Hash                string    `json:"hash"`
}

func rememberEmployeeProjection(statePath string, p api.NetworkProxyEmployeeProjection) error {
	if statePath == "" {
		return errors.New("projection floor storage unavailable")
	}
	path := filepath.Join(filepath.Dir(statePath), "mihomo-projection-floor.json")
	records := map[string]projectionFloor{}
	raw, err := readFileBounded(path, 1<<20, true)
	if err == nil {
		plain, openErr := unprotectSecret(raw, "Soha projection revision floor")
		if openErr != nil {
			return errors.New("projection floor invalid")
		}
		err = decodeStrict(plain, &records)
		clear(plain)
		if err != nil {
			return errors.New("projection floor invalid")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("projection floor unavailable")
	}
	previous, exists := records[p.ProfileID]
	ids := []string{}
	for _, n := range p.Nodes {
		ids = append(ids, n.NodeID)
	}
	if exists && previous.CeilingKnown && previous.ProcessEpoch == p.ProcessEpoch && previous.BundleID == p.BundleID && previous.Revision == p.Revision && previous.Hash == p.ProjectionHash && previous.CredentialEpoch == p.CredentialEpoch {
		if p.Credential.CredentialID != "" && previous.CredentialKey != "" {
			expired := !previous.CredentialExpiresAt.IsZero() && !previous.CredentialExpiresAt.After(time.Now())
			if previous.CredentialKey != projectionCredentialKey(&p) && !expired {
				return errors.New("live projection credential identity changed")
			}
			if expired && (previous.CredentialKey == projectionCredentialKey(&p) || previous.CredentialID == p.Credential.CredentialID) {
				return errors.New("expired projection credential cannot revive")
			}
		}

		if !subsetIDs(ids, previous.AllowedNodes) {
			return errors.New("projection node ceiling cannot widen")
		}
	}
	if exists {
		if p.OrgRevision < previous.OrgRevision || p.SourceRevision < previous.SourceRevision || string(p.DeliveryMode) == previous.DeliveryMode && p.CredentialEpoch < previous.CredentialEpoch {
			return errors.New("projection rollback rejected")
		}
		if p.BundleID == previous.BundleID && (p.Revision < previous.Revision || p.Revision == previous.Revision && (p.ProjectionHash != previous.Hash || p.OrgRevision != previous.OrgRevision || p.SourceRevision != previous.SourceRevision || string(p.DeliveryMode) != previous.DeliveryMode)) {
			return errors.New("projection revision reused")
		}
	}
	records[p.ProfileID] = projectionFloor{CredentialID: p.Credential.CredentialID, CredentialExpiresAt: p.Credential.ExpiresAt, CredentialKey: projectionCredentialKey(&p), ProcessEpoch: p.ProcessEpoch, AllowedNodes: ids, CeilingKnown: true, DeliveryMode: string(p.DeliveryMode), BundleID: p.BundleID, Revision: p.Revision, OrgRevision: p.OrgRevision, SourceRevision: p.SourceRevision, CredentialEpoch: p.CredentialEpoch, Hash: p.ProjectionHash}
	raw, err = json.Marshal(records)
	if err != nil {
		return err
	}
	return saveProtectedState(path, raw, "Soha projection revision floor")
}

func (client *ControlClient) MihomoDirectProjection(ctx context.Context, id string) (api.NetworkProxyDirectProjection, error) {
	var p api.NetworkProxyDirectProjection
	if !identifierPattern.MatchString(id) {
		return p, errors.New("invalid direct projection identity")
	}
	endpoint := strings.TrimSuffix(client.projectionPath(id), "projection") + "direct-projection?processEpoch=" + url.QueryEscape(client.processEpoch)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return p, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	response, err := client.http.Do(request)
	if err != nil {
		return p, errors.New("direct projection unavailable")
	}
	cache := strings.FieldsFunc(strings.ToLower(response.Header.Get("Cache-Control")), func(r rune) bool { return r == ',' || r == ' ' })
	if !slices.Contains(cache, "private") || !slices.Contains(cache, "no-store") {
		response.Body.Close()
		return p, errors.New("direct projection requires private no-store")
	}
	raw, err := readRuntimeResponseLimit(response, http.StatusOK, 2<<20)
	if err != nil {
		return p, errors.New("direct projection unavailable")
	}
	defer clear(raw)
	if decodeStrict(raw, &p) != nil || p.RuntimeID != client.runtimeID || p.ProfileID != id || p.ProcessEpoch != client.processEpoch {
		return api.NetworkProxyDirectProjection{}, errors.New("direct projection identity invalid")
	}
	return p, nil
}
func validateDirectProjection(p api.NetworkProxyDirectProjection, c MihomoConfiguration, runtimeID string, until, now time.Time) error {
	if p.SchemaVersion != "proxy-direct/v1" || p.RuntimeID != runtimeID || p.ProfileID != c.ProfileID || p.BundleID != c.BundleID || p.OrgRevision != c.OrgRevision || p.SourceRevision != c.SourceRevision || p.DeliveryMode != "direct_subscription" || c.DeliveryMode != "direct_subscription" || p.UpstreamDisclosure != "upstream_parameters" || p.Format != "mihomo_yaml" || p.Revision <= 0 || p.ActiveRevision != p.Revision || !validProjectionHash(p.ProjectionHash) || p.ProcessEpoch == "" || !p.ExpiresAt.After(now) || p.ExpiresAt.After(until) || p.ExpiresAt.After(now.Add(5*time.Minute)) || len(p.Content) == 0 || len(p.Content) > 1<<20 || len(p.Groups) > 2048 || len(p.Rules) > 10240 {
		return errors.New("direct projection binding invalid")
	}
	var content struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	decoder := yaml.NewDecoder(strings.NewReader(p.Content))
	decoder.KnownFields(true)
	if decoder.Decode(&content) != nil || decoder.Decode(&struct{}{}) != io.EOF || len(content.Proxies) == 0 || len(content.Proxies) > 128 {
		return errors.New("direct projection proxy subset invalid")
	}
	nodes, groups := map[string]bool{}, map[string]bool{}
	for _, node := range content.Proxies {
		id, ok := node["name"].(string)
		if !ok || !validMihomoName(id) || nodes[id] || reservedMihomoName(id) || id == c.SelectorGroup {
			return errors.New("direct projection node invalid")
		}
		nodes[id] = true
	}
	for _, g := range p.Groups {
		if g.Type != "select" {
			return errors.New("direct group type unsupported")
		}
		if !identifierPattern.MatchString(g.GroupID) || groups[g.GroupID] || nodes[g.GroupID] || reservedMihomoName(g.GroupID) || len(g.NodeIDs) == 0 || len(g.NodeIDs) > 128 {
			return errors.New("direct group invalid")
		}
		groups[g.GroupID] = true
		seen := map[string]bool{}
		for _, id := range g.NodeIDs {
			if !nodes[id] || seen[id] {
				return errors.New("direct group reference invalid")
			}
			seen[id] = true
		}
		if g.GroupID == c.SelectorGroup && len(seen) != len(nodes) {
			return errors.New("primary direct group must cover projected inventory")
		}
		if g.SelectedNodeID != "" && !slices.Contains(g.NodeIDs, g.SelectedNodeID) {
			return errors.New("direct group selection invalid")
		}
	}
	for _, r := range p.Rules {
		if r.Source == "personal" {
			return errors.New("direct projection cannot replace personal drafts")
		}
	}
	return nil
}
func directProjectionTag(p api.NetworkProxyDirectProjection) api.NetworkProxyEmployeeProjection {
	tag := api.NetworkProxyEmployeeProjection{DeliveryMode: "direct_subscription", RuntimeID: p.RuntimeID, ProfileID: p.ProfileID, BundleID: p.BundleID, Revision: p.Revision, SourceRevision: p.SourceRevision, OrgRevision: p.OrgRevision, ProjectionHash: p.ProjectionHash, ProcessEpoch: p.ProcessEpoch}
	for _, id := range configurationNodeIDs(MihomoConfiguration{DirectProjection: &p}) {
		tag.Nodes = append(tag.Nodes, api.NetworkProxyEmployeeNode{NodeID: id})
	}
	return tag
}

func directRawName(id string) string {
	return fmt.Sprintf("soha-owned-outbound-%x", sha256.Sum256([]byte(id)))
}
func configurationGroups(c MihomoConfiguration) []api.NetworkProxyGroup {
	if c.Projection != nil {
		return c.Projection.Groups
	}
	if c.DirectProjection != nil {
		return c.DirectProjection.Groups
	}
	return nil
}
func configurationNodeIDs(c MihomoConfiguration) []string {
	ids := []string{}
	if c.DirectProjection != nil && len(c.BootstrapNodes) == 0 {
		var content struct {
			Proxies []struct {
				Name string `yaml:"name"`
			} `yaml:"proxies"`
		}
		if yaml.Unmarshal([]byte(c.DirectProjection.Content), &content) == nil {
			for _, node := range content.Proxies {
				ids = append(ids, node.Name)
			}
		}
		return ids
	}
	if c.Projection != nil {
		for _, n := range c.Projection.Nodes {
			ids = append(ids, n.NodeID)
		}
	} else {
		for _, n := range c.BootstrapNodes {
			if id, ok := n["name"].(string); ok {
				ids = append(ids, id)
			}
		}
	}
	return ids
}
func directGuardNodes(c MihomoConfiguration) []map[string]any {
	nodes := []map[string]any{}
	for _, id := range configurationNodeIDs(c) {
		nodes = append(nodes, map[string]any{"name": id, "type": guardNodeType(c), "server": "127.0.0.1", "port": guardNodePort(c), "username": projectionNodeUser(id), "password": c.GuardProxySecret, "udp": c.GuardSOCKSPort > 0 && directNodeUDP(c, id)})
	}
	return nodes
}
