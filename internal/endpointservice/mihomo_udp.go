package endpointservice

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/opensoha/soha-contracts/proxyadapter"
	"github.com/opensoha/soha-contracts/proxypolicy"
	"github.com/opensoha/soha-contracts/proxytransport"
)

func guardNodeType(c MihomoConfiguration) string {
	if c.GuardSOCKSPort > 0 {
		return "socks5"
	}
	return "http"
}
func guardNodePort(c MihomoConfiguration) int {
	if c.GuardSOCKSPort > 0 {
		return c.GuardSOCKSPort
	}
	return c.GuardPort
}
func directNodeUDP(c MihomoConfiguration, id string) bool {
	for _, n := range c.BootstrapNodes {
		kind, _ := n["type"].(string)
		if n["name"] == id && n["udp"] == true {
			return proxyadapter.SupportsMihomoUDP(kind)
		}
	}
	return false
}

// Only the authenticated typed direct projection receives protocol defaults.
// The raw snapshot remains immutable; the same normalization is used for comparison.
func normalizeDirectUDP(node map[string]any) error {
	value, exists := node["udp"]
	if exists {
		if _, ok := value.(bool); !ok {
			return errors.New("invalid native UDP option")
		}
	}
	kind, _ := node["type"].(string)
	node["udp"] = proxyadapter.SupportsMihomoUDP(kind) && (!exists || value == true)
	return nil
}

func (g *mihomoEgress) packetUntil() time.Time {
	until := time.Unix(0, g.until.Load())
	if p := g.projection.Load(); p != nil {
		if limit := projectionCredentialUntil(p); limit.Before(until) {
			until = limit
		}
	}
	if limit := time.Now().Add(5 * time.Minute); limit.Before(until) {
		until = limit
	}
	return until
}
func (g *mihomoEgress) refreshLease(until time.Time) error {
	if !time.Unix(0, g.until.Load()).After(time.Now()) {
		return net.ErrClosed
	}
	g.until.Store(until.UnixNano())
	if err := g.handler.Refresh(until); err != nil {
		return err
	}
	if g.socks != nil {
		if err := g.socks.Refresh(g.packetUntil()); err != nil {
			return err
		}
	}
	for _, bridge := range g.bridges {
		if err := bridge.gate.Refresh(g.packetUntil()); err != nil {
			return err
		}
	}
	return nil
}

// The packet wrapper preserves message boundaries and the shared Refresh API.
// It also pins the authorization checked for the original target to the dialled IP.
type guardedPacketConnection struct {
	net.Conn
	check func(context.Context) error
	until func() time.Time
}

func (c *guardedPacketConnection) authorize() error {
	until := c.until()
	if !until.After(time.Now()) {
		return net.ErrClosed
	}
	if limit := time.Now().Add(5 * time.Second); limit.Before(until) {
		until = limit
	}
	ctx, cancel := context.WithDeadline(context.Background(), until)
	defer cancel()
	return c.check(ctx)
}
func (c *guardedPacketConnection) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err == nil {
		err = c.authorize()
	}
	if err != nil {
		_ = c.Close()
		return 0, err
	}
	return n, nil
}
func (c *guardedPacketConnection) Write(b []byte) (int, error) {
	if err := c.authorize(); err != nil {
		_ = c.Close()
		return 0, err
	}
	return c.Conn.Write(b)
}
func (c *guardedPacketConnection) Refresh(until time.Time) error {
	if limit := c.until(); limit.Before(until) {
		until = limit
	}
	return c.Conn.(interface{ Refresh(time.Time) error }).Refresh(until)
}

func (c *MihomoController) installPacketGate(g *mihomoEgress, configuration *MihomoConfiguration, credentials map[string]string, dial proxytransport.Dial) error {
	scope, err := proxytransport.NewScopeWithResolver(configuration.Protection.CIDRs, configuration.Protection.Hosts, nativeLookup(*configuration))
	if err != nil {
		return err
	}
	nodeUsers := map[string]string{}
	for _, id := range configurationNodeIDs(*configuration) {
		nodeUsers[projectionNodeUser(id)] = id
	}
	check := func(ctx context.Context, user, target string) (netip.Addr, string, error) {
		status := c.ProcessStatus()
		if status.Ownership != "soha_owned" || status.State != "running" || status.PID == 0 {
			return netip.Addr{}, "", errors.New("guarded packet unauthorized")
		}
		nodeID := nodeUsers[user]
		address, err := g.resolveNodeDestination(ctx, scope, nodeID, user == "direct", target)
		return address, nodeID, err
	}
	authorize := func(ctx context.Context, user, target string) error {
		_, _, err := check(ctx, user, target)
		return err
	}
	dialPacket := func(ctx context.Context, user, target string) (net.Conn, error) {
		address, nodeID, err := check(ctx, user, target)
		if err != nil {
			return nil, err
		}
		_, port, _ := net.SplitHostPort(target)
		pinned := net.JoinHostPort(address.String(), port)
		until := g.packetUntil()
		epoch := c.ProcessStatus().ProcessEpoch
		projection := g.projection.Load()
		key := projectionCredentialKey(projection)
		var certificateUntil time.Time
		var conn net.Conn
		if projection != nil && user != "direct" {
			secured, err := c.projectionTLS(ctx, projection, nodeID)
			if err != nil {
				return nil, err
			}
			for _, cert := range secured.ConnectionState().PeerCertificates {
				if certificateUntil.IsZero() || cert.NotAfter.Before(certificateUntil) {
					certificateUntil = cert.NotAfter
				}
			}
			if !certificateUntil.IsZero() && certificateUntil.Before(until) {
				until = certificateUntil
			}
			username, err := proxytransport.EncodeMappedUsername(projection.Credential.CredentialID, nodeID)
			if err != nil {
				_ = secured.Close()
				return nil, errors.New("invalid packet credential")
			}
			conn, err = proxytransport.DialPacketTunnel(ctx, secured, pinned, username, projection.Credential.Secret, until)
			if err != nil {
				_ = secured.Close()
				return nil, err
			}
		} else {
			backend, backendUser, secret := configuration.GuardNodePorts[nodeID], "proxy", g.proxySecret
			if user == "direct" {
				backend, backendUser, secret = g.directPort, "direct", g.directSecret
			} else if configuration.DirectProjection == nil || !directNodeUDP(*configuration, nodeID) {
				return nil, proxytransport.ErrPacketUnsupported
			}
			conn, err = proxytransport.DialSOCKS5UDP(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(backend)), backendUser, secret, pinned, until)
			if err != nil {
				return nil, err
			}
			conn = g.countNativeBackend(conn)
		}
		guarded := &guardedPacketConnection{Conn: conn, until: func() time.Time {
			limit := g.packetUntil()
			if !certificateUntil.IsZero() && certificateUntil.Before(limit) {
				limit = certificateUntil
			}
			return limit
		}}
		guarded.check = func(ctx context.Context) error {
			current, _, err := check(ctx, user, target)
			if err != nil || current != address || c.ProcessStatus().ProcessEpoch != epoch || projectionCredentialKey(g.projection.Load()) != key {
				return errors.New("packet grant changed")
			}
			return nil
		}
		return g.trackNode(nodeID, guarded)
	}
	g.socks, err = proxytransport.NewSOCKS5Gate(credentials, dial, dialPacket, authorize, g.packetUntil())
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = g.socks.Close()
		return err
	}
	configuration.GuardSOCKSPort = listener.Addr().(*net.TCPAddr).Port
	g.socksReady.Store(true)
	go func() {
		_ = g.socks.Serve(listener)
		g.socksReady.Store(false)
		_ = listener.Close()
		_ = g.socks.Close()
	}()
	return nil
}

func (g *mihomoEgress) resolveNodeDestination(ctx context.Context, scope *proxytransport.Scope, nodeID string, direct bool, target string) (netip.Addr, error) {
	deny := func() (netip.Addr, error) { return netip.Addr{}, errors.New("guarded destination unauthorized") }
	if !g.packetUntil().After(time.Now()) {
		return deny()
	}
	host, port, err := net.SplitHostPort(target)
	n, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || n < 1 || n > 65535 {
		return deny()
	}
	if guard, ok := g.nativeGuard.(*nativeGuard); ok {
		if _, err := guard.state(ctx); err != nil {
			return deny()
		}
	}
	address, err := scope.Resolve(ctx, host)
	if err != nil {
		return deny()
	}
	policy := g.policy.Load()
	if policy == nil || !direct && (nodeID == "" || !policy.Allowed[nodeID]) {
		return deny()
	}
	if p := g.projection.Load(); p != nil && !direct {
		found := false
		for _, id := range p.Credential.NodeIDs {
			if id == nodeID {
				found = true
			}
		}
		if !found {
			return deny()
		}
	}
	action, matched, err := proxypolicy.EvaluateMandatory(policy.Rules, host, []netip.Addr{address})
	if err != nil {
		return deny()
	}
	if matched {
		allowed := false
		switch action.Type {
		case "direct":
			allowed = direct
		case "node":
			allowed = nodeID == action.TargetID
		case "group":
			for _, group := range policy.Groups {
				if group.GroupID == action.TargetID {
					for _, id := range group.NodeIDs {
						if id == nodeID {
							allowed = true
						}
					}
				}
			}
		}
		if !allowed {
			return deny()
		}
	}
	return address, nil
}
