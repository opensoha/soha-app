package endpointservice

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/opensoha/soha-contracts/proxytransport"
)

type mihomoSOCKSUpstream struct {
	ip           netip.Addr
	user, secret string
	connect      proxytransport.UpstreamConnect
}
type mihomoSOCKSBridge struct {
	gate       *proxytransport.SOCKS5Gate
	node       map[string]any
	nativeName string
	probes     atomic.Int64
}

// Source TLS is independent of the internal projection CA. Unsupported native
// TLS/plugin options cannot silently lose their semantics during the rewrite.
type socksBridgeOptions struct {
	user, secret string
	secure       bool
	tlsConfig    *tls.Config
}

func parseSOCKSBridgeOptions(node map[string]any) (socksBridgeOptions, error) {
	var options socksBridgeOptions
	allowed := map[string]bool{}
	for _, key := range []string{"name", "type", "server", "port", "username", "password", "udp", "tls", "sni", "servername", "alpn", "skip-cert-verify"} {
		allowed[key] = true
	}
	for key := range node {
		if !allowed[key] {
			return options, proxytransport.ErrPacketUnsupported
		}
	}
	if node["skip-cert-verify"] != nil && node["skip-cert-verify"] != false {
		return options, proxytransport.ErrPacketUnsupported
	}
	host, ok := node["server"].(string)
	if !ok {
		return options, proxytransport.ErrPacketUnsupported
	}
	for key, dst := range map[string]*string{"username": &options.user, "password": &options.secret} {
		if value, exists := node[key]; exists {
			var ok bool
			*dst, ok = value.(string)
			if !ok {
				return options, proxytransport.ErrPacketUnsupported
			}
		}
	}
	if len(options.user) > 255 || len(options.secret) > 255 || options.user == "" && options.secret != "" {
		return options, proxytransport.ErrPacketUnsupported
	}
	secure := false
	if value, exists := node["tls"]; exists {
		var ok bool
		secure, ok = value.(bool)
		if !ok {
			return options, proxytransport.ErrPacketUnsupported
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if a, aok := node["servername"]; aok {
		if b, bok := node["sni"]; bok {
			first, firstOK := a.(string)
			second, secondOK := b.(string)
			if !firstOK || !secondOK || first != second {
				return options, proxytransport.ErrPacketUnsupported
			}
		}
	}
	for _, key := range []string{"servername", "sni"} {
		if value, exists := node[key]; exists {
			name, ok := value.(string)
			if !ok || name == "" {
				return options, proxytransport.ErrPacketUnsupported
			}
			tlsConfig.ServerName = name
		}
	}
	if value, exists := node["alpn"]; exists {
		values, ok := value.([]any)
		if !ok {
			return options, proxytransport.ErrPacketUnsupported
		}
		for _, value := range values {
			protocol, ok := value.(string)
			if !ok || len(protocol) < 1 || len(protocol) > 255 {
				return options, proxytransport.ErrPacketUnsupported
			}
			tlsConfig.NextProtos = append(tlsConfig.NextProtos, protocol)
		}
	}
	options.secure, options.tlsConfig = secure, tlsConfig
	return options, nil
}

func newMihomoSOCKSUpstream(node map[string]any, scope *proxytransport.Scope, egress ...guardedEgress) (mihomoSOCKSUpstream, error) {
	var source mihomoSOCKSUpstream
	options, err := parseSOCKSBridgeOptions(node)
	if err != nil {
		return source, err
	}
	source.user, source.secret = options.user, options.secret
	host := node["server"].(string)
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return source, errors.New("SOCKS source is not pinned")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err = scope.Resolve(ctx, ip.String()); err != nil {
		return source, errors.New("SOCKS source rejected")
	}
	port, err := strconv.Atoi(fmt.Sprint(node["port"]))
	if err != nil || port < 1 || port > 65535 {
		return source, errors.New("invalid SOCKS source port")
	}
	address := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	source.ip = ip
	source.connect = func(ctx context.Context) (net.Conn, error) {
		conn, err := nativeDial(bootstrapConfiguration(egress), ctx, "tcp", address)
		if err != nil {
			return nil, errors.New("SOCKS source unavailable")
		}
		if !options.secure {
			return conn, nil
		}
		secured := tls.Client(conn, options.tlsConfig.Clone())
		if err = secured.HandshakeContext(ctx); err != nil {
			_ = secured.Close()
			return nil, errors.New("SOCKS source TLS rejected")
		}
		var until time.Time
		for _, cert := range secured.ConnectionState().PeerCertificates {
			if until.IsZero() || cert.NotAfter.Before(until) {
				until = cert.NotAfter
			}
		}
		return &sourceLeaseConnection{Conn: secured, until: until}, nil
	}
	return source, nil
}

type sourceLeaseConnection struct {
	net.Conn
	until time.Time
}

type bridgeTCPConnection struct {
	net.Conn
	limit func() time.Time
}

func (c *bridgeTCPConnection) SetDeadline(until time.Time) error {
	if limit := c.limit(); until.IsZero() || limit.Before(until) {
		until = limit
	}
	return c.Conn.(interface{ Refresh(time.Time) error }).Refresh(until)
}

func (c *sourceLeaseConnection) SetDeadline(until time.Time) error {
	if until.IsZero() || c.until.Before(until) {
		until = c.until
	}
	return c.Conn.SetDeadline(until)
}
func (c *sourceLeaseConnection) SetReadDeadline(until time.Time) error {
	if until.IsZero() || c.until.Before(until) {
		until = c.until
	}
	return c.Conn.SetReadDeadline(until)
}
func (c *sourceLeaseConnection) SetWriteDeadline(until time.Time) error {
	if until.IsZero() || c.until.Before(until) {
		until = c.until
	}
	return c.Conn.SetWriteDeadline(until)
}

func (c *MihomoController) installSOCKSBridge(g *mihomoEgress, configuration *MihomoConfiguration, nodeID string, source mihomoSOCKSUpstream) (*mihomoSOCKSBridge, error) {
	bridge := &mihomoSOCKSBridge{nativeName: nodeID}
	if configuration.DirectProjection != nil {
		bridge.nativeName = directRawName(nodeID)
	}
	scope, err := proxytransport.NewScopeWithResolver(configuration.Protection.CIDRs, configuration.Protection.Hosts, nativeLookup(*configuration))
	if err != nil {
		return nil, err
	}
	check := func(ctx context.Context, target string) (netip.Addr, error) {
		return g.resolveNodeDestination(ctx, scope, nodeID, false, target)
	}
	dial := func(packet bool) proxytransport.Dial {
		return func(ctx context.Context, _ string, target string) (net.Conn, error) {
			if !packet && target == net.JoinHostPort(g.probeHost, "80") {
				bridge.probes.Add(1)
				return proxytransport.ProbeConnection(), nil
			}
			address, err := check(ctx, target)
			if err != nil {
				return nil, err
			}
			_, port, _ := net.SplitHostPort(target)
			pinned := net.JoinHostPort(address.String(), port)
			var certificateUntil time.Time
			connect := func(ctx context.Context) (net.Conn, error) {
				conn, err := source.connect(ctx)
				if bounded, ok := conn.(*sourceLeaseConnection); ok {
					certificateUntil = bounded.until
				}
				return conn, err
			}
			until := func() time.Time {
				limit := g.packetUntil()
				if !certificateUntil.IsZero() && certificateUntil.Before(limit) {
					limit = certificateUntil
				}
				return limit
			}
			var conn net.Conn
			if packet {
				if configuration.Egress != nil {
					conn, err = proxytransport.DialSOCKS5UpstreamUDPWithDial(ctx, connect, func(ctx context.Context, remote netip.AddrPort) (*net.UDPConn, error) {
						raw, err := configuration.Egress.DialPinned(ctx, "udp", remote)
						if err != nil {
							return nil, err
						}
						udp, ok := raw.(*net.UDPConn)
						if !ok {
							raw.Close()
							return nil, errors.New("native UDP socket unavailable")
						}
						return udp, nil
					}, source.ip, source.user, source.secret, pinned, until())
				} else {
					conn, err = proxytransport.DialSOCKS5UpstreamUDP(ctx, connect, source.ip, source.user, source.secret, pinned, until())
				}
			} else {
				conn, err = proxytransport.DialSOCKS5UpstreamTCP(ctx, connect, source.ip, source.user, source.secret, pinned, until())
			}
			if err != nil {
				return nil, errors.New("approved SOCKS source refused transport")
			}
			if packet {
				epoch := c.ProcessStatus().ProcessEpoch
				guarded := &guardedPacketConnection{Conn: conn, until: until, check: func(ctx context.Context) error {
					current, err := check(ctx, target)
					status := c.ProcessStatus()
					if err != nil || current != address || status.Ownership != "soha_owned" || status.State != "running" || status.ProcessEpoch != epoch {
						return errors.New("SOCKS packet grant changed")
					}
					return nil
				}}
				return g.trackNode(nodeID, guarded)
			}
			return g.trackNode(nodeID, &bridgeTCPConnection{Conn: conn, limit: until})
		}
	}
	user, secret := rand.Text(), rand.Text()+rand.Text()
	authorize := func(ctx context.Context, _ string, target string) error {
		_, err := check(ctx, target)
		status := c.ProcessStatus()
		if err != nil || status.Ownership != "soha_owned" || status.State != "running" || status.PID == 0 {
			return errors.New("SOCKS packet unauthorized")
		}
		return nil
	}
	gate, err := proxytransport.NewSOCKS5Gate(map[string]string{user: secret}, dial(false), proxytransport.DialPacket(dial(true)), authorize, g.packetUntil())
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = gate.Close()
		return nil, err
	}
	bridge.gate = gate
	bridge.node = map[string]any{"name": nodeID, "type": "socks5", "server": "127.0.0.1", "port": listener.Addr().(*net.TCPAddr).Port, "username": user, "password": secret, "udp": true}
	go func() { _ = gate.Serve(listener); _ = listener.Close(); _ = gate.Close() }()
	return bridge, nil
}

func (c *MihomoController) installSOCKSBridges(g *mihomoEgress, configuration *MihomoConfiguration) error {
	scope, err := proxytransport.NewScopeWithResolver(configuration.Protection.CIDRs, configuration.Protection.Hosts, nativeLookup(*configuration))
	if err != nil {
		return err
	}
	for i, node := range configuration.BootstrapNodes {
		if node["type"] != "socks5" || node["udp"] != true {
			continue
		}
		id, _ := node["name"].(string)
		sourceNode := node
		if original := configuration.GuardSourceNodes[id]; original != nil {
			sourceNode = map[string]any{}
			for key, value := range original {
				sourceNode[key] = value
			}
			sourceNode["server"], sourceNode["port"] = node["server"], node["port"]
		}
		source, err := newMihomoSOCKSUpstream(sourceNode, scope, configuration.Egress)
		if err != nil {
			if errors.Is(err, proxytransport.ErrPacketUnsupported) && !configuration.GuardUDPExplicit[id] {
				copy := map[string]any{}
				for key, value := range node {
					copy[key] = value
				}
				copy["udp"] = false
				configuration.BootstrapNodes[i] = copy
				g.udpSourceUnsupported = true
				continue
			}
			return err
		}
		bridge, err := c.installSOCKSBridge(g, configuration, id, source)
		if err != nil {
			return err
		}
		if g.bridges == nil {
			g.bridges = map[string]*mihomoSOCKSBridge{}
		}
		g.bridges[id] = bridge
		configuration.BootstrapNodes[i] = bridge.node
	}
	return nil
}
