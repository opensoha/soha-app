package endpointservice

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	api "github.com/opensoha/soha-contracts/gen/go/sohaapi"
	"github.com/opensoha/soha-contracts/proxypolicy"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/opensoha/soha-contracts/proxytransport"
	"golang.org/x/net/proxy"
)

const mihomoGuardProxyName = "soha-egress-proxy"
const mihomoGuardDirectName = "soha-egress-direct"

type mihomoEgress struct {
	nativeGuard               guardedEgress
	shadow                    *nativeShadowLedger
	policy                    atomic.Pointer[gatePolicy]
	connectionsMu             sync.Mutex
	nodeConnections           map[*nodeConnection]bool
	leaseMu                   sync.Mutex
	credentialKey             string
	credentialLease           *atomic.Int64
	projection                atomic.Pointer[api.NetworkProxyEmployeeProjection]
	probeHost                 string
	proxyProbes, directProbes atomic.Int64
	bridges                   map[string]*mihomoSOCKSBridge
	udpSourceUnsupported      bool
	socks                     *proxytransport.SOCKS5Gate
	until                     atomic.Int64
	socksReady                atomic.Bool
	handler                   *proxytransport.Handler
	server                    *http.Server
	proxyPort, directPort     int
	proxySecret, directSecret string
}

func (controller *MihomoController) prepareEgress(configuration *MihomoConfiguration) (func(), error) {
	if !configuration.EnforcementUntil.After(time.Now()) {
		return nil, errors.New("mihomo enforcement lease is missing")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	reserves := []net.Listener{}
	release := func() {
		for _, reserve := range reserves {
			_ = reserve.Close()
		}
	}
	count := 2
	if configuration.DirectProjection != nil {
		if len(configuration.BootstrapNodes) > 128 {
			_ = listener.Close()
			return nil, errors.New("proxy node limit exceeded")
		}
		count += len(configuration.BootstrapNodes)
	}
	for range count {
		reserve, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			release()
			_ = listener.Close()
			return nil, err
		}
		reserves = append(reserves, reserve)
	}
	gate := &mihomoEgress{probeHost: "soha-egress-" + strings.ToLower(rand.Text()) + ".invalid", proxyPort: reserves[0].Addr().(*net.TCPAddr).Port, directPort: reserves[1].Addr().(*net.TCPAddr).Port, proxySecret: rand.Text() + rand.Text(), directSecret: rand.Text() + rand.Text()}
	configuration.GuardNodePorts = map[string]int{}
	if configuration.DirectProjection != nil {
		for i, node := range configuration.BootstrapNodes {
			configuration.GuardNodePorts[node["name"].(string)] = reserves[i+2].Addr().(*net.TCPAddr).Port
		}
	}
	controller.registerNativeBackendsLocked(gate, *configuration)
	if configuration.NativePlan != nil {
		configuration.NativePlan.ProbeHost = gate.probeHost
	}
	gate.nativeGuard = configuration.Egress
	gate.until.Store(configuration.EnforcementUntil.UnixNano())
	gate.refreshProjection(configuration.Projection)
	gate.updatePolicy(*configuration)
	scope, err := proxytransport.NewScopeWithResolver(configuration.Protection.CIDRs, configuration.Protection.Hosts, nativeLookup(*configuration))
	if err != nil {
		release()
		_ = listener.Close()
		return nil, err
	}
	if err := controller.installSOCKSBridges(gate, configuration); err != nil {
		gate.closeBridges()
		release()
		_ = listener.Close()
		return nil, err
	}
	dial := func(ctx context.Context, user, target string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			return nil, err
		}
		if host == gate.probeHost && port == "80" {
			if user == "direct" {
				gate.directProbes.Add(1)
			} else {
				gate.proxyProbes.Add(1)
			}
			return proxytransport.ProbeConnection(), nil
		}
		if err := nativeEgressReady(ctx, *configuration); err != nil {
			return nil, err
		}
		address, err := scope.Resolve(ctx, host)
		if err != nil {
			return nil, err
		}
		nodeID := ""
		for _, id := range configurationNodeIDs(*configuration) {
			if user == projectionNodeUser(id) {
				nodeID = id
				break
			}
		}
		policy := gate.policy.Load()
		if nodeID != "" && !policy.Allowed[nodeID] {
			return nil, errors.New("proxy node revoked")
		}
		action, matched, policyErr := proxypolicy.EvaluateMandatory(policy.Rules, host, []netip.Addr{address})
		if policyErr != nil || matched && string(action.Type) == "reject" {
			return nil, errors.New("mandatory destination policy rejected")
		}
		if matched {
			allowed := false
			switch string(action.Type) {
			case "direct":
				allowed = user == "direct"
			case "node":
				allowed = nodeID == action.TargetID
			case "group":
				for _, g := range policy.Groups {
					if g.GroupID == action.TargetID {
						for _, id := range g.NodeIDs {
							if id == nodeID {
								allowed = true
							}
						}
					}
				}
				if action.TargetID == configuration.SelectorGroup && (nodeID != "" || user == "proxy" && configuration.Projection == nil && configuration.DirectProjection == nil) {
					allowed = true
				}
			}
			if !allowed {
				return nil, errors.New("mandatory route mismatch")
			}
		}
		if configuration.Projection != nil && user != "direct" {
			if nodeID == "" {
				return nil, errors.New("mapped node unauthorized")
			}
			projection := gate.projection.Load()
			conn, err := controller.dialProjection(ctx, projection, nodeID, net.JoinHostPort(host, port))
			if err == nil {
				conn.(*projectionConnection).credentialLease = gate.leaseFor(projection)
			}
			if err != nil {
				return nil, err
			}
			return gate.trackNode(nodeID, conn)
		}

		backend, password := gate.proxyPort, gate.proxySecret
		backendUser := user
		if configuration.DirectProjection != nil && nodeID != "" {
			backend = configuration.GuardNodePorts[nodeID]
			backendUser = "proxy"
		}
		if user == "direct" {
			backend, password = gate.directPort, gate.directSecret
		}
		dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(backend)), &proxy.Auth{User: backendUser, Password: password}, &net.Dialer{Timeout: 5 * time.Second})
		if err != nil {
			return nil, err
		}
		contextDialer, ok := dialer.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("SOCKS backend cannot enforce cancellation")
		}
		conn, err := contextDialer.DialContext(ctx, "tcp", net.JoinHostPort(address.String(), port))
		if err != nil {
			return nil, err
		}
		return gate.trackNode(nodeID, gate.countNativeBackend(conn))
	}
	credentials := map[string]string{"proxy": gate.proxySecret, "direct": gate.directSecret}
	if configuration.Projection != nil || configuration.DirectProjection != nil {
		for _, id := range configurationNodeIDs(*configuration) {
			credentials[projectionNodeUser(id)] = gate.proxySecret
		}
	}
	gate.handler, err = proxytransport.New(credentials, dial, configuration.EnforcementUntil)
	if err != nil {
		gate.closeBridges()
		release()
		_ = listener.Close()
		return nil, err
	}
	if configuration.Projection != nil || configuration.DirectProjection != nil {
		if err := controller.installPacketGate(gate, configuration, credentials, dial); err != nil {
			release()
			_ = listener.Close()
			_ = gate.handler.Close()
			gate.closeBridges()
			return nil, err
		}
	}
	gate.server = &http.Server{Handler: gate.handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() { _ = gate.server.Serve(listener); _ = gate.handler.Close() }()
	if guard, ok := configuration.Egress.(*nativeGuard); ok {
		guard.mu.Lock()
		guard.closeGate = func() { _ = gate.close() }
		guard.mu.Unlock()
	}
	controller.egress = gate
	configuration.GuardPort = listener.Addr().(*net.TCPAddr).Port
	configuration.GuardProxyPort, configuration.GuardDirectPort = gate.proxyPort, gate.directPort
	configuration.GuardProxySecret, configuration.GuardDirectSecret = gate.proxySecret, gate.directSecret
	return release, nil
}

func (gate *mihomoEgress) close() error {
	if gate == nil {
		return nil
	}
	gate.closeBridges()
	var packetErr error
	if gate.socks != nil {
		gate.socksReady.Store(false)
		packetErr = gate.socks.Close()
	}
	return errors.Join(packetErr, gate.handler.Close(), gate.server.Close())
}

func (controller *MihomoController) verifyEgress(ctx context.Context) error {
	gate := controller.egress
	if gate == nil || !gate.handler.Ready() {
		return errors.New("mihomo egress guard is inactive")
	}
	for _, probe := range []struct {
		name    string
		counter *atomic.Int64
	}{{mihomoGuardProxyName, &gate.proxyProbes}, {mihomoGuardDirectName, &gate.directProbes}} {
		before := probe.counter.Load()
		var result struct {
			Delay int `json:"delay"`
		}
		path := "/proxies/" + url.PathEscape(probe.name) + "/delay?timeout=2000&url=" + url.QueryEscape("http://"+gate.probeHost+"/")
		if err := controller.request(ctx, http.MethodGet, path, nil, http.StatusOK, &result); err != nil {
			return err
		}
		if probe.counter.Load() <= before {
			return errors.New("mihomo guard adapter did not reach the authenticated local transport")
		}
	}
	for _, bridge := range gate.bridges {
		before := bridge.probes.Load()
		var result struct {
			Delay int `json:"delay"`
		}
		path := "/proxies/" + url.PathEscape(bridge.nativeName) + "/delay?timeout=2000&url=" + url.QueryEscape("http://"+gate.probeHost+"/")
		if err := controller.request(ctx, http.MethodGet, path, nil, http.StatusOK, &result); err != nil {
			return err
		}
		if bridge.probes.Load() <= before {
			return errors.New("native SOCKS bridge readback failed")
		}
	}
	return nil
}

func projectionCredentialKey(p *api.NetworkProxyEmployeeProjection) string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("%s/%d/%x", p.Credential.CredentialID, p.CredentialEpoch, sha256.Sum256([]byte(p.Credential.Secret)))
}
func projectionCredentialUntil(p *api.NetworkProxyEmployeeProjection) time.Time {
	until := p.Credential.ExpiresAt
	if p.ExpiresAt.Before(until) {
		until = p.ExpiresAt
	}
	return until
}
func (g *mihomoEgress) refreshProjection(p *api.NetworkProxyEmployeeProjection) {
	g.leaseMu.Lock()
	defer g.leaseMu.Unlock()
	if p != nil {
		key := projectionCredentialKey(p)
		if g.credentialLease == nil || key != g.credentialKey {
			g.credentialLease = &atomic.Int64{}
			g.credentialKey = key
		}
		g.credentialLease.Store(projectionCredentialUntil(p).UnixNano())
	}
	g.projection.Store(p)
}
func (g *mihomoEgress) leaseFor(p *api.NetworkProxyEmployeeProjection) *atomic.Int64 {
	g.leaseMu.Lock()
	defer g.leaseMu.Unlock()
	if projectionCredentialKey(p) == g.credentialKey {
		return g.credentialLease
	}
	lease := &atomic.Int64{}
	lease.Store(projectionCredentialUntil(p).UnixNano())
	return lease
}

func (gate *mihomoEgress) closeBridges() {
	for _, bridge := range gate.bridges {
		_ = bridge.gate.Close()
	}
}
