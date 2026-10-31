package endpointservice

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/opensoha/soha-contracts/proxytransport"
	"golang.org/x/net/proxy"
)

const mihomoGuardProxyName = "soha-egress-proxy"
const mihomoGuardDirectName = "soha-egress-direct"

type mihomoEgress struct {
	probeHost                 string
	proxyProbes, directProbes atomic.Int64
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
	for range 2 {
		reserve, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			release()
			_ = listener.Close()
			return nil, err
		}
		reserves = append(reserves, reserve)
	}
	gate := &mihomoEgress{probeHost: "soha-egress-" + strings.ToLower(rand.Text()) + ".invalid", proxyPort: reserves[0].Addr().(*net.TCPAddr).Port, directPort: reserves[1].Addr().(*net.TCPAddr).Port, proxySecret: rand.Text() + rand.Text(), directSecret: rand.Text() + rand.Text()}
	scope, err := proxytransport.NewScope(configuration.Protection.CIDRs, configuration.Protection.Hosts)
	if err != nil {
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
		address, err := scope.Resolve(ctx, host)
		if err != nil {
			return nil, err
		}
		backend, password := gate.proxyPort, gate.proxySecret
		if user == "direct" {
			backend, password = gate.directPort, gate.directSecret
		}
		dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(backend)), &proxy.Auth{User: user, Password: password}, &net.Dialer{Timeout: 5 * time.Second})
		if err != nil {
			return nil, err
		}
		contextDialer, ok := dialer.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("SOCKS backend cannot enforce cancellation")
		}
		return contextDialer.DialContext(ctx, "tcp", net.JoinHostPort(address.String(), port))
	}
	gate.handler, err = proxytransport.New(map[string]string{"proxy": gate.proxySecret, "direct": gate.directSecret}, dial, configuration.EnforcementUntil)
	if err != nil {
		release()
		_ = listener.Close()
		return nil, err
	}
	gate.server = &http.Server{Handler: gate.handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() { _ = gate.server.Serve(listener); _ = gate.handler.Close() }()
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
	return errors.Join(gate.handler.Close(), gate.server.Close())
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
	return nil
}
