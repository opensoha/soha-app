package endpointservice

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// This loopback controller reads the rendered configuration and routes delay
// probes through the real authenticated guard. It never contacts a proxy node.
type mihomoControllerFixture struct {
	mu          sync.Mutex
	secret      string
	document    mihomoFixtureDocument
	payload     string
	selected    string
	failReset   bool
	connections bool
	probes      int
}

type mihomoFixtureProxy struct {
	Name, Type, Server, Username, Password string
	Port                                   int
}

type mihomoFixtureDocument struct {
	MixedPort    int    `yaml:"mixed-port"`
	HTTPPort     int    `yaml:"port"`
	SOCKSPort    int    `yaml:"socks-port"`
	RedirectPort int    `yaml:"redir-port"`
	TProxyPort   int    `yaml:"tproxy-port"`
	BindAddress  string `yaml:"bind-address"`
	AllowLAN     bool   `yaml:"allow-lan"`
	Mode         string
	IPv6         bool
	Tun          struct{ Enable bool }
	Proxies      []mihomoFixtureProxy
	ProxyGroups  []struct {
		Name, Type string
		Proxies    []string
	} `yaml:"proxy-groups"`
	Rules []string
}

func newMihomoControllerFixture(t *testing.T, secret string) (*httptest.Server, *mihomoControllerFixture) {
	t.Helper()
	fixture := &mihomoControllerFixture{secret: secret}
	server := httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
	t.Cleanup(server.Close)
	return server, fixture
}

func (f *mihomoControllerFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+f.secret {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.Method + " " + r.URL.Path {
	case "PUT /configs":
		if f.failReset {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var body struct{ Payload string }
		if json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&body) != nil || yaml.Unmarshal([]byte(body.Payload), &f.document) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.payload, f.selected = body.Payload, ""
		w.WriteHeader(http.StatusNoContent)
	case "PATCH /configs":
		var body struct {
			MixedPort int `json:"mixed-port"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.document.MixedPort = body.MixedPort
		w.WriteHeader(http.StatusNoContent)
	case "GET /configs":
		d := f.document
		_ = json.NewEncoder(w).Encode(map[string]any{"mixed-port": d.MixedPort, "port": d.HTTPPort, "socks-port": d.SOCKSPort, "redir-port": d.RedirectPort, "tproxy-port": d.TProxyPort, "bind-address": d.BindAddress, "allow-lan": d.AllowLAN, "mode": d.Mode, "ipv6": d.IPv6, "tun": map[string]bool{"enable": d.Tun.Enable}})
	case "GET /rules":
		rules := []mihomoRule{}
		for _, raw := range f.document.Rules {
			parts := strings.Split(raw, ",")
			types := map[string]string{"IP-CIDR": "IPCIDR", "DOMAIN": "Domain", "DOMAIN-SUFFIX": "DomainSuffix", "MATCH": "Match"}
			rule := mihomoRule{Type: types[parts[0]]}
			if len(parts) == 2 && parts[0] == "MATCH" {
				rule.Proxy = parts[1]
			} else if len(parts) == 3 {
				rule.Payload, rule.Proxy = parts[1], parts[2]
			} else {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			rules = append(rules, rule)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"rules": rules})
	case "GET /proxies":
		proxies := map[string]mihomoProxyState{}
		for _, p := range f.document.Proxies {
			proxies[p.Name] = mihomoProxyState{Type: map[string]string{"http": "Http", "socks5": "Socks5", "direct": "Direct"}[p.Type]}
		}
		for _, group := range f.document.ProxyGroups {
			selected := f.selected
			if selected == "" && len(group.Proxies) > 0 {
				selected = group.Proxies[0]
			}
			proxies[group.Name] = mihomoProxyState{Type: "Selector", All: group.Proxies, Now: selected}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"proxies": proxies})
	case "PUT /proxies/Soha":
		var selected struct{ Name string }
		if json.NewDecoder(r.Body).Decode(&selected) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.selected = selected.Name
		w.WriteHeader(http.StatusNoContent)
	case "DELETE /connections":
		f.connections = false
		w.WriteHeader(http.StatusNoContent)
	case "GET /connections":
		connections := []any{}
		if f.connections {
			connections = append(connections, map[string]any{"metadata": map[string]string{"host": "must-not-leave-endpoint"}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"downloadTotal": 4096, "uploadTotal": 1024, "connections": connections})
	default:
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/proxies/") && strings.HasSuffix(r.URL.Path, "/delay") && f.probe(r) {
			f.probes++
			_ = json.NewEncoder(w).Encode(map[string]int{"delay": 1})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *mihomoControllerFixture) probe(r *http.Request) bool {
	target, err := url.Parse(r.URL.Query().Get("url"))
	if err != nil || target.Scheme != "http" || !strings.HasPrefix(target.Hostname(), "soha-egress-") || !strings.HasSuffix(target.Hostname(), ".invalid") || target.Port() != "" {
		return false
	}
	name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/proxies/"), "/delay")
	for _, proxy := range f.document.Proxies {
		if proxy.Name != name || proxy.Server != "127.0.0.1" || proxy.Type != "http" {
			continue
		}
		front := &url.URL{Scheme: "http", Host: net.JoinHostPort(proxy.Server, strconv.Itoa(proxy.Port)), User: url.UserPassword(proxy.Username, proxy.Password)}
		transport := &http.Transport{Proxy: http.ProxyURL(front), DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		response, err := client.Get(target.String())
		if err != nil {
			return false
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return response.StatusCode == http.StatusNoContent
	}
	return false
}
