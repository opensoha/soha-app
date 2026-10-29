//go:build darwin

package endpointservice

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/route"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// The service owns the TUN descriptor; closing it removes its interface and routes.
type DarwinSystem struct {
	mu       sync.Mutex
	device   *device.Device
	name     string
	dns      *darwinDNS
	expected *TunnelPlan
}

func NewDarwinSystem() (*DarwinSystem, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("macOS VPN requires the privileged network service")
	}
	return &DarwinSystem{}, nil
}

func (s *DarwinSystem) Apply(ctx context.Context, plan TunnelPlan) (result error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := s.disable(); err != nil {
		return err
	}
	routes, err := darwinRoutes()
	if err != nil {
		return err
	}
	for _, existing := range routes {
		if existing.prefix.Bits() == 0 {
			continue
		}
		for _, raw := range append(slices.Clone(plan.Routes), plan.Addresses...) {
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				return err
			}
			if p.Overlaps(existing.prefix) {
				return fmt.Errorf("route %s conflicts with the requested Soha tunnel", existing.prefix)
			}
		}
	}
	endpoint, err := net.ResolveUDPAddr("udp", plan.Peer.Endpoint)
	if err != nil {
		return errors.New("could not resolve WireGuard endpoint")
	}
	private, err := wgtypes.ParseKey(plan.PrivateKey)
	if err != nil {
		return err
	}
	defer clear(private[:])
	peer, err := wgtypes.ParseKey(plan.Peer.PublicKey)
	if err != nil {
		return err
	}
	adapter, err := tun.CreateTUN("utun", plan.MTU)
	if err != nil {
		return fmt.Errorf("create macOS VPN interface: %w", err)
	}
	s.name, err = adapter.Name()
	if err != nil {
		_ = adapter.Close()
		return err
	}
	s.device = device.NewDevice(adapter, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer func() {
		if result != nil {
			result = errors.Join(result, s.disable())
		}
	}()
	expected := cloneTunnelPlan(plan)
	s.expected = &expected
	var config bytes.Buffer
	fmt.Fprintf(&config, "private_key=%x\nreplace_peers=true\npublic_key=%x\nendpoint=%s\npersistent_keepalive_interval=%d\nreplace_allowed_ips=true\n", private[:], peer[:], endpoint, plan.Peer.PersistentKeepaliveSeconds)
	for _, prefix := range plan.Peer.AllowedIPs {
		fmt.Fprintf(&config, "allowed_ip=%s\n", prefix)
	}
	raw := config.Bytes()
	defer clear(raw)
	if err := s.device.IpcSetOperation(&config); err != nil {
		return errors.New("configure macOS WireGuard device failed")
	}
	addresses := make([]string, 0, len(plan.Addresses))
	for _, prefix := range plan.Addresses {
		address := netip.MustParsePrefix(prefix).Addr().String()
		addresses = append(addresses, address)
		args := []string{s.name, "inet", address, address, "netmask", "255.255.255.255", "alias"}
		if strings.Contains(address, ":") {
			args = []string{s.name, "inet6", address, "prefixlen", "128", "alias"}
		}
		if err := nativeCommand(ctx, "/sbin/ifconfig", args...); err != nil {
			return err
		}
	}
	if err := nativeCommand(ctx, "/sbin/ifconfig", s.name, "up"); err != nil {
		return err
	}
	for _, prefix := range plan.Routes {
		args := []string{"-n", "add", "-net", prefix, "-interface", s.name}
		if strings.Contains(prefix, ":") {
			args = []string{"-n", "add", "-inet6", "-net", prefix, "-interface", s.name}
		}
		if err := nativeCommand(ctx, "/sbin/route", args...); err != nil {
			return err
		}
	}
	if len(plan.DNSServers) > 0 {
		s.dns, err = openDarwinDNS(s.name, addresses, plan.DNSServers)
		if err != nil {
			return err
		}
	}
	if err := s.device.Up(); err != nil {
		return err
	}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		readback, err := s.readback(ctx)
		if err == nil && reflect.DeepEqual(readback, plan.Readback()) {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("macOS WireGuard handshake or system state did not converge before the deadline")
		case <-ticker.C:
		}
	}
}

func nativeCommand(ctx context.Context, path string, args ...string) error {
	if err := exec.CommandContext(ctx, path, args...).Run(); err != nil {
		return fmt.Errorf("%s failed: %w", path, err)
	}
	return nil
}

func (s *DarwinSystem) Readback(ctx context.Context) (TunnelReadback, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readback(ctx)
}

func (s *DarwinSystem) TunnelInterface(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.readback(ctx)
	if err != nil || s.expected == nil || !reflect.DeepEqual(state, s.expected.Readback()) {
		return "", errors.New("macOS VPN interface is not verified")
	}
	return s.name, nil
}
func (s *DarwinSystem) readback(ctx context.Context) (TunnelReadback, error) {
	if s.device == nil {
		if s.dns != nil || s.name != "" {
			return TunnelReadback{}, errors.New("VPN cleanup is incomplete")
		}
		return TunnelReadback{}, nil
	}
	var raw bytes.Buffer
	if err := s.device.IpcGetOperation(&raw); err != nil {
		return TunnelReadback{}, errors.New("read macOS WireGuard state failed")
	}
	defer clear(raw.Bytes())
	state, err := parseDarwinWireGuard(raw.Bytes(), time.Now())
	if err != nil {
		return TunnelReadback{}, err
	}
	adapter, err := net.InterfaceByName(s.name)
	if err != nil || adapter.Flags&net.FlagUp == 0 {
		return TunnelReadback{}, errors.New("macOS VPN interface is not operational")
	}
	state.MTU = adapter.MTU
	state.Addresses, err = interfaceIPAddresses(adapter)
	if err != nil {
		return TunnelReadback{}, err
	}
	table, err := darwinRoutes()
	if err != nil {
		return TunnelReadback{}, err
	}
	actual := []netip.Prefix{}
	for _, entry := range table {
		if entry.index == adapter.Index {
			actual = append(actual, entry.prefix)
		} else if entry.prefix.Bits() > 0 {
			for _, raw := range state.Peer.AllowedIPs {
				if entry.prefix.Overlaps(netip.MustParsePrefix(raw)) {
					return TunnelReadback{}, errors.New("another interface now overlaps the Soha tunnel")
				}
			}
		}
	}
	if err := verifyRouteSet(actual, state.Peer.AllowedIPs, state.Addresses); err != nil {
		return TunnelReadback{}, err
	}
	state.Routes = slices.Clone(state.Peer.AllowedIPs)
	endpoint, err := net.ResolveUDPAddr("udp", state.Peer.Endpoint)
	if err != nil || s.expected == nil || !endpointMatches(ctx, s.expected.Peer.Endpoint, endpoint) {
		return TunnelReadback{}, errors.New("macOS WireGuard endpoint changed")
	}
	state.Peer.Endpoint = s.expected.Peer.Endpoint
	state.DNSServers = []string{}
	if len(s.expected.DNSServers) > 0 {
		if !s.dns.matches() {
			return TunnelReadback{}, errors.New("macOS VPN DNS settings changed")
		}
		state.DNSServers = slices.Clone(s.expected.DNSServers)
	}
	return state, nil
}

func (s *DarwinSystem) Disable(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.disable()
}
func (s *DarwinSystem) disable() error {
	var cleanupErr error
	if s.device != nil {
		s.device.Close()
		s.device = nil
	}
	if s.name != "" {
		if _, err := net.InterfaceByName(s.name); err == nil {
			cleanupErr = errors.New("macOS VPN interface still exists after close")
		} else {
			s.name = ""
		}
	}
	if err := s.dns.close(); err != nil {
		return errors.Join(cleanupErr, err)
	}
	s.dns = nil
	s.expected = nil
	return cleanupErr
}
func (s *DarwinSystem) CheckVPNHealth(ctx context.Context) error {
	_, err := s.Readback(ctx)
	return err
}

type darwinRoute struct {
	index  int
	prefix netip.Prefix
}

func darwinRoutes() ([]darwinRoute, error) {
	result := []darwinRoute{}
	for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
		rib, err := route.FetchRIB(family, route.RIBTypeRoute, 0)
		if err != nil {
			return nil, err
		}
		messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
		if err != nil {
			return nil, err
		}
		for _, message := range messages {
			m, ok := message.(*route.RouteMessage)
			if !ok {
				continue
			}
			p, ok := darwinRoutePrefix(m)
			if ok {
				result = append(result, darwinRoute{m.Index, p})
			}
		}
	}
	return result, nil
}
func darwinRoutePrefix(m *route.RouteMessage) (netip.Prefix, bool) {
	if len(m.Addrs) <= syscall.RTAX_DST {
		return netip.Prefix{}, false
	}
	var address netip.Addr
	var mask net.IPMask
	switch dst := m.Addrs[syscall.RTAX_DST].(type) {
	case *route.Inet4Addr:
		address = netip.AddrFrom4(dst.IP)
		if len(m.Addrs) > syscall.RTAX_NETMASK {
			if v, ok := m.Addrs[syscall.RTAX_NETMASK].(*route.Inet4Addr); ok {
				mask = net.IPMask(v.IP[:])
			}
		}
	case *route.Inet6Addr:
		address = netip.AddrFrom16(dst.IP)
		if len(m.Addrs) > syscall.RTAX_NETMASK {
			if v, ok := m.Addrs[syscall.RTAX_NETMASK].(*route.Inet6Addr); ok {
				mask = net.IPMask(v.IP[:])
			}
		}
	default:
		return netip.Prefix{}, false
	}
	bits := address.BitLen()
	if m.Flags&syscall.RTF_HOST == 0 {
		var total int
		bits, total = mask.Size()
		if total != address.BitLen() {
			return netip.Prefix{}, false
		}
	}
	if bits > 0 && !address.IsGlobalUnicast() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(address, bits).Masked(), true
}

func parseDarwinWireGuard(raw []byte, now time.Time) (TunnelReadback, error) {
	invalid := errors.New("macOS WireGuard readback is invalid or its handshake is stale")
	state := TunnelReadback{}
	peers := 0
	var handshake int64
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		key, value, ok := bytes.Cut(line, []byte{'='})
		if !ok {
			continue
		}
		switch string(key) {
		case "private_key", "public_key", "preshared_key":
			var k wgtypes.Key
			if len(value) != 64 {
				return TunnelReadback{}, invalid
			}
			if _, err := hex.Decode(k[:], value); err != nil {
				return TunnelReadback{}, invalid
			}
			switch string(key) {
			case "private_key":
				state.PublicKey = k.PublicKey().String()
			case "public_key":
				peers++
				state.Peer.PublicKey = k.String()
			case "preshared_key":
				if k != (wgtypes.Key{}) {
					return TunnelReadback{}, invalid
				}
			}
			clear(k[:])
		case "endpoint":
			state.Peer.Endpoint = string(value)
		case "allowed_ip":
			state.Peer.AllowedIPs = append(state.Peer.AllowedIPs, string(value))
		case "persistent_keepalive_interval":
			n, err := strconv.Atoi(string(value))
			if err != nil || n < 0 || n > 300 {
				return TunnelReadback{}, invalid
			}
			state.Peer.PersistentKeepaliveSeconds = n
		case "last_handshake_time_sec":
			var err error
			handshake, err = strconv.ParseInt(string(value), 10, 64)
			if err != nil {
				return TunnelReadback{}, invalid
			}
		}
	}
	allowed, err := canonicalPrefixes(state.Peer.AllowedIPs, false)
	if err != nil || len(allowed) == 0 || peers != 1 || state.PublicKey == "" || strings.TrimSpace(state.Peer.Endpoint) == "" || !validVPNHandshake(time.Unix(handshake, 0), now) {
		return TunnelReadback{}, invalid
	}
	state.Peer.AllowedIPs = allowed
	return state, nil
}
