//go:build windows

package endpointservice

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	tunnelServiceName   = "WireGuardTunnel$" + endpointInterfaceName
	wireGuardTimeout    = 30 * time.Second
	wireGuardPollPeriod = 200 * time.Millisecond
)

type WindowsSystem struct {
	executable string
	configPath string
	expected   *TunnelPlan
}

func NewWindowsSystem(executable, configPath string) (*WindowsSystem, error) {
	if err := regularFile(executable); err != nil {
		return nil, fmt.Errorf("WireGuard executable: %w", err)
	}
	if !filepath.IsAbs(configPath) || filepath.Base(configPath) != endpointInterfaceName+".conf.dpapi" {
		return nil, errors.New("WireGuard tunnel config path is invalid")
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		return nil, fmt.Errorf("create endpoint state directory: %w", err)
	}
	if err := secureStateDirectory(filepath.Dir(configPath)); err != nil {
		return nil, fmt.Errorf("secure endpoint state directory: %w", err)
	}
	return &WindowsSystem{executable: executable, configPath: configPath}, nil
}

func (system *WindowsSystem) Apply(ctx context.Context, plan TunnelPlan) error {
	operationCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := system.Disable(operationCtx); err != nil {
		return fmt.Errorf("remove previous WireGuard tunnel: %w", err)
	}
	if err := rejectWindowsRouteConflicts(plan); err != nil {
		return err
	}
	plain := renderWireGuardConfig(plan)
	defer clear(plain)
	if err := system.writeConfig(plain); err != nil {
		return err
	}
	expected := cloneTunnelPlan(plan)
	system.expected = &expected
	if err := system.run(operationCtx, "/installtunnelservice", system.configPath); err != nil {
		system.failClosed()
		return err
	}
	ticker := time.NewTicker(wireGuardPollPeriod)
	defer ticker.Stop()
	for {
		readback, err := system.Readback(operationCtx)
		if err == nil && reflect.DeepEqual(readback, plan.Readback()) {
			return nil
		}
		select {
		case <-operationCtx.Done():
			system.failClosed()
			return errors.New("WireGuard tunnel did not converge before the deadline")
		case <-ticker.C:
		}
	}
}

func (system *WindowsSystem) Readback(ctx context.Context) (TunnelReadback, error) {
	client, err := wgctrl.New()
	if err != nil {
		return TunnelReadback{}, fmt.Errorf("open WireGuard control client: %w", err)
	}
	defer client.Close()
	device, err := client.Device(endpointInterfaceName)
	if errors.Is(err, os.ErrNotExist) {
		if _, interfaceErr := net.InterfaceByName(endpointInterfaceName); interfaceErr == nil {
			return TunnelReadback{}, errors.New("WireGuard adapter exists without a control device")
		}
		return TunnelReadback{}, nil
	}
	if err != nil {
		return TunnelReadback{}, fmt.Errorf("read WireGuard device: %w", err)
	}
	if device.Name != endpointInterfaceName || len(device.Peers) != 1 || device.PublicKey == (wgtypes.Key{}) || device.Peers[0].PresharedKey != (wgtypes.Key{}) {
		return TunnelReadback{}, errors.New("WireGuard device identity or peer count is invalid")
	}
	adapter, err := net.InterfaceByName(endpointInterfaceName)
	if err != nil || adapter.Flags&net.FlagUp == 0 || adapter.MTU < 1 {
		return TunnelReadback{}, errors.New("WireGuard adapter is not operational")
	}
	addresses, err := interfaceIPv4Addresses(adapter)
	if err != nil {
		return TunnelReadback{}, err
	}
	peer := device.Peers[0]
	if !validVPNHandshake(peer.LastHandshakeTime, time.Now()) {
		return TunnelReadback{}, errors.New("WireGuard handshake is missing or stale")
	}
	allowedIPs, err := allowedIPv4Prefixes(peer.AllowedIPs)
	if err != nil || peer.Endpoint == nil || peer.PersistentKeepaliveInterval%time.Second != 0 {
		return TunnelReadback{}, errors.New("WireGuard peer state is invalid")
	}
	if err := verifyInterfaceRoutes(adapter.Index, allowedIPs, addresses); err != nil {
		return TunnelReadback{}, err
	}
	dnsServers, err := interfaceDNSServers(uint32(adapter.Index))
	if err != nil {
		return TunnelReadback{}, err
	}
	endpoint := peer.Endpoint.String()
	if system.expected != nil {
		if !endpointMatches(ctx, system.expected.Peer.Endpoint, peer.Endpoint) {
			return TunnelReadback{}, errors.New("WireGuard endpoint readback does not match desired state")
		}
		endpoint = system.expected.Peer.Endpoint
	}
	return TunnelReadback{PublicKey: device.PublicKey.String(), Addresses: addresses, MTU: adapter.MTU, Peer: TunnelPeer{PublicKey: peer.PublicKey.String(), Endpoint: endpoint, AllowedIPs: allowedIPs, PersistentKeepaliveSeconds: int(peer.PersistentKeepaliveInterval / time.Second)}, Routes: slices.Clone(allowedIPs), DNSServers: dnsServers}, nil
}

func (system *WindowsSystem) Disable(ctx context.Context) error {
	operationCtx, cancel := context.WithTimeout(ctx, wireGuardTimeout)
	defer cancel()
	exists, err := tunnelServiceExists()
	if err != nil {
		return err
	}
	var uninstallErr error
	if exists {
		uninstallErr = system.run(operationCtx, "/uninstalltunnelservice", endpointInterfaceName)
		for exists && operationCtx.Err() == nil {
			time.Sleep(wireGuardPollPeriod)
			exists, err = tunnelServiceExists()
			if err != nil {
				break
			}
		}
	}
	if exists && err == nil {
		err = errors.New("WireGuard tunnel service did not stop before the deadline")
	}
	removeErr := os.Remove(system.configPath)
	if errors.Is(removeErr, os.ErrNotExist) {
		removeErr = nil
	}
	if !exists && err == nil {
		system.expected = nil
	}
	return errors.Join(uninstallErr, err, removeErr)
}

func (system *WindowsSystem) run(ctx context.Context, arguments ...string) error {
	command := exec.CommandContext(ctx, system.executable, arguments...)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	if err := command.Run(); err != nil {
		return fmt.Errorf("WireGuard command failed: %w", err)
	}
	return nil
}

func (system *WindowsSystem) writeConfig(plain []byte) error {
	protected, err := protectSecret(plain, endpointInterfaceName)
	if err != nil {
		return fmt.Errorf("protect WireGuard tunnel config: %w", err)
	}
	directory := filepath.Dir(system.configPath)
	temporary, err := os.CreateTemp(directory, ".soha0-*.dpapi")
	if err != nil {
		return fmt.Errorf("create temporary WireGuard config: %w", err)
	}
	temporaryPath := temporary.Name()
	remove := true
	defer func() {
		_ = temporary.Close()
		if remove {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(protected); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Remove(system.configPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(temporaryPath, system.configPath); err != nil {
		return err
	}
	remove = false
	return nil
}

func (system *WindowsSystem) failClosed() {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = system.Disable(cleanupCtx)
}

func tunnelServiceExists() (bool, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return false, fmt.Errorf("connect Windows service manager: %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(tunnelServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("open WireGuard tunnel service: %w", err)
	}
	_ = service.Close()
	return true, nil
}

func rejectWindowsRouteConflicts(plan TunnelPlan) error {
	prefixes := make([]netip.Prefix, 0, len(plan.Addresses)+len(plan.Routes))
	for _, raw := range append(slices.Clone(plan.Addresses), plan.Routes...) {
		prefixes = append(prefixes, netip.MustParsePrefix(raw))
	}
	table, err := windowsRouteTable()
	if err != nil {
		return err
	}
	for _, route := range table {
		if route.Bits() == 0 {
			continue
		}
		for _, planned := range prefixes {
			if route.Contains(planned.Addr()) || planned.Contains(route.Addr()) {
				return fmt.Errorf("route %s conflicts with the requested Soha tunnel", route)
			}
		}
	}
	return nil
}

func windowsRouteTable() ([]netip.Prefix, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return nil, fmt.Errorf("read Windows IPv4 route table: %w", err)
	}
	if table == nil {
		return nil, nil
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	routes := make([]netip.Prefix, 0, table.NumEntries)
	for _, row := range table.Rows() {
		if prefix, ok := rowIPv4Prefix(row); ok {
			routes = append(routes, prefix)
		}
	}
	return routes, nil
}

func rowIPv4Prefix(row windows.MibIpForwardRow2) (netip.Prefix, bool) {
	if row.DestinationPrefix.Prefix.Family != windows.AF_INET || row.DestinationPrefix.PrefixLength > 32 {
		return netip.Prefix{}, false
	}
	raw := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.DestinationPrefix.Prefix))
	return netip.PrefixFrom(netip.AddrFrom4(raw.Addr), int(row.DestinationPrefix.PrefixLength)).Masked(), true
}

func verifyInterfaceRoutes(interfaceIndex int, expected, allowedExtras []string) error {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return fmt.Errorf("read WireGuard routes: %w", err)
	}
	if table == nil {
		return errors.New("WireGuard route table is empty")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	actual := []netip.Prefix{}
	for _, row := range table.Rows() {
		if int(row.InterfaceIndex) != interfaceIndex {
			continue
		}
		if prefix, ok := rowIPv4Prefix(row); ok {
			actual = append(actual, prefix)
		}
	}
	return verifyRouteSet(actual, expected, allowedExtras)
}

func interfaceDNSServers(interfaceIndex uint32) ([]string, error) {
	size := uint32(15_000)
	for {
		buffer := make([]byte, size)
		addresses := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(uint32(windows.AF_INET), windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST, 0, addresses, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read WireGuard DNS servers: %w", err)
		}
		for adapter := addresses; adapter != nil; adapter = adapter.Next {
			if adapter.IfIndex != interfaceIndex {
				continue
			}
			servers := []string{}
			for dns := adapter.FirstDnsServerAddress; dns != nil; dns = dns.Next {
				if address, ok := netip.AddrFromSlice(dns.Address.IP()); ok && address.Unmap().Is4() {
					servers = append(servers, address.Unmap().String())
				}
			}
			slices.Sort(servers)
			return slices.Compact(servers), nil
		}
		return nil, errors.New("WireGuard adapter was not found while reading DNS")
	}
}

func (system *WindowsSystem) CheckVPNHealth(ctx context.Context) error {
	_, err := system.Readback(ctx)
	return err
}
