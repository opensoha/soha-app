//go:build windows

package endpointservice

import (
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"net/netip"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

var winNativeIPHelper = windows.NewLazySystemDLL("iphlpapi.dll")

func winNativeStatus(proc string, args ...uintptr) error {
	p := winNativeIPHelper.NewProc(proc)
	if err := p.Find(); err != nil {
		return err
	}
	r, _, _ := p.Call(args...)
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}
func winNativeAdapters() ([]nativeInterface, []nativeResolverScope, error) {
	for _, path := range []string{`SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`, `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
		if errors.Is(err, registry.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		names, err := k.ReadSubKeyNames(-1)
		k.Close()
		if err != nil || len(names) > 0 {
			return nil, nil, errors.New("NRPT resolver namespace requires explicit handling")
		}
	}
	size := uint32(16384)
	for tries := 0; tries < 4; tries++ {
		if size > 4<<20 {
			return nil, nil, errors.New("adapter snapshot exceeds bound")
		}
		buffer := make([]byte, size)
		head := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST, 0, head, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		var interfaces []nativeInterface
		var scopes []nativeResolverScope
		for a := head; a != nil; a = a.Next {
			if a.OperStatus != 1 {
				continue
			}
			row := windows.MibIfRow2{InterfaceLuid: a.Luid}
			if err := windows.GetIfEntry2Ex(0, &row); err != nil {
				return nil, nil, err
			}
			kind := "unknown"
			if row.Type == 24 {
				kind = "loopback"
			} else if row.Type == 131 || row.Type == 53 || a.TunnelType != 0 {
				kind = "tunnel"
			} else if row.InterfaceAndOperStatusFlags&1 != 0 && (row.Type == 6 || row.Type == 71) {
				kind = "physical"
			}
			i := nativeInterface{ID: row.InterfaceGuid.String(), Index: row.InterfaceIndex, Name: windows.UTF16PtrToString(a.FriendlyName), Kind: kind}
			for u := a.FirstUnicastAddress; u != nil; u = u.Next {
				addr, ok := netip.AddrFromSlice(u.Address.IP())
				if ok && !addr.Is4In6() {
					i.Addresses = append(i.Addresses, netip.PrefixFrom(addr, int(u.OnLinkPrefixLength)))
				}
			}
			interfaces = append(interfaces, i)
			scope := nativeResolverScope{ID: i.ID, Interface: i, Default: true, Priority: a.Ipv4Metric}
			suffix := windows.UTF16PtrToString(a.DnsSuffix)
			if suffix != "" {
				scope.Domains = []string{suffix}
			}
			for dns := a.FirstDnsServerAddress; dns != nil; dns = dns.Next {
				addr, ok := netip.AddrFromSlice(dns.Address.IP())
				if ok {
					scope.Servers = append(scope.Servers, addr.Unmap())
				}
			}
			if len(scope.Servers) > 0 {
				scopes = append(scopes, scope)
			}
		}
		runtime.KeepAlive(buffer)
		return interfaces, scopes, nil
	}
	return nil, nil, errors.New("adapter snapshot changed repeatedly")
}
func winNativeCheckInterface(expected nativeInterface) error {
	interfaces, _, err := winNativeAdapters()
	if err != nil {
		return err
	}
	for _, i := range interfaces {
		if i.ID == expected.ID && reflect.DeepEqual(i, expected) {
			return nil
		}
	}
	return errors.New("network interface identity changed")
}
func winNativeSockaddr(a netip.Addr) windows.RawSockaddrInet {
	var out windows.RawSockaddrInet
	if a.Is4() {
		v := (*windows.RawSockaddrInet4)(unsafe.Pointer(&out))
		v.Family = windows.AF_INET
		v.Addr = a.As4()
	} else {
		v := (*windows.RawSockaddrInet6)(unsafe.Pointer(&out))
		v.Family = windows.AF_INET6
		v.Addr = a.As16()
	}
	return out
}
func winNativeAddr(a windows.RawSockaddrInet) netip.Addr {
	if a.Family == windows.AF_INET {
		return netip.AddrFrom4((*windows.RawSockaddrInet4)(unsafe.Pointer(&a)).Addr)
	}
	if a.Family == windows.AF_INET6 {
		return netip.AddrFrom16((*windows.RawSockaddrInet6)(unsafe.Pointer(&a)).Addr)
	}
	return netip.Addr{}
}
func winNativeRoute(row windows.MibIpForwardRow2, i nativeInterface) (nativeRoute, error) {
	prefix, ok := rowIPPrefix(row)
	if !ok {
		return nativeRoute{}, errors.New("invalid native route prefix")
	}
	flags := row.Protocol&65535 | (row.Origin&255)<<16 | uint32(row.Loopback)<<24 | uint32(row.AutoconfigureAddress)<<25 | uint32(row.Publish)<<26 | uint32(row.Immortal)<<27
	return nativeRoute{Destination: prefix, Gateway: winNativeAddr(row.NextHop), Interface: i, Metric: row.Metric, Flags: flags}, nil
}
func winNativeRoutes() ([]nativeRoute, error) {
	interfaces, _, err := winNativeAdapters()
	if err != nil {
		return nil, err
	}
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &table); err != nil {
		return nil, err
	}
	if table == nil {
		return nil, nil
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	var routes []nativeRoute
	for _, row := range table.Rows() {
		for _, i := range interfaces {
			if i.Index == row.InterfaceIndex {
				r, err := winNativeRoute(row, i)
				if err == nil {
					routes = append(routes, r)
				}
			}
		}
	}
	return routes, nil
}
func winNativeBestRoute(i nativeInterface, d netip.Addr) (nativeRoute, netip.Addr, error) {
	destination := winNativeSockaddr(d)
	var row windows.MibIpForwardRow2
	var source windows.RawSockaddrInet
	err := winNativeStatus("GetBestRoute2", 0, uintptr(i.Index), 0, uintptr(unsafe.Pointer(&destination)), 0, uintptr(unsafe.Pointer(&row)), uintptr(unsafe.Pointer(&source)))
	if err != nil {
		return nativeRoute{}, netip.Addr{}, err
	}
	if row.InterfaceIndex != i.Index {
		return nativeRoute{}, netip.Addr{}, errors.New("best route escaped pinned interface")
	}
	addr := winNativeAddr(source)
	owned := false
	for _, p := range i.Addresses {
		if p.Addr() == addr {
			owned = true
		}
	}
	if !owned {
		return nativeRoute{}, netip.Addr{}, errors.New("best source is outside pinned interface")
	}
	r, err := winNativeRoute(row, i)
	return r, addr, err
}
func winNativeRouteRow(r nativeRoute) windows.MibIpForwardRow2 {
	row := windows.MibIpForwardRow2{}
	_ = winNativeStatus("InitializeIpForwardEntry", uintptr(unsafe.Pointer(&row)))
	row.InterfaceIndex = r.Interface.Index
	row.DestinationPrefix.Prefix = winNativeSockaddr(r.Destination.Addr())
	row.DestinationPrefix.PrefixLength = uint8(r.Destination.Bits())
	row.NextHop = winNativeSockaddr(r.Gateway)
	row.Metric = r.Metric
	row.Protocol = r.Flags & 65535
	row.Origin = (r.Flags >> 16) & 255
	row.Loopback = uint8(r.Flags>>24) & 1
	row.AutoconfigureAddress = uint8(r.Flags>>25) & 1
	row.Publish = uint8(r.Flags>>26) & 1
	row.Immortal = uint8(r.Flags>>27) & 1
	return row
}
func winNativeWriteRoute(before, after nativeValue) error {
	r := after.Route
	if r == nil {
		r = before.Route
	}
	if r == nil {
		return errors.New("route identity missing")
	}
	if err := winNativeCheckInterface(r.Interface); err != nil {
		return err
	}
	if before.Present && after.Present {
		row := winNativeRouteRow(*after.Route)
		return winNativeStatus("SetIpForwardEntry2", uintptr(unsafe.Pointer(&row)))
	}
	row := winNativeRouteRow(*r)
	op := "CreateIpForwardEntry2"
	if !after.Present {
		op = "DeleteIpForwardEntry2"
	}
	return winNativeStatus(op, uintptr(unsafe.Pointer(&row)))
}
func winNativeReadDNS(scope nativeScope) (*nativeDNSConfig, error) {
	if scope.Family != 4 && scope.Family != 6 {
		return nil, errors.New("invalid DNS family")
	}
	text, _, err := winNativeDNSNameServer(scope)
	if err != nil {
		return nil, err
	}

	d := &nativeDNSConfig{Automatic: strings.TrimSpace(text) == ""}
	for _, raw := range strings.FieldsFunc(text, func(c rune) bool { return c == ',' || c == ' ' || c == ';' }) {
		a, err := netip.ParseAddr(raw)
		if err != nil || a.Is4() != (scope.Family == 4) {
			return nil, errors.New("configured DNS namespace is invalid")
		}
		d.Servers = append(d.Servers, a)
	}
	if !d.Automatic {
		_, scopes, err := winNativeAdapters()
		if err != nil {
			return nil, err
		}
		var actual []netip.Addr
		for _, s := range scopes {
			if s.Interface.ID == scope.Interface.ID {
				for _, a := range s.Servers {
					if a.Is4() == (scope.Family == 4) {
						actual = append(actual, a)
					}
				}
			}
		}
		if !reflect.DeepEqual(actual, d.Servers) {
			return nil, errors.New("configured DNS differs from effective resolver scope")
		}
	}
	return d, nil
}

type winNativeDNSSettings struct {
	Version                                                                 uint32
	Flags                                                                   uint64
	Domain, NameServer, SearchList                                          *uint16
	RegistrationEnabled, RegisterAdapterName, EnableLLMNR, QueryAdapterName uint32
	ProfileNameServer                                                       *uint16
}

func winNativeWriteDNS(scope nativeScope, value nativeValue) error {
	if value.Present && value.DNS == nil {
		return errors.New("missing DNS value")
	}
	guid, err := windows.GUIDFromString(scope.Interface.ID)
	if err != nil {
		return err
	}
	settings := winNativeDNSSettings{Version: 1, Flags: 2}
	if scope.Family == 6 {
		settings.Flags |= 1
	}
	var parts []string
	var servers []netip.Addr
	if value.DNS != nil {
		servers = value.DNS.Servers
	}
	for _, a := range servers {
		parts = append(parts, a.String())
	}
	settings.NameServer, err = windows.UTF16PtrFromString(strings.Join(parts, ","))
	if err != nil {
		return err
	}
	// GUID is a 16-byte by-value aggregate, passed indirectly by the Windows x64/ARM64 ABI.
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return errors.New("native DNS ABI requires 64-bit Windows")
	}
	err = winNativeStatus("SetInterfaceDnsSettings", uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(&settings)))
	runtime.KeepAlive(settings)
	if err != nil {
		return err
	}
	if len(servers) == 0 {
		text, present, err := winNativeDNSNameServer(scope)
		if err != nil {
			return err
		}
		if text != "" {
			return errors.New("automatic DNS changed during write")
		}
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, winNativeDNSPath(scope), registry.SET_VALUE)
		if err != nil {
			return err
		}
		defer key.Close()
		if !value.Present && present {
			return key.DeleteValue("NameServer")
		}
		if value.Present && !present {
			return key.SetStringValue("NameServer", "")
		}
	}
	return nil
}

func winNativeDNSPath(scope nativeScope) string {
	service := "Tcpip"
	if scope.Family == 6 {
		service = "Tcpip6"
	}
	return `SYSTEM\CurrentControlSet\Services\` + service + `\Parameters\Interfaces\` + scope.Interface.ID
}
func winNativeDNSNameServer(scope nativeScope) (string, bool, error) {
	if _, err := windows.GUIDFromString(scope.Interface.ID); err != nil {
		return "", false, err
	}
	if scope.Family != 4 && scope.Family != 6 {
		return "", false, errors.New("invalid DNS family")
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, winNativeDNSPath(scope), registry.QUERY_VALUE)
	if err != nil {
		return "", false, err
	}
	defer key.Close()
	text, _, err := key.GetStringValue("NameServer")
	if errors.Is(err, registry.ErrNotExist) {
		return "", false, nil
	}
	return text, err == nil, err
}
func winNativeDNSValue(scope nativeScope) (nativeValue, error) {
	d, err := winNativeReadDNS(scope)
	if err != nil {
		return nativeValue{}, err
	}
	_, present, err := winNativeDNSNameServer(scope)
	if err != nil {
		return nativeValue{}, err
	}
	if !present {
		return nativeValue{}, nil
	}
	return nativeValue{Present: true, DNS: d}, nil
}
