//go:build darwin && cgo

package endpointservice

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework Foundation -framework Security -framework SystemConfiguration -framework CoreFoundation -lbsm -lproc
#include <stdlib.h>
int ni_peer(int, unsigned int *);
int ni_listener(unsigned int,int,int,unsigned short,const void *);
int ni_console(unsigned int, unsigned int);
int ni_code(const unsigned int *,const char *,const char *);
char *ni_setting(const char *,const char *,const char *);
int ni_setting_cas(const char *,const char *,const char *,const char *,const char *);
char *ni_network(void);
char *ni_interfaces(void);
unsigned int ni_route_metric(const void *,int);
int ni_route_setmetric(void *,int,unsigned int);
*/
import "C"

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

var errDarwinNative = errors.New("macOS interception identity or network scope could not be verified")

// System calls are replaceable only inside this package's tests. Construction is read-only.
type darwinNativeCalls struct {
	recovery     *darwinRecoveryCalls
	flushCommand func(context.Context, string, ...string) error
	listener     func(string, netip.AddrPort, uint32) error
	peer         func(net.Conn) ([8]uint32, error)
	console      func(uint32, uint32) error
	code         func([8]uint32) error
	interfaces   func() ([]nativeInterface, error)
	network      func() (darwinNativeNetwork, error)
	read         func(string, string, string) (json.RawMessage, error)
	cas          func(string, string, string, json.RawMessage, json.RawMessage) (string, error)
	routes       func([]nativeInterface) ([]nativeRoute, error)
	routeWrite   func(nativeRoute, bool) error
	bind         func(syscall.RawConn, uint32, netip.Addr) error
	lookup       func(netip.Addr, nativeInterface) (nativeRoute, error)
}
type darwinNativePlatform struct {
	uid      uint32
	presence *UIProcessPresence
	calls    darwinNativeCalls
	mu       sync.Mutex
}
type darwinNativeSession struct {
	platform    *darwinNativePlatform
	token       [8]uint32
	owner       nativeOwner
	restoreOnly bool
	mu          sync.Mutex
	closed      bool
}
type darwinNativeNetwork struct {
	IPv4     string
	IPv6     string
	Services []struct {
		ID        string
		Name      string
		Interface string
		Type      string
	}
	Resolvers []struct {
		ID    string
		Value struct {
			ServerAddresses          []string
			SupplementalMatchDomains []string
			SupplementalMatchOrders  []uint32
			SearchOrder              uint32
			InterfaceName            string
		}
	}
}

var darwinProxyFields = []string{"HTTPEnable", "HTTPProxy", "HTTPPort", "HTTPSEnable", "HTTPSProxy", "HTTPSPort", "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"}

func newNativeInterceptionPlatform(config Config, presence *UIProcessPresence) (nativePlatform, error) {
	if config.AllowedUserUID == nil || config.UIExecutable == "" || presence == nil || presence.verify == nil {
		return nil, errDarwinNative
	}
	hash := strings.TrimPrefix(config.UICodeIdentity, "cdhash:")
	decoded, err := hex.DecodeString(hash)
	if err != nil || hash == config.UICodeIdentity || (len(decoded) != 20 && len(decoded) != 32) || hash != strings.ToLower(hash) {
		return nil, errDarwinNative
	}
	p := &darwinNativePlatform{uid: *config.AllowedUserUID, presence: presence}
	p.calls = darwinNativeCalls{peer: darwinNativePeer, console: darwinNativeConsole, interfaces: darwinNativeInterfaces, network: darwinNativeNetworkRead, read: darwinNativeSetting, cas: darwinNativeSettingCAS, routes: darwinNativeRoutes, routeWrite: darwinNativeRouteWrite, bind: darwinNativeBind, lookup: darwinNativeLookup, listener: darwinNativeListener, flushCommand: darwinNativeFlushCommand}
	requirement := `cdhash H"` + hash + `"`
	p.calls.code = func(token [8]uint32) error {
		req, path := C.CString(requirement), C.CString(config.UIExecutable)
		defer C.free(unsafe.Pointer(req))
		defer C.free(unsafe.Pointer(path))
		if C.ni_code((*C.uint)(unsafe.Pointer(&token[0])), req, path) != 0 {
			return errDarwinNative
		}
		return nil
	}
	return p, nil
}
func darwinNativePeer(conn net.Conn) (token [8]uint32, err error) {
	peer, ok := conn.(*net.UnixConn)
	if !ok {
		return token, errDarwinNative
	}
	raw, err := peer.SyscallConn()
	if err != nil {
		return token, err
	}
	status := C.int(-1)
	err = raw.Control(func(fd uintptr) { status = C.ni_peer(C.int(fd), (*C.uint)(unsafe.Pointer(&token[0]))) })
	if err == nil && status != 0 {
		err = errDarwinNative
	}
	return
}
func darwinNativeConsole(uid, asid uint32) error {
	if C.ni_console(C.uint(uid), C.uint(asid)) != 0 {
		return errDarwinNative
	}
	return nil
}
func (p *darwinNativePlatform) Authenticate(ctx context.Context, conn net.Conn) (NativePeer, error) {
	token, err := p.calls.peer(conn)
	if err != nil {
		return NativePeer{}, err
	}
	if token[0] != p.uid || token[1] != p.uid || token[3] != p.uid || token[5] == 0 || token[6] == 0 || token[7] == 0 {
		return NativePeer{}, errDarwinNative
	}
	if p.presence == nil || p.presence.verify == nil {
		return NativePeer{}, errDarwinNative
	}
	if err = p.presence.verify(conn); err != nil {
		return NativePeer{}, err
	}
	second, err := p.calls.peer(conn)
	if err != nil || second != token {
		return NativePeer{}, errDarwinNative
	}
	s := &darwinNativeSession{platform: p, token: token, owner: nativeOwner{UserID: strconv.FormatUint(uint64(p.uid), 10), SessionID: strconv.FormatUint(uint64(token[6]), 10)}}
	if err = s.Validate(ctx, false); err != nil {
		return NativePeer{}, err
	}
	return NativePeer{owner: s.owner, pid: token[5], session: s}, nil
}
func (p *darwinNativePlatform) AcquireRestoreSession(ctx context.Context, owner nativeOwner) (nativeSession, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	asid, err := strconv.ParseUint(owner.SessionID, 10, 32)
	if owner.UserID != strconv.FormatUint(uint64(p.uid), 10) || err != nil || asid == 0 || owner.SessionID != strconv.FormatUint(asid, 10) {
		return nil, errDarwinNative
	}
	return &darwinNativeSession{platform: p, owner: owner, restoreOnly: true}, nil
}
func (s *darwinNativeSession) Owner() nativeOwner { return s.owner }
func (s *darwinNativeSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}
func (s *darwinNativeSession) Validate(ctx context.Context, restore bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.closed || s.owner.UserID != strconv.FormatUint(uint64(s.platform.uid), 10) {
		return errDarwinNative
	}
	if restore {
		return nil
	}
	if s.restoreOnly {
		return errDarwinNative
	}
	if err := s.platform.calls.console(s.platform.uid, s.token[6]); err != nil {
		return err
	}
	return s.platform.calls.code(s.token)
}
func (p *darwinNativePlatform) session(s nativeSession, ctx context.Context, restore bool) error {
	own, ok := s.(*darwinNativeSession)
	if !ok || own.platform != p {
		return errDarwinNative
	}
	return own.Validate(ctx, restore)
}
func nativeDarwinJSON(ptr *C.char, out any) error {
	if ptr == nil {
		return errDarwinNative
	}
	defer C.free(unsafe.Pointer(ptr))
	raw := C.GoString(ptr)
	if len(raw) > 1<<20 {
		return errDarwinNative
	}
	return json.Unmarshal([]byte(raw), out)
}
func darwinNativeNetworkRead() (out darwinNativeNetwork, err error) {
	err = nativeDarwinJSON(C.ni_network(), &out)
	return
}
func darwinNativeInterfaces() ([]nativeInterface, error) {
	var rows []struct {
		Name      string
		Index     uint32
		Kind      string
		Stamp     string
		Addresses []string
	}
	if err := nativeDarwinJSON(C.ni_interfaces(), &rows); err != nil {
		return nil, err
	}
	if len(rows) > 256 {
		return nil, errDarwinNative
	}
	result := make([]nativeInterface, 0, len(rows))
	for _, row := range rows {
		if row.Index == 0 || row.Name == "" || row.Stamp == "" || row.Stamp == "0:0" || len(row.Addresses) > 64 {
			return nil, errDarwinNative
		}
		item := nativeInterface{Name: row.Name, Index: row.Index, Kind: row.Kind}
		slices.Sort(row.Addresses)
		for _, s := range row.Addresses {
			v, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, err
			}
			item.Addresses = append(item.Addresses, v)
		}
		encoded, _ := json.Marshal(row)
		hash := sha256.Sum256(encoded)
		item.ID = hex.EncodeToString(hash[:])
		result = append(result, item)
	}
	slices.SortFunc(result, func(a, b nativeInterface) int { return strings.Compare(a.Name, b.Name) })
	return result, nil
}
func darwinNativeSetting(service, entity, field string) (json.RawMessage, error) {
	s, e, f := C.CString(service), C.CString(entity), C.CString(field)
	defer C.free(unsafe.Pointer(s))
	defer C.free(unsafe.Pointer(e))
	defer C.free(unsafe.Pointer(f))
	var v json.RawMessage
	err := nativeDarwinJSON(C.ni_setting(s, e, f), &v)
	return v, err
}
func darwinNativeSettingCAS(service, entity, field string, before, after json.RawMessage) (string, error) {
	args := []*C.char{C.CString(service), C.CString(entity), C.CString(field), C.CString(string(before)), C.CString(string(after))}
	defer func() {
		for _, v := range args {
			C.free(unsafe.Pointer(v))
		}
	}()
	status := int(C.ni_setting_cas(args[0], args[1], args[2], args[3], args[4]))
	outcomes := []string{"applied", "conflict", "not_applied", "unknown"}
	if status < 0 || status >= len(outcomes) {
		return "unknown", errDarwinNative
	}
	if status != 0 {
		return outcomes[status], errDarwinNative
	}
	return outcomes[status], nil
}
func darwinNativeField(change nativeChange) (entity, field string, err error) {
	if change.Scope.ServiceID == "" || len(change.Scope.ServiceID) > 256 {
		return "", "", errDarwinNative
	}
	switch change.Kind {
	case "dns":
		return "DNS", "ServerAddresses", nil
	case "proxy":
		if slices.Contains(darwinProxyFields, change.Field) {
			return "Proxies", change.Field, nil
		}
	}
	return "", "", errDarwinNative
}
func darwinNativeDecode(change nativeChange, raw json.RawMessage) (nativeValue, error) {
	absent := string(raw) == "null"
	v := nativeValue{Present: !absent}
	if change.Kind == "dns" {
		dns := &nativeDNSConfig{Automatic: absent}
		v.DNS = dns
		if !absent {
			var servers []string
			if err := json.Unmarshal(raw, &servers); err != nil {
				return v, err
			}
			if len(servers) > 64 {
				return v, errDarwinNative
			}
			for _, s := range servers {
				a, err := netip.ParseAddr(s)
				if err != nil {
					return v, err
				}
				dns.Servers = append(dns.Servers, a)
			}
		}
		return v, nil
	}
	if absent {
		return v, nil
	}
	v.Proxy = &nativeProxyValue{}
	if strings.HasSuffix(change.Field, "Enable") {
		var flag uint32
		if err := json.Unmarshal(raw, &flag); err != nil || flag > 1 {
			return v, errDarwinNative
		}
		v.Proxy.Bool = flag == 1
	} else if strings.HasSuffix(change.Field, "Port") {
		if err := json.Unmarshal(raw, &v.Proxy.Number); err != nil || v.Proxy.Number > 65535 {
			return v, errDarwinNative
		}
	} else if err := json.Unmarshal(raw, &v.Proxy.Text); err != nil || len(v.Proxy.Text) > 4096 {
		return v, errDarwinNative
	}
	return v, nil
}
func darwinNativeEncode(change nativeChange, v nativeValue) (json.RawMessage, error) {
	if !v.Present {
		return json.RawMessage("null"), nil
	}
	if change.Kind == "dns" {
		if v.DNS == nil || v.DNS.Automatic {
			return nil, errDarwinNative
		}
		servers := make([]string, 0, len(v.DNS.Servers))
		for _, a := range v.DNS.Servers {
			if !a.IsValid() {
				return nil, errDarwinNative
			}
			servers = append(servers, a.String())
		}
		return json.Marshal(servers)
	}
	if v.Proxy == nil {
		return nil, errDarwinNative
	}
	if strings.HasSuffix(change.Field, "Enable") {
		if v.Proxy.Bool {
			return json.RawMessage("1"), nil
		}
		return json.RawMessage("0"), nil
	}
	if strings.HasSuffix(change.Field, "Port") {
		return json.Marshal(v.Proxy.Number)
	}
	return json.Marshal(v.Proxy.Text)
}
func (p *darwinNativePlatform) Snapshot(ctx context.Context, s nativeSession) (nativeSnapshot, error) {
	return p.snapshot(ctx, s, false)
}

// RecoverySnapshot is read-only cleanup evidence and conveys no active authorization.
func (p *darwinNativePlatform) RecoverySnapshot(ctx context.Context, s nativeSession) (nativeSnapshot, error) {
	if err := p.session(s, ctx, true); err != nil {
		return nativeSnapshot{}, err
	}
	interfaces, err := p.calls.interfaces()
	if err != nil {
		return nativeSnapshot{}, err
	}
	if err = p.session(s, ctx, true); err != nil {
		return nativeSnapshot{}, err
	}
	return nativeSnapshot{Interfaces: interfaces}, nil
}
func (p *darwinNativePlatform) snapshot(ctx context.Context, s nativeSession, restore bool) (nativeSnapshot, error) {
	var snap nativeSnapshot
	if err := p.session(s, ctx, restore); err != nil {
		return snap, err
	}
	interfaces, err := p.calls.interfaces()
	if err != nil {
		return snap, err
	}
	network, err := p.calls.network()
	if err != nil {
		return snap, err
	}
	if network.IPv4 != "" && network.IPv6 != "" && network.IPv4 != network.IPv6 {
		return snap, errDarwinNative
	}
	snap.PrimaryServiceID = network.IPv4
	if snap.PrimaryServiceID == "" {
		snap.PrimaryServiceID = network.IPv6
	}
	if snap.PrimaryServiceID == "" {
		return snap, errDarwinNative
	}
	// An Ethernet-looking VPN is not physical without a matching public SC interface type.
	for i := range interfaces {
		if interfaces[i].Kind == "physical" {
			interfaces[i].Kind = "unknown"
			for _, svc := range network.Services {
				if svc.Interface == interfaces[i].Name && (svc.Type == "Ethernet" || svc.Type == "IEEE80211") {
					interfaces[i].Kind = "physical"
				}
			}
		}
	}
	snap.Interfaces = interfaces
	snap.Routes, err = p.calls.routes(interfaces)
	if err != nil {
		return snap, err
	}
	var primary nativeInterface
	for _, svc := range network.Services {
		if svc.ID == snap.PrimaryServiceID {
			snap.PrimaryServiceName = svc.Name
			for _, iface := range interfaces {
				if iface.Name == svc.Interface {
					primary = iface
				}
			}
		}
	}
	if primary.ID == "" {
		return snap, errDarwinNative
	}
	for _, field := range append(slices.Clone(darwinProxyFields), "ServerAddresses") {
		change := nativeChange{ID: "darwin:" + snap.PrimaryServiceID + ":" + field, Kind: "proxy", Scope: nativeScope{ServiceID: snap.PrimaryServiceID, Interface: primary}, Field: field}
		if field == "ServerAddresses" {
			change.Kind = "dns"
			change.Field = ""
		}
		change.Before, err = p.readSetting(change)
		if err != nil {
			return snap, err
		}
		snap.Settings = append(snap.Settings, change)
	}
	for _, r := range network.Resolvers {
		if len(r.Value.ServerAddresses) > 64 || len(r.Value.SupplementalMatchDomains) > 64 {
			return snap, errDarwinNative
		}
		if len(r.Value.ServerAddresses) == 0 {
			continue
		}
		scope := nativeResolverScope{ID: r.ID, Domains: r.Value.SupplementalMatchDomains, Default: len(r.Value.SupplementalMatchDomains) == 0, Priority: r.Value.SearchOrder}
		for _, iface := range interfaces {
			if iface.Name == r.Value.InterfaceName {
				scope.Interface = iface
			}
		}

		if scope.Interface.ID == "" {
			for _, svc := range network.Services {
				if r.ID == "State:/Network/Service/"+svc.ID+"/DNS" {
					for _, iface := range interfaces {
						if iface.Name == svc.Interface {
							scope.Interface = iface
						}
					}
				}
			}
		}
		if scope.Interface.ID == "" && r.ID == "State:/Network/Global/DNS" && scope.Default {
			scope.Interface = primary
		}
		if scope.Interface.ID == "" {
			return snap, errDarwinNative
		}
		for _, server := range r.Value.ServerAddresses {
			a, e := netip.ParseAddr(server)
			if e != nil {
				return snap, e
			}
			scope.Servers = append(scope.Servers, a)
		}
		if len(r.Value.SupplementalMatchOrders) > 0 {
			for _, order := range r.Value.SupplementalMatchOrders {
				if order != r.Value.SupplementalMatchOrders[0] {
					return snap, errDarwinNative
				}
			}
			scope.Priority = r.Value.SupplementalMatchOrders[0]
		}
		snap.Resolvers = append(snap.Resolvers, scope)
	}
	slices.SortFunc(snap.Resolvers, func(a, b nativeResolverScope) int { return strings.Compare(a.ID, b.ID) })
	encoded, _ := json.Marshal(snap)
	hash := sha256.Sum256(encoded)
	snap.Generation = binary.BigEndian.Uint64(hash[:8])
	if err = p.session(s, ctx, restore); err != nil {
		return nativeSnapshot{}, err
	}
	return snap, nil
}
func (p *darwinNativePlatform) readSetting(c nativeChange) (nativeValue, error) {
	entity, field, err := darwinNativeField(c)
	if err != nil {
		return nativeValue{}, err
	}
	raw, err := p.calls.read(c.Scope.ServiceID, entity, field)
	if err != nil {
		return nativeValue{}, err
	}
	return darwinNativeDecode(c, raw)
}
func (p *darwinNativePlatform) ReadChange(ctx context.Context, s nativeSession, c nativeChange) (nativeValue, error) {
	if err := p.session(s, ctx, true); err != nil {
		return nativeValue{}, err
	}
	if c.Kind != "route" {
		return p.readSetting(c)
	}
	interfaces, err := p.calls.interfaces()
	if err != nil {
		return nativeValue{}, err
	}
	routes, err := p.calls.routes(interfaces)
	if err != nil {
		return nativeValue{}, err
	}
	target := c.After.Route
	if target == nil {
		target = c.Before.Route
	}
	if target == nil || !target.Destination.IsValid() {
		return nativeValue{}, errDarwinNative
	}
	var found *nativeRoute
	for _, r := range routes {
		if r.Destination == target.Destination && r.Interface.Index == c.Scope.Interface.Index {
			if found != nil {
				return nativeValue{}, errDarwinNative
			}
			copy := r
			found = &copy
		}
	}
	if found == nil {
		return nativeValue{}, nil
	}
	return nativeValue{Present: true, Route: found}, nil
}
func (p *darwinNativePlatform) CompareApply(ctx context.Context, s nativeSession, c nativeChange) (nativeReceipt, error) {
	return p.compare(ctx, s, c, false)
}
func (p *darwinNativePlatform) CompareRestore(ctx context.Context, s nativeSession, c nativeChange) (nativeReceipt, error) {
	return p.compare(ctx, s, c, true)
}
func (p *darwinNativePlatform) compare(ctx context.Context, s nativeSession, c nativeChange, restore bool) (nativeReceipt, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	receipt := nativeReceipt{ChangeID: c.ID, Outcome: "not_applied"}
	if err := p.session(s, ctx, restore); err != nil {
		return receipt, err
	}
	before, after := c.Before, c.After
	if restore {
		before, after = after, before
	}
	current, err := p.ReadChange(ctx, s, c)
	receipt.Current = current
	if err != nil {
		return receipt, err
	}
	if !reflect.DeepEqual(current, before) {
		receipt.Outcome = "conflict"
		return receipt, errDarwinNative
	}
	if c.Kind == "route" {
		if before.Present && after.Present {
			return receipt, errors.New("route replacement requires separate journalled delete and add")
		}
		target := after.Route
		if !after.Present {
			target = before.Route
		}
		if target == nil || target.Interface.ID != c.Scope.Interface.ID {
			return receipt, errDarwinNative
		}
		interfaces, e := p.calls.interfaces()
		if e != nil {
			return receipt, e
		}
		valid := false
		for _, iface := range interfaces {
			if darwinNativeSameInterface(iface, c.Scope.Interface) {
				valid = true
			}
		}
		if !valid {
			return receipt, errDarwinNative
		}
		receipt.Outcome = "unknown"
		err = p.calls.routeWrite(*target, after.Present)
	} else {
		entity, field, e := darwinNativeField(c)
		if e != nil {
			return receipt, e
		}
		b, e := darwinNativeEncode(c, before)
		if e != nil {
			return receipt, e
		}
		a, e := darwinNativeEncode(c, after)
		if e != nil {
			return receipt, e
		}
		receipt.Outcome, err = p.calls.cas(c.Scope.ServiceID, entity, field, b, a)
	}
	if err != nil {
		var errno syscall.Errno
		if c.Kind == "route" && errors.As(err, &errno) {
			receipt.Outcome = "not_applied"
		}
		return receipt, err
	}
	current, err = p.ReadChange(ctx, s, c)
	receipt.Current = current
	if err != nil || !reflect.DeepEqual(current, after) {
		receipt.Outcome = "unknown"
		return receipt, errors.Join(err, errDarwinNative)
	}
	receipt.Outcome = "applied"
	if err = p.session(s, ctx, restore); err != nil {
		return receipt, err
	}
	return receipt, nil
}
func darwinNativeSameInterface(a, b nativeInterface) bool {
	return a.ID != "" && a.ID == b.ID && a.Index == b.Index && a.Name == b.Name && slices.Equal(a.Addresses, b.Addresses)
}

func (p *darwinNativePlatform) PlanChanges(s nativeSnapshot, plan nativeInterceptionPlan) ([]nativeChange, error) {
	return darwinNativePlan(s, plan, uint32(unix.RTF_UP|unix.RTF_STATIC))
}
func darwinNativeAddr(a route.Addr) netip.Addr {
	switch v := a.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(v.IP)
	case *route.Inet6Addr:
		ip := v.IP
		// Darwin embeds scope IDs in link-local sockaddr addresses.
		if ip[0] == 0xfe && ip[1]&0xc0 == 0x80 {
			ip[2] = 0
			ip[3] = 0
		}
		addr := netip.AddrFrom16(ip)
		if v.ZoneID != 0 && addr.IsLinkLocalUnicast() {
			addr = addr.WithZone(strconv.Itoa(v.ZoneID))
		}
		return addr
	}
	return netip.Addr{}
}
func darwinNativeRouteDecode(raw []byte, interfaces []nativeInterface) (nativeRoute, error) {
	var result nativeRoute
	messages, err := route.ParseRIB(route.RIBTypeRoute, raw)
	if err != nil || len(messages) != 1 {
		return result, errDarwinNative
	}
	msg, ok := messages[0].(*route.RouteMessage)
	if !ok {
		return result, errDarwinNative
	}
	if msg.Err != nil {
		return result, msg.Err
	}
	if len(msg.Addrs) <= unix.RTAX_NETMASK {
		return result, errDarwinNative
	}
	for _, iface := range interfaces {
		if int(iface.Index) == msg.Index {
			result.Interface = iface
		}
	}
	if result.Interface.ID == "" {
		return result, errDarwinNative
	}
	dest := darwinNativeAddr(msg.Addrs[unix.RTAX_DST]).WithZone("")
	if !dest.IsValid() {
		return result, errDarwinNative
	}
	bits := 0
	if mask := darwinNativeAddr(msg.Addrs[unix.RTAX_NETMASK]); mask.IsValid() {
		bytes := mask.AsSlice()
		zero := false
		for _, b := range bytes {
			for bit := 7; bit >= 0; bit-- {
				if b&(1<<bit) != 0 {
					if zero {
						return result, errDarwinNative
					}
					bits++
				} else {
					zero = true
				}
			}
		}
	}
	if msg.Flags&unix.RTF_HOST != 0 {
		bits = dest.BitLen()
	}
	result.Destination = netip.PrefixFrom(dest, bits).Masked()
	result.Gateway = darwinNativeAddr(msg.Addrs[unix.RTAX_GATEWAY])
	result.Flags = uint32(msg.Flags)
	if result.Gateway.IsLinkLocalUnicast() {
		result.Gateway = result.Gateway.WithZone(strconv.Itoa(int(result.Interface.Index)))
	}
	result.Metric = uint32(C.ni_route_metric(unsafe.Pointer(&raw[0]), C.int(len(raw))))
	return result, nil
}
func darwinNativeRoutes(interfaces []nativeInterface) ([]nativeRoute, error) {
	raw, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	if len(raw) > 4<<20 {
		return nil, errDarwinNative
	}
	var results []nativeRoute
	for len(raw) > 0 {
		if len(raw) < 4 {
			return nil, errDarwinNative
		}
		size := int(binary.LittleEndian.Uint16(raw))
		if size < 4 || size > len(raw) {
			return nil, errDarwinNative
		}
		// Some cloned/link-layer routes have no IP prefix and are not capture candidates.
		r, err := darwinNativeRouteDecode(raw[:size], interfaces)
		if err == nil {
			results = append(results, r)
		}
		raw = raw[size:]
		if len(results) > 16384 {
			return nil, errDarwinNative
		}
	}
	slices.SortFunc(results, func(a, b nativeRoute) int {
		if d := strings.Compare(a.Destination.String(), b.Destination.String()); d != 0 {
			return d
		}
		return int(a.Interface.Index) - int(b.Interface.Index)
	})
	return results, nil
}

var darwinNativeSequence atomic.Int32

func darwinNativeSockAddr(addr netip.Addr) route.Addr {
	if addr.Is4() {
		return &route.Inet4Addr{IP: addr.As4()}
	}
	if addr.Is6() {
		zone, _ := strconv.Atoi(addr.Zone())
		return &route.Inet6Addr{IP: addr.WithZone("").As16(), ZoneID: zone}
	}
	return nil
}
func darwinNativeExchange(msg *route.RouteMessage, metric uint32) ([]byte, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	unix.CloseOnExec(fd)
	if err = unix.SetNonblock(fd, true); err != nil {
		return nil, err
	}
	msg.Version = unix.RTM_VERSION
	msg.ID = uintptr(os.Getpid())
	msg.Seq = int(darwinNativeSequence.Add(1))
	raw, err := msg.Marshal()
	if err != nil {
		return nil, err
	}
	if msg.Type == unix.RTM_ADD || msg.Type == unix.RTM_DELETE {
		if C.ni_route_setmetric(unsafe.Pointer(&raw[0]), C.int(len(raw)), C.uint(metric)) != 0 {
			return nil, errDarwinNative
		}
	}
	if n, e := unix.Write(fd, raw); e != nil || n != len(raw) {
		return nil, errors.Join(e, errDarwinNative)
	}
	deadline := time.Now().Add(2 * time.Second)
	buffer := make([]byte, 65536)
	for time.Now().Before(deadline) {
		polls := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if _, err = unix.Poll(polls, 100); err != nil {
			return nil, err
		}
		if polls[0].Revents&unix.POLLIN == 0 {
			continue
		}
		n, e := unix.Read(fd, buffer)
		if e == unix.EAGAIN {
			continue
		}
		if e != nil {
			return nil, e
		}
		messages, e := route.ParseRIB(route.RIBTypeRoute, buffer[:n])
		if e != nil {
			return nil, e
		}
		for _, m := range messages {
			reply, ok := m.(*route.RouteMessage)
			if ok && reply.ID == msg.ID && reply.Seq == msg.Seq {
				if reply.Err != nil {
					return nil, reply.Err
				}
				return slices.Clone(buffer[:n]), nil
			}
		}
	}
	return nil, errors.New("macOS route acknowledgement unknown")
}
func darwinNativeRouteWrite(r nativeRoute, add bool) error {
	if !r.Destination.IsValid() || r.Interface.ID == "" || r.Interface.Index == 0 {
		return errDarwinNative
	}
	addrs := make([]route.Addr, unix.RTAX_MAX)
	addrs[unix.RTAX_DST] = darwinNativeSockAddr(r.Destination.Addr())
	mask := net.CIDRMask(r.Destination.Bits(), r.Destination.Addr().BitLen())
	m, _ := netip.AddrFromSlice(mask)
	addrs[unix.RTAX_NETMASK] = darwinNativeSockAddr(m)
	if r.Gateway.IsValid() {
		addrs[unix.RTAX_GATEWAY] = darwinNativeSockAddr(r.Gateway)
	} else {
		addrs[unix.RTAX_GATEWAY] = &route.LinkAddr{Index: int(r.Interface.Index)}
	}
	addrs[unix.RTAX_IFP] = &route.LinkAddr{Index: int(r.Interface.Index)}
	typ := unix.RTM_DELETE
	if add {
		typ = unix.RTM_ADD
	}
	_, err := darwinNativeExchange(&route.RouteMessage{Type: typ, Index: int(r.Interface.Index), Flags: int(r.Flags), Addrs: addrs}, r.Metric)
	return err
}
func darwinNativeLookup(dest netip.Addr, iface nativeInterface) (nativeRoute, error) {
	addrs := make([]route.Addr, unix.RTAX_MAX)
	addrs[unix.RTAX_DST] = darwinNativeSockAddr(dest)
	addrs[unix.RTAX_IFP] = &route.LinkAddr{Index: int(iface.Index)}
	raw, err := darwinNativeExchange(&route.RouteMessage{Type: unix.RTM_GET, Index: int(iface.Index), Flags: unix.RTF_IFSCOPE, Addrs: addrs}, 0)
	if err != nil {
		return nativeRoute{}, err
	}
	return darwinNativeRouteDecode(raw, []nativeInterface{iface})
}
func (p *darwinNativePlatform) SelectExit(ctx context.Context, dest netip.Addr, snap nativeSnapshot, wg TunnelReadback) (nativeExit, error) {
	if ctx.Err() != nil {
		return nativeExit{}, ctx.Err()
	}
	if !dest.IsValid() || dest.IsUnspecified() || dest.IsMulticast() || dest.IsLoopback() {
		return nativeExit{}, errDarwinNative
	}
	exit, err := darwinNativeChooseExit(dest, snap, wg, uint32(unix.RTF_UP), uint32(unix.RTF_REJECT|unix.RTF_BLACKHOLE))
	if err != nil {
		return exit, err
	}

	var expected *nativeRoute
	for _, r := range snap.Routes {
		if r.Destination.Contains(dest) && darwinNativeSameInterface(r.Interface, exit.Interface) && r.Gateway == exit.Gateway && (expected == nil || r.Destination.Bits() > expected.Destination.Bits()) {
			copy := r
			expected = &copy
		}
	}
	if expected == nil {
		return nativeExit{}, errDarwinNative
	}
	actual, err := p.calls.lookup(dest, exit.Interface)
	if err != nil {
		return nativeExit{}, err
	}
	if actual.Metric != expected.Metric || actual.Flags & ^uint32(unix.RTF_DONE) != expected.Flags & ^uint32(unix.RTF_DONE) {
		return nativeExit{}, errDarwinNative
	}
	exit.Route = actual
	if err = p.verifyExit(dest, exit); err != nil {
		return nativeExit{}, err
	}
	return exit, nil
}
func (p *darwinNativePlatform) verifyExit(dest netip.Addr, exit nativeExit) error {
	interfaces, err := p.calls.interfaces()
	if err != nil {
		return err
	}
	found := false
	for _, iface := range interfaces {
		if darwinNativeSameInterface(iface, exit.Interface) {
			found = true
		}
	}
	if !found {
		return errDarwinNative
	}
	actual, err := p.calls.lookup(dest, exit.Interface)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, exit.Route) {
		return errDarwinNative
	}
	if !darwinNativeSameInterface(actual.Interface, exit.Interface) || actual.Gateway != exit.Gateway || actual.Flags&unix.RTF_UP == 0 || actual.Flags&(unix.RTF_REJECT|unix.RTF_BLACKHOLE) != 0 {
		return errDarwinNative
	}
	if !slices.ContainsFunc(exit.Interface.Addresses, func(prefix netip.Prefix) bool { return prefix.Addr().WithZone("") == exit.Source.WithZone("") }) {
		return errDarwinNative
	}
	return nil
}
func (p *darwinNativePlatform) Control(exit nativeExit) func(string, string, syscall.RawConn) error {
	return func(network, address string, raw syscall.RawConn) error {
		if network != "tcp4" && network != "tcp6" && network != "udp4" && network != "udp6" {
			return errDarwinNative
		}
		target, err := netip.ParseAddrPort(address)
		if err != nil || target.Addr().Is4() != exit.Source.Is4() || strings.HasSuffix(network, "4") != exit.Source.Is4() {
			return errDarwinNative
		}
		if err = p.verifyExit(target.Addr(), exit); err != nil {
			return err
		}
		if err = p.calls.bind(raw, exit.Interface.Index, exit.Source); err != nil {
			return err
		}
		return p.verifyExit(target.Addr(), exit)
	}
}
func darwinNativeBind(raw syscall.RawConn, index uint32, source netip.Addr) error {
	var socketErr error
	err := raw.Control(func(fd uintptr) {
		if source.Is4() {
			socketErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, int(index))
			if socketErr == nil {
				socketErr = unix.Bind(int(fd), &unix.SockaddrInet4{Addr: source.As4()})
			}
		} else if source.Is6() {
			socketErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, int(index))
			if socketErr == nil {
				socketErr = unix.Bind(int(fd), &unix.SockaddrInet6{Addr: source.WithZone("").As16(), ZoneId: index})
			}
		} else {
			socketErr = errDarwinNative
		}
	})
	return errors.Join(err, socketErr)
}

func (p *darwinNativePlatform) VerifyListenerOwner(ctx context.Context, s nativeSession, network string, endpoint netip.AddrPort, pid uint32) error {
	if err := p.session(s, ctx, false); err != nil {
		return err
	}
	if pid == 0 || !endpoint.IsValid() || endpoint.Port() == 0 || (endpoint.Addr() != netip.MustParseAddr("127.0.0.1") && endpoint.Addr() != netip.IPv6Loopback()) || (network != "tcp" && network != "udp") || p.calls.listener == nil {
		return errDarwinNative
	}
	if err := p.calls.listener(network, endpoint, pid); err != nil {
		return err
	}
	return p.session(s, ctx, false)
}
func darwinNativeListener(network string, endpoint netip.AddrPort, pid uint32) error {
	tcp := 0
	if network == "tcp" {
		tcp = 1
	}
	family := unix.AF_INET6
	if endpoint.Addr().Is4() {
		family = unix.AF_INET
	}
	address := endpoint.Addr().AsSlice()
	if C.ni_listener(C.uint(pid), C.int(tcp), C.int(family), C.ushort(endpoint.Port()), unsafe.Pointer(&address[0])) != 0 {
		return errDarwinNative
	}
	return nil
}

// These fixed requests do not establish that application-owned DNS caches were cleared.
func (p *darwinNativePlatform) FlushResolverCache(ctx context.Context, s nativeSession) error {
	if err := p.session(s, ctx, true); err != nil {
		return err
	}
	if p.calls.flushCommand == nil {
		return errors.New("macOS resolver cache request unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, command := range []struct {
		path string
		args []string
	}{{"/usr/bin/dscacheutil", []string{"-flushcache"}}, {"/bin/launchctl", []string{"kill", "SIGHUP", "system/com.apple.mDNSResponder"}}} {
		if ctx.Err() != nil {
			return errors.New("macOS resolver cache request incomplete")
		}
		if err := p.session(s, ctx, true); err != nil {
			return errors.New("macOS resolver cache request not authorized")
		}
		if err := p.calls.flushCommand(ctx, command.path, command.args...); err != nil {
			return errors.New("macOS resolver cache request incomplete")
		}
	}
	if ctx.Err() != nil {
		return errors.New("macOS resolver cache request incomplete")
	}
	return p.session(s, ctx, true)
}
func darwinNativeFlushCommand(ctx context.Context, path string, args ...string) error {
	cmd := exec.CommandContext(ctx, path, args...)
	// Nil standard streams are connected to the null device by os/exec.
	return cmd.Run()
}
