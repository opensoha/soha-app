//go:build windows

package endpointservice

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"unsafe"
)

type winNativePlatform struct {
	config     Config
	presence   *UIProcessPresence
	mu         sync.Mutex
	generation uint64
}
type winNativeSession struct {
	mu                  sync.Mutex
	owner               nativeOwner
	process             windows.Handle
	token               windows.Token
	pid, session        uint32
	created             windows.Filetime
	restoreOnly, closed bool
}

func newNativeInterceptionPlatform(c Config, p *UIProcessPresence) (nativePlatform, error) {
	if !validSID(c.AllowedUserSID) || c.UIExecutable == "" || !validReadbackHash(c.UICodeIdentity) || p == nil || p.verify == nil {
		return nil, errors.New("native interception UI identity is not provisioned")
	}
	return &winNativePlatform{config: c, presence: p}, nil
}
func (p *winNativePlatform) Authenticate(ctx context.Context, c net.Conn) (NativePeer, error) {
	if err := ctx.Err(); err != nil {
		return NativePeer{}, err
	}
	pipe, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return NativePeer{}, errors.New("native interception requires a named pipe")
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(windows.Handle(pipe.Fd()), &pid); err != nil || pid == 0 {
		return NativePeer{}, errors.New("pipe has no authenticated client PID")
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return NativePeer{}, err
	}
	s := &winNativeSession{process: h, pid: pid}
	success := false
	defer func() {
		if !success {
			s.Close()
		}
	}()
	var exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &s.created, &exit, &kernel, &user); err != nil {
		return NativePeer{}, err
	}
	var token windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY, &token); err != nil {
		return NativePeer{}, err
	}
	defer token.Close()
	if err := windows.DuplicateTokenEx(token, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &s.token); err != nil {
		return NativePeer{}, err
	}
	u, err := token.GetTokenUser()
	if err != nil || u.User.Sid.String() != p.config.AllowedUserSID {
		return NativePeer{}, errors.New("native pipe user does not match enrollment")
	}
	if err := windows.ProcessIdToSessionId(pid, &s.session); err != nil || s.session != windows.WTSGetActiveConsoleSessionId() {
		return NativePeer{}, errors.New("UI is not in the active console session")
	}
	s.owner = nativeOwner{UserID: p.config.AllowedUserSID, SessionID: strconv.FormatUint(uint64(s.session), 10)}
	if err := p.presence.verify(c); err != nil {
		return NativePeer{}, err
	}
	var again uint32
	if err := windows.GetNamedPipeClientProcessId(windows.Handle(pipe.Fd()), &again); err != nil || again != pid {
		return NativePeer{}, errors.New("pipe identity changed")
	}
	if err := s.Validate(ctx, false); err != nil {
		return NativePeer{}, err
	}
	success = true
	return NativePeer{owner: s.owner, pid: pid, session: s}, nil
}
func (s *winNativeSession) Owner() nativeOwner { return s.owner }
func (s *winNativeSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.process != 0 {
		err = windows.CloseHandle(s.process)
	}
	if s.token != 0 {
		err = errors.Join(err, s.token.Close())
	}
	return err
}
func (s *winNativeSession) Validate(ctx context.Context, restore bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.closed || s.token == 0 || s.restoreOnly && !restore {
		return errors.New("native session cannot enable interception")
	}
	u, err := s.token.GetTokenUser()
	if err != nil || u.User.Sid.String() != s.owner.UserID {
		return errors.New("native session user changed")
	}
	var session uint32
	var size uint32
	if err := windows.GetTokenInformation(s.token, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), 4, &size); err != nil || session != s.session {
		return errors.New("native token session changed")
	}
	var current windows.Token
	if err := windows.WTSQueryUserToken(session, &current); err != nil {
		return errors.New("original desktop session unavailable; cleanup pending")
	}
	defer current.Close()
	cu, err := current.GetTokenUser()
	if err != nil || cu.User.Sid.String() != s.owner.UserID {
		return errors.New("original desktop user unavailable; cleanup pending")
	}
	if restore {
		return nil
	}
	if s.session != windows.WTSGetActiveConsoleSessionId() {
		return errors.New("active desktop changed")
	}
	event, err := windows.WaitForSingleObject(s.process, 0)
	if err != nil || event != uint32(windows.WAIT_TIMEOUT) {
		return errors.New("authenticated UI exited")
	}
	var created, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(s.process, &created, &exit, &kernel, &user); err != nil || created != s.created {
		return errors.New("UI creation identity changed")
	}
	return nil
}
func (p *winNativePlatform) AcquireRestoreSession(ctx context.Context, o nativeOwner) (nativeSession, error) {
	if o.UserID != p.config.AllowedUserSID {
		return nil, errors.New("journal owner differs from enrolled user")
	}
	id, err := strconv.ParseUint(o.SessionID, 10, 32)
	if err != nil {
		return nil, err
	}
	s := &winNativeSession{owner: o, session: uint32(id), restoreOnly: true}
	if err := windows.WTSQueryUserToken(s.session, &s.token); err != nil {
		return nil, errors.New("original desktop token unavailable; cleanup pending")
	}
	if err := s.Validate(ctx, true); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}
func (p *winNativePlatform) PlanChanges(s nativeSnapshot, plan nativeInterceptionPlan) ([]nativeChange, error) {
	return winNativePlan(s, plan)
}
func (p *winNativePlatform) ReadChange(ctx context.Context, s nativeSession, c nativeChange) (nativeValue, error) {
	return p.read(ctx, s, c, true)
}
func (p *winNativePlatform) read(ctx context.Context, s nativeSession, c nativeChange, restore bool) (nativeValue, error) {
	if err := winNativeValidate(c); err != nil {
		return nativeValue{}, err
	}
	if err := s.Validate(ctx, restore); err != nil {
		return nativeValue{}, err
	}
	switch c.Kind {
	case "proxy":
		result, err := winNativeCallHelper(ctx, s, winNativeHelperRequest{Field: c.Field})
		return result.Value, err
	case "dns":
		if err := winNativeCheckInterface(c.Scope.Interface); err != nil {
			return nativeValue{}, err
		}
		return winNativeDNSValue(c.Scope)
	case "route":
		routes, err := winNativeRoutes()
		if err != nil {
			return nativeValue{}, err
		}
		key := c.After.Route
		if key == nil {
			key = c.Before.Route
		}
		if key == nil {
			return nativeValue{}, errors.New("missing route key")
		}
		for _, r := range routes {
			if r.Destination == key.Destination && r.Interface.ID == key.Interface.ID && r.Gateway == key.Gateway {
				r := r
				return nativeValue{Present: true, Route: &r}, nil
			}
		}
		return nativeValue{}, nil
	}
	return nativeValue{}, errors.New("unknown change")
}
func (p *winNativePlatform) CompareApply(ctx context.Context, s nativeSession, c nativeChange) (nativeReceipt, error) {
	return p.compare(ctx, s, c, false)
}
func (p *winNativePlatform) CompareRestore(ctx context.Context, s nativeSession, c nativeChange) (nativeReceipt, error) {
	return p.compare(ctx, s, c, true)
}

// WinINet and IP Helper have no cross-application CAS: preflight + write + readback are best effort.
func (p *winNativePlatform) compare(ctx context.Context, s nativeSession, c nativeChange, restore bool) (nativeReceipt, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := s.(*winNativeSession); !ok {
		return nativeReceipt{ChangeID: c.ID, Outcome: "not_applied"}, errors.New("untrusted native session")
	}
	return winNativeCompare(ctx, s, c, restore, func() (nativeValue, error) { return p.read(ctx, s, c, restore) }, func(before, after nativeValue) error {
		switch c.Kind {
		case "proxy":
			_, err := winNativeCallHelper(ctx, s, winNativeHelperRequest{Field: c.Field, Write: true, Before: before, After: after, Restore: restore})
			return err
		case "dns":
			if err := winNativeCheckInterface(c.Scope.Interface); err != nil {
				return err
			}
			return winNativeWriteDNS(c.Scope, after)
		case "route":
			return winNativeWriteRoute(before, after)
		}
		return errors.New("unknown native change")
	})
}

func (p *winNativePlatform) Snapshot(ctx context.Context, s nativeSession) (nativeSnapshot, error) {
	if err := s.Validate(ctx, false); err != nil {
		return nativeSnapshot{}, err
	}
	interfaces, resolvers, err := winNativeAdapters()
	if err != nil {
		return nativeSnapshot{}, err
	}
	routes, err := winNativeRoutes()
	if err != nil {
		return nativeSnapshot{}, err
	}
	p.mu.Lock()
	p.generation++
	generation := p.generation
	p.mu.Unlock()
	out := nativeSnapshot{Generation: generation, Interfaces: interfaces, Resolvers: resolvers, Routes: routes}
	for _, f := range []string{"flags", "server", "bypass", "pac"} {
		c := nativeChange{ID: "wininet/" + f, Kind: "proxy", Field: f}
		v, err := winNativeCallHelper(ctx, s, winNativeHelperRequest{Field: f})
		if err != nil {
			return nativeSnapshot{}, err
		}
		c.Before = v.Value
		out.Settings = append(out.Settings, c)
	}
	for _, i := range interfaces {
		if i.Kind != "physical" {
			continue
		}
		for _, family := range []uint8{4, 6} {
			enabled := false
			for _, a := range i.Addresses {
				if a.Addr().Is4() == (family == 4) {
					enabled = true
				}
			}
			if !enabled {
				continue
			}
			scope := nativeScope{Interface: i, ServiceID: i.ID, Family: family}
			value, err := winNativeDNSValue(scope)
			if err != nil {
				return nativeSnapshot{}, err
			}
			out.Settings = append(out.Settings, nativeChange{ID: fmt.Sprintf("dns/%s/%d", i.ID, family), Kind: "dns", Scope: scope, Before: value})
		}
	}
	primary := ""
	for _, r := range routes {
		if r.Destination.Bits() == 0 && r.Interface.Kind == "physical" {
			if primary != "" && primary != r.Interface.ID {
				return nativeSnapshot{}, errors.New("multiple physical default services")
			}
			primary = r.Interface.ID
			out.PrimaryServiceName = r.Interface.Name
		}
	}
	out.PrimaryServiceID = primary
	if err := s.Validate(ctx, false); err != nil {
		return nativeSnapshot{}, err
	}
	return out, nil
}
func (p *winNativePlatform) SelectExit(ctx context.Context, d netip.Addr, s nativeSnapshot, wg TunnelReadback) (nativeExit, error) {
	return winNativeSelectExit(ctx, d, s, wg, winNativeCheckInterface, winNativeBestRoute)
}
func (p *winNativePlatform) Control(exit nativeExit) func(string, string, syscall.RawConn) error {
	return func(network, address string, raw syscall.RawConn) error {
		target, err := netip.ParseAddrPort(address)
		if err != nil {
			return errors.New("native control requires a numeric destination")
		}
		return winNativeGuardControl(exit, target, raw, winNativeCheckInterface, winNativeBestRoute, func(fd uintptr) error {
			level, option, index := windows.IPPROTO_IPV6, 31, exit.Interface.Index
			if target.Addr().Is4() {
				level = windows.IPPROTO_IP
				index = (index&255)<<24 | (index&65280)<<8 | (index>>8)&65280 | index>>24
			}
			if err := windows.SetsockoptInt(windows.Handle(fd), level, option, int(index)); err != nil {
				return err
			}
			got, err := windows.GetsockoptInt(windows.Handle(fd), level, option)
			if err != nil {
				return err
			}
			if uint32(got) != index {
				return errors.New("socket interface binding readback differs")
			}
			var sa windows.Sockaddr
			if exit.Source.Is4() {
				sa = &windows.SockaddrInet4{Addr: exit.Source.As4()}
			} else {
				zone := uint32(0)
				if exit.Source.IsLinkLocalUnicast() {
					zone = exit.Interface.Index
				}
				sa = &windows.SockaddrInet6{Addr: exit.Source.As16(), ZoneId: zone}
			}
			return windows.Bind(windows.Handle(fd), sa)
		})
	}
}

var _ nativePlatform = (*winNativePlatform)(nil)

// RecoverySnapshot is a read-only cleanup view; it never creates active authority.
func (p *winNativePlatform) RecoverySnapshot(ctx context.Context, s nativeSession) (nativeSnapshot, error) {
	return winRecoverySnapshot(ctx, s, func(ctx context.Context, s nativeSession, restore bool) error {
		actual, ok := s.(*winNativeSession)
		if !ok || actual == nil || actual.Owner().UserID != p.config.AllowedUserSID {
			return errors.New("untrusted recovery session")
		}
		return actual.Validate(ctx, restore)
	}, winRecoverySystemInterfaces)
}
func winRecoverySystemRows() ([]winRecoveryInterfaceRow, error) {
	var table *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(0, &table); err != nil {
		return nil, err
	}
	if table == nil {
		return nil, errors.New("complete recovery interface table unavailable")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	if table.NumEntries > 65536 {
		return nil, errors.New("recovery interface table exceeds bound")
	}
	out := make([]winRecoveryInterfaceRow, 0, table.NumEntries)
	for _, row := range unsafe.Slice(&table.Table[0], table.NumEntries) {
		kind := "unknown"
		switch {
		case row.Type == 24:
			kind = "loopback"
		case row.Type == 131 || row.Type == 53 || row.TunnelType != 0:
			kind = "tunnel"
		case row.InterfaceAndOperStatusFlags&1 != 0 && (row.Type == 6 || row.Type == 71):
			kind = "physical"
		}
		out = append(out, winRecoveryInterfaceRow{LUID: row.InterfaceLuid, Status: row.OperStatus, Octets: row.InOctets, Interface: nativeInterface{ID: row.InterfaceGuid.String(), Index: row.InterfaceIndex, Name: windows.UTF16ToString(row.Alias[:]), Kind: kind}})
	}
	return out, nil
}
func winRecoverySystemAddresses(ctx context.Context) ([]winRecoveryAddressRow, error) {
	size := uint32(16384)
	for tries := 0; tries < 4; tries++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if size < 1 || size > 4<<20 {
			return nil, errors.New("recovery address snapshot exceeds bound")
		}
		buffer := make([]byte, size)
		head := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		flags := uint32(windows.GAA_FLAG_INCLUDE_ALL_INTERFACES | windows.GAA_FLAG_SKIP_DNS_SERVER | windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_FRIENDLY_NAME)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, head, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var out []winRecoveryAddressRow
		count := 0
		for a := head; a != nil; a = a.Next {
			count++
			if count > 65536 || a.Length < uint32(unsafe.Offsetof(a.Luid)+unsafe.Sizeof(a.Luid)) {
				return nil, errors.New("invalid recovery adapter metadata")
			}
			entry := winRecoveryAddressRow{LUID: a.Luid}
			n := 0
			for u := a.FirstUnicastAddress; u != nil; u = u.Next {
				n++
				if n > 4096 || u.Length < uint32(unsafe.Offsetof(u.OnLinkPrefixLength)+unsafe.Sizeof(u.OnLinkPrefixLength)) {
					return nil, errors.New("invalid recovery unicast metadata")
				}
				address, ok := netip.AddrFromSlice(u.Address.IP())
				if !ok {
					return nil, errors.New("invalid recovery interface address")
				}
				address = address.Unmap()
				prefix := netip.PrefixFrom(address, int(u.OnLinkPrefixLength))
				if !prefix.IsValid() {
					return nil, errors.New("invalid recovery interface prefix")
				}
				entry.Addresses = append(entry.Addresses, prefix)
			}
			out = append(out, entry)
		}
		return out, ctx.Err()
	}
	return nil, errors.New("recovery address snapshot changed repeatedly")
}
func winRecoverySystemInterfaces(ctx context.Context) ([]nativeInterface, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	before, err := winRecoverySystemRows()
	if err != nil {
		return nil, err
	}
	addresses, err := winRecoverySystemAddresses(ctx)
	if err != nil {
		return nil, err
	}
	after, err := winRecoverySystemRows()
	if err != nil {
		return nil, err
	}
	confirmed, err := winRecoverySystemAddresses(ctx)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return winRecoveryMerge(before, after, addresses, confirmed)
}
