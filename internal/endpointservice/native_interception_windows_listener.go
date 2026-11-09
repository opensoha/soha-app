//go:build windows

package endpointservice

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"net/netip"
	"syscall"
	"unsafe"
)

func (p *winNativePlatform) VerifyListenerOwner(ctx context.Context, s nativeSession, network string, endpoint netip.AddrPort, pid uint32) error {
	if s == nil {
		return errors.New("missing native session")
	}
	if err := s.Validate(ctx, false); err != nil {
		return err
	}
	listeners, err := winNativeListeners(network, endpoint.Addr().Is4())
	if err != nil {
		return err
	}
	if err := winNativeListenerOwned(listeners, endpoint, pid); err != nil {
		return err
	}
	return s.Validate(ctx, false)
}
func winNativeListeners(network string, ipv4 bool) ([]winNativeListener, error) {
	tcp := network == "tcp" || network == "tcp4" || network == "tcp6"
	udp := network == "udp" || network == "udp4" || network == "udp6"
	if !tcp && !udp {
		return nil, errors.New("listener protocol is invalid")
	}
	if network == "tcp4" || network == "udp4" {
		if !ipv4 {
			return nil, errors.New("listener family differs")
		}
	}
	if network == "tcp6" || network == "udp6" {
		if ipv4 {
			return nil, errors.New("listener family differs")
		}
	}
	proc, class := "GetExtendedUdpTable", uintptr(1)
	if tcp {
		proc, class = "GetExtendedTcpTable", 3
	}
	family := uintptr(windows.AF_INET6)
	if ipv4 {
		family = windows.AF_INET
	}
	api := winNativeIPHelper.NewProc(proc)
	if err := api.Find(); err != nil {
		return nil, err
	}
	size := uint32(16384)
	for tries := 0; tries < 4; tries++ {
		if size > 4<<20 {
			return nil, errors.New("listener table exceeds bound")
		}
		buf := make([]byte, size)
		r, _, _ := api.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, family, class, 0)
		if r == 122 {
			continue
		}
		if r != 0 {
			return nil, syscall.Errno(r)
		}
		if size < 4 || int(size) > len(buf) {
			return nil, errors.New("invalid listener table size")
		}
		return winNativeParseListeners(buf[:size], tcp, ipv4)
	}
	return nil, errors.New("listener table changed repeatedly")
}
