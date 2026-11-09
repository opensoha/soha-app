package endpointservice

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

type nativeDNSForward struct {
	v4tcp   net.Listener
	v4udp   *net.UDPConn
	proxy   *nativeDNSProxy
	started bool
}

func reserveNativeDNS() (*nativeDNSForward, error) {
	f := &nativeDNSForward{}
	var err error
	f.v4tcp, err = net.Listen("tcp4", "127.0.0.1:53")
	if err != nil {
		return nil, errors.New("native DNS TCP port occupied")
	}
	f.v4udp, err = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:53")))
	if err != nil {
		f.close()
		return nil, errors.New("native DNS UDP port occupied")
	}
	tcp, err := net.Listen("tcp6", "[::1]:53")
	if err != nil {
		f.close()
		return nil, errors.New("native IPv6 DNS TCP port occupied")
	}
	udp, err := net.ListenUDP("udp6", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[::1]:53")))
	if err != nil {
		tcp.Close()
		f.close()
		return nil, errors.New("native IPv6 DNS UDP port occupied")
	}
	f.proxy = &nativeDNSProxy{forward: true, tcp: tcp, udp: udp, sem: make(chan struct{}, 64), until: time.Now().Add(24 * time.Hour), dial: func(ctx context.Context, network string, target netip.AddrPort) (net.Conn, error) {
		if target != netip.MustParseAddrPort("127.0.0.1:53") {
			return nil, errors.New("invalid loopback DNS forwarding target")
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, target.String())
	}}
	return f, nil
}
func (f *nativeDNSForward) releaseIPv4() {
	if f == nil {
		return
	}
	if f.v4tcp != nil {
		f.v4tcp.Close()
		f.v4tcp = nil
	}
	if f.v4udp != nil {
		f.v4udp.Close()
		f.v4udp = nil
	}
}
func (f *nativeDNSForward) start() error {
	if f == nil || f.proxy == nil {
		return errors.New("native DNS forwarding unavailable")
	}
	if f.started {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.proxy.cancel = cancel
	f.proxy.workers.Add(2)
	f.started = true
	go f.proxy.serveTCP(ctx)
	go f.proxy.serveUDP(ctx)
	return nil
}
func (f *nativeDNSForward) close() {
	if f == nil {
		return
	}
	f.releaseIPv4()
	if f.proxy != nil {
		if f.started {
			f.proxy.close()
		} else {
			f.proxy.tcp.Close()
			f.proxy.udp.Close()
		}
		f.proxy = nil
	}
}

func (f *nativeDNSForward) quiesce(ctx context.Context) error {
	if f == nil || f.proxy == nil {
		return nil
	}
	return f.proxy.quiesce(ctx)
}
