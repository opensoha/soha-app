package endpointservice

import (
	"context"
	"encoding/binary"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type nativeQuiesceDNSConn struct{ net.Conn }

func (c nativeQuiesceDNSConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}
func TestNativeInterceptionForwardQuiesceDropsInFlightAndNewDNS(t *testing.T) {
	for _, network := range []string{"udp4", "tcp4"} {
		for _, kind := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
			t.Run(network+"-"+kind.String(), func(t *testing.T) {
				received := make(chan struct{}, 1)
				release := make(chan struct{})
				defer close(release)
				var upstream atomic.Int32
				tcp, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				udp, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(tcp.Addr().(*net.TCPAddr).AddrPort()))
				if err != nil {
					tcp.Close()
					t.Fatal(err)
				}
				p := &nativeDNSProxy{forward: true, tcp: tcp, udp: udp, sem: make(chan struct{}, 64), until: time.Now().Add(time.Minute)}
				p.dial = func(ctx context.Context, _ string, _ netip.AddrPort) (net.Conn, error) {
					upstream.Add(1)
					left, right := net.Pipe()
					go func() {
						defer right.Close()
						buf := make([]byte, 4096)
						n, err := right.Read(buf)
						if err != nil {
							return
						}
						var q dnsmessage.Message
						if q.Unpack(buf[:n]) != nil {
							return
						}
						received <- struct{}{}
						select {
						case <-release:
						case <-ctx.Done():
							return
						}
						q.Response = true
						q.RecursionAvailable = true
						h := dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: kind, Class: dnsmessage.ClassINET, TTL: 30}
						if kind == dnsmessage.TypeA {
							q.Answers = []dnsmessage.Resource{{Header: h, Body: &dnsmessage.AResource{A: [4]byte{198, 18, 0, 4}}}}
						} else {
							q.Answers = []dnsmessage.Resource{{Header: h, Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("fdfe:dcba:9876::4").As16()}}}
						}
						raw, _ := q.Pack()
						right.Write(raw)
					}()
					return nativeQuiesceDNSConn{left}, nil
				}
				f := &nativeDNSForward{proxy: p}
				if err = f.start(); err != nil {
					t.Fatal(err)
				}
				defer f.close()
				address := tcp.Addr().String()
				raw := nativeTestDNSQuery(t, "owned-probe.invalid", kind)
				dial := func() (net.Conn, error) {
					c, err := net.DialTimeout(network, address, time.Second)
					if err != nil {
						return nil, err
					}
					c.SetDeadline(time.Now().Add(250 * time.Millisecond))
					return c, nil
				}
				send := func(c net.Conn) error {
					if network == "tcp4" {
						var length [2]byte
						binary.BigEndian.PutUint16(length[:], uint16(len(raw)))
						_, err := c.Write(append(length[:], raw...))
						return err
					}
					_, err := c.Write(raw)
					return err
				}
				first, err := dial()
				if err != nil {
					t.Fatal(err)
				}
				defer first.Close()
				if err = send(first); err != nil {
					t.Fatal(err)
				}
				select {
				case <-received:
				case <-time.After(time.Second):
					t.Fatal("in-flight query not observed")
				}
				if err = f.quiesce(context.Background()); err != nil {
					t.Fatal(err)
				}
				if _, err = first.Read(make([]byte, 4096)); err == nil {
					t.Fatal("in-flight fake-IP response escaped")
				}
				second, err := dial()
				if err != nil {
					t.Fatal("quiesce released listener", err)
				}
				defer second.Close()
				_ = send(second)
				if _, err = second.Read(make([]byte, 4096)); err == nil {
					t.Fatal("new fake-IP response escaped")
				}
				if upstream.Load() != 1 {
					t.Fatal("new request reached backend", upstream.Load())
				}
				if other, err := net.Listen("tcp4", address); err == nil {
					other.Close()
					t.Fatal("TCP ownership released early")
				}
				if other, err := net.ListenPacket("udp4", address); err == nil {
					other.Close()
					t.Fatal("UDP ownership released early")
				}
			})
		}
	}
}
func TestNativeInterceptionForwardQuiesceWaitsWriteBoundaryAndHonorsCancel(t *testing.T) {
	p := &nativeDNSProxy{}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- p.emitReply(context.Background(), func() error { close(entered); <-release; return nil })
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := p.quiesce(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("pending write crossed quiesce barrier", err)
	}
	var writes atomic.Int32
	if err := p.emitReply(context.Background(), func() error { writes.Add(1); return nil }); err == nil || writes.Load() != 0 {
		t.Fatal("new write passed cancelled quiesce")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := p.quiesce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.emitReply(context.Background(), func() error { writes.Add(1); return nil }); err == nil || writes.Load() != 0 {
		t.Fatal("quiesced write revived")
	}
}

func TestNativeInterceptionTunPreflightRejectsMissingGlobalIPv6(t *testing.T) {
	for _, ip := range []string{"", "::1/128", "fe80::1/64", "::ffff:192.0.2.2/128"} {
		t.Run(ip, func(t *testing.T) {
			e, p, peer := nativeTestExecutor(t)
			if ip != "" {
				p.snap.Interfaces[0].Addresses = append(p.snap.Interfaces[0].Addresses, netip.MustParsePrefix(ip))
			}
			before := e.mihomo.(*nativeTestEngine).applies
			view, err := e.SetInterception(context.Background(), peer, InterceptionIntent{RequestID: "enable-v6", TUN: true})
			if err == nil || view.ReasonCode != "native_ipv6_unavailable" || p.writes != 0 || e.mihomo.(*nativeTestEngine).applies != before {
				t.Fatal("non-global IPv6 reached native apply", view, err)
			}
		})
	}
	if !nativeHasGlobalIPv6(nativeSnapshot{Interfaces: []nativeInterface{{Addresses: []netip.Prefix{netip.MustParsePrefix("fd04:122::2/64")}}}}) {
		t.Fatal("ULA rejected as non-global-unicast")
	}
}
