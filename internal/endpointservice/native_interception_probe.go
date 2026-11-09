package endpointservice

import (
	"bufio"
	"context"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// Only this unpredictable owned hostname may traverse a verified fake-IP TUN
// without the ordinary physical/WG guard. No credential or real target is sent.
func (c *MihomoController) verifyNativeProbe(ctx context.Context, iface nativeInterface, plan *nativeEnginePlan) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if plan == nil || !plan.TUN || c.egress == nil {
		return errors.New("native probe unavailable")
	}
	for _, family := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		if err := c.nativeProbeFamily(ctx, iface, plan, family); err != nil {
			return err
		}
	}
	return nil
}
func (c *MihomoController) nativeProbeFamily(ctx context.Context, iface nativeInterface, plan *nativeEnginePlan, family dnsmessage.Type) error {
	host := c.egress.probeHost
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return err
	}
	message := dnsmessage.Message{Header: dnsmessage.Header{ID: 71, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: family, Class: dnsmessage.ClassINET}}}
	raw, _ := message.Pack()
	local := &nativeDNSProxy{dial: func(ctx context.Context, network string, target netip.AddrPort) (net.Conn, error) {
		if target != netip.MustParseAddrPort("127.0.0.1:53") {
			return nil, errors.New("invalid native probe resolver")
		}
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, target.String())
	}}
	reply, err := local.query(ctx, "udp", netip.MustParseAddrPort("127.0.0.1:53"), raw, message)
	if err != nil {
		return err
	}
	var answer dnsmessage.Message
	if answer.Unpack(reply) != nil || len(answer.Answers) == 0 {
		return errors.New("native fake-IP probe failed")
	}
	var ip netip.Addr
	pool := plan.FakeIPPool
	network := "tcp4"
	if family == dnsmessage.TypeAAAA {
		pool = plan.FakeIPv6Pool
		network = "tcp6"
	}
	for _, r := range answer.Answers {
		var candidate netip.Addr
		switch a := r.Body.(type) {
		case *dnsmessage.AResource:
			candidate = netip.AddrFrom4(a.A)
		case *dnsmessage.AAAAResource:
			candidate = netip.AddrFrom16(a.AAAA)
		}
		if pool.Contains(candidate) && candidate.Compare(pool.Addr().Next().Next().Next()) > 0 {
			ip = candidate
			break
		}
	}

	if !ip.IsValid() {
		return errors.New("native DNS lost fake-IP mapping")
	}
	before := c.egress.proxyProbes.Load() + c.egress.directProbes.Load()
	for _, b := range c.egress.bridges {
		before += b.probes.Load()
	}
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, netip.AddrPortFrom(ip, 80).String())
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	localIP, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		return err
	}
	owned := false
	for _, p := range iface.Addresses {
		if p.Addr() == localIP.Addr() {
			owned = true
		}
	}
	if !owned {
		return errors.New("native probe did not use the owned TUN")
	}
	if _, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n"); err != nil {
		return err
	}
	response, err := http.ReadResponse(bufio.NewReader(io.LimitReader(conn, 4096)), nil)
	if err != nil {
		return err
	}
	response.Body.Close()
	after := c.egress.proxyProbes.Load() + c.egress.directProbes.Load()
	for _, b := range c.egress.bridges {
		after += b.probes.Load()
	}
	if response.StatusCode != http.StatusNoContent || after <= before {
		return errors.New("native domain rule probe did not reach the owned gate")
	}
	return nil
}
