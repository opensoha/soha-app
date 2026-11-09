package endpointservice

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type nativeDNSProxy struct {
	quiesced  atomic.Bool
	replyOnce sync.Once
	replyGate chan struct{}

	leaseMu sync.RWMutex
	forward bool
	scopes  []nativeResolverScope
	records []DNSRecord
	dial    func(context.Context, string, netip.AddrPort) (net.Conn, error)
	tcp     net.Listener
	udp     *net.UDPConn
	sem     chan struct{}
	cancel  context.CancelFunc
	workers sync.WaitGroup
	until   time.Time
}

func startNativeDNS(scopes []nativeResolverScope, records []DNSRecord, until time.Time, dial func(context.Context, string, netip.AddrPort) (net.Conn, error)) (*nativeDNSProxy, error) {
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	endpoint := tcp.Addr().(*net.TCPAddr).AddrPort()
	udp, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(endpoint))
	if err != nil {
		tcp.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &nativeDNSProxy{scopes: scopes, records: records, until: until, dial: dial, tcp: tcp, udp: udp, sem: make(chan struct{}, 64), cancel: cancel}
	p.workers.Add(2)
	go p.serveUDP(ctx)
	go p.serveTCP(ctx)
	return p, nil
}
func (p *nativeDNSProxy) endpoint() netip.AddrPort { return p.tcp.Addr().(*net.TCPAddr).AddrPort() }
func (p *nativeDNSProxy) close() {
	if p == nil {
		return
	}
	p.cancel()
	p.tcp.Close()
	p.udp.Close()
	p.workers.Wait()
}
func (p *nativeDNSProxy) serveUDP(ctx context.Context) {
	defer p.workers.Done()
	buf := make([]byte, 4097)
	for {
		n, remote, err := p.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if n > 4096 || !remote.Addr().IsLoopback() || p.quiesced.Load() {
			continue
		}
		raw := append([]byte(nil), buf[:n]...)
		select {
		case p.sem <- struct{}{}:
		default:
			continue
		}
		p.workers.Add(1)
		go func() {
			defer p.workers.Done()
			defer func() { <-p.sem }()
			qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			reply, err := p.exchange(qctx, raw)
			if err == nil {
				_ = p.emitReply(qctx, func() error {
					_ = p.udp.SetWriteDeadline(time.Now().Add(5 * time.Second))
					_, err := p.udp.WriteToUDPAddrPort(reply, remote)
					return err
				})
			}
		}()
	}
}
func (p *nativeDNSProxy) serveTCP(ctx context.Context) {
	defer p.workers.Done()
	for {
		c, err := p.tcp.Accept()
		if err != nil {
			return
		}
		if p.quiesced.Load() {
			c.Close()
			continue
		}
		select {
		case p.sem <- struct{}{}:
		default:
			c.Close()
			continue
		}
		p.workers.Add(1)
		go func() {
			defer p.workers.Done()
			defer func() { <-p.sem }()
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			var length [2]byte
			if _, err := io.ReadFull(c, length[:]); err != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(length[:]))
			if n < 12 || n > 4096 {
				return
			}
			raw := make([]byte, n)
			if _, err := io.ReadFull(c, raw); err != nil {
				return
			}
			qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			reply, err := p.exchange(qctx, raw)
			if err != nil {
				return
			}
			binary.BigEndian.PutUint16(length[:], uint16(len(reply)))
			_ = p.emitReply(qctx, func() error { _, err := c.Write(append(length[:], reply...)); return err })
		}()
	}
}
func nativeDNSQuestion(raw []byte) (dnsmessage.Message, error) {
	var m dnsmessage.Message
	if len(raw) < 12 || len(raw) > 4096 || m.Unpack(raw) != nil || m.Response || m.OpCode != 0 || m.RCode != 0 || m.Truncated || len(m.Questions) != 1 || len(m.Answers) > 0 || len(m.Authorities) > 0 || len(m.Additionals) > 1 {
		return m, errors.New("invalid native DNS query")
	}
	q := m.Questions[0]
	if q.Class != dnsmessage.ClassINET || q.Type == 251 || q.Type == 252 || q.Type == 0 {
		return m, errors.New("unsupported native DNS query")
	}
	if _, err := nativeDNSName(q.Name.String()); err != nil {
		return m, err
	}
	for _, r := range m.Additionals {
		if r.Header.Type != dnsmessage.TypeOPT {
			return m, errors.New("unsupported native DNS additional")
		}
	}
	return m, nil
}
func nativeDNSName(host string) (string, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || len(host) > 253 {
		return "", errors.New("invalid DNS name")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", errors.New("invalid DNS label")
		}
		for _, r := range label {
			if r != '-' && r != '_' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				return "", errors.New("invalid DNS label")
			}
		}
	}
	return host, nil
}
func (p *nativeDNSProxy) scopeFor(host string) (nativeResolverScope, error) {
	bestBits, bestPriority := -1, uint32(^uint32(0))
	var selected *nativeResolverScope
	ambiguous := false
	for i := range p.scopes {
		s := &p.scopes[i]
		bits := -1
		if s.Default {
			bits = 0
		}
		for _, d := range s.Domains {
			d = strings.ToLower(strings.TrimSuffix(d, "."))
			if d == "" {
				if bits < 0 {
					bits = 0
				}
				continue
			}
			if host == d || strings.HasSuffix(host, "."+d) {
				if len(d) > bits {
					bits = len(d)
				}
			}
		}
		if bits < 0 {
			continue
		}
		if bits > bestBits || bits == bestBits && s.Priority < bestPriority {
			selected = s
			bestBits = bits
			bestPriority = s.Priority
			ambiguous = false
		} else if bits == bestBits && s.Priority == bestPriority && selected != nil && selected.ID != s.ID && (selected.Interface.ID != s.Interface.ID || !slices.Equal(selected.Servers, s.Servers)) {
			ambiguous = true
		}
	}
	if selected == nil || ambiguous || len(selected.Servers) == 0 {
		return nativeResolverScope{}, errors.New("native DNS scope unavailable or ambiguous")
	}
	return *selected, nil
}
func (p *nativeDNSProxy) exchange(ctx context.Context, raw []byte) ([]byte, error) {
	if p.quiesced.Load() {
		return nil, errors.New("native DNS is quiesced")
	}
	m, err := nativeDNSQuestion(raw)
	if err != nil {
		return nil, err
	}
	p.leaseMu.RLock()
	until := p.until
	records := append([]DNSRecord(nil), p.records...)
	p.leaseMu.RUnlock()
	if !until.After(time.Now()) {
		return nil, errors.New("native DNS lease expired")
	}
	if p.forward {
		canonical, err := m.Pack()
		if err != nil {
			return nil, err
		}
		return p.query(ctx, "udp", netip.MustParseAddrPort("127.0.0.1:53"), canonical, m)
	}
	host, _ := nativeDNSName(m.Questions[0].Name.String())
	q := m.Questions[0]
	for _, r := range records {
		if strings.EqualFold(strings.TrimSuffix(r.Hostname, "."), host) {
			if !r.ExpiresAt.After(time.Now()) {
				return nil, errors.New("managed DNS record expired")
			}
			reply := dnsmessage.Message{Header: dnsmessage.Header{ID: m.ID, Response: true, RecursionDesired: m.RecursionDesired, RecursionAvailable: true}, Questions: m.Questions}
			ttl := uint32(min(time.Until(r.ExpiresAt), time.Until(until)) / time.Second)
			for _, text := range r.Addresses {
				ip, e := netip.ParseAddr(text)
				if e != nil {
					return nil, errors.New("invalid managed DNS address")
				}
				h := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: ttl}
				if q.Type == dnsmessage.TypeA && ip.Is4() {
					h.Type = dnsmessage.TypeA
					reply.Answers = append(reply.Answers, dnsmessage.Resource{Header: h, Body: &dnsmessage.AResource{A: ip.As4()}})
				}
				if q.Type == dnsmessage.TypeAAAA && ip.Is6() {
					h.Type = dnsmessage.TypeAAAA
					reply.Answers = append(reply.Answers, dnsmessage.Resource{Header: h, Body: &dnsmessage.AAAAResource{AAAA: ip.As16()}})
				}
			}
			return reply.Pack()
		}
	}
	scope, err := p.scopeFor(host)
	if err != nil {
		return nil, err
	}
	var token [2]byte
	if _, err = rand.Read(token[:]); err != nil {
		return nil, err
	}
	original := m.ID
	m.ID = binary.BigEndian.Uint16(token[:])
	query, err := m.Pack()
	if err != nil {
		return nil, err
	}
	for _, ip := range scope.Servers {
		if !ip.IsValid() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, errors.New("unsafe upstream DNS resolver")
		}
		reply, err := p.query(ctx, "udp", netip.AddrPortFrom(ip, 53), query, m)
		if err == nil {
			var result dnsmessage.Message
			_ = result.Unpack(reply)
			if result.Truncated {
				reply, err = p.query(ctx, "tcp", netip.AddrPortFrom(ip, 53), query, m)
			}
		}
		if err == nil {
			binary.BigEndian.PutUint16(reply[:2], original)
			return reply, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, errors.New("native DNS namespace failed")
}
func (p *nativeDNSProxy) query(ctx context.Context, network string, server netip.AddrPort, query []byte, want dnsmessage.Message) ([]byte, error) {
	c, err := p.dial(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	actual, e := netip.ParseAddrPort(c.RemoteAddr().String())
	if e != nil || actual != server {
		return nil, errors.New("DNS upstream endpoint changed")
	}
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	var raw []byte
	if network == "tcp" {
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(query)))
		if _, err = c.Write(append(length[:], query...)); err != nil {
			return nil, err
		}
		if _, err = io.ReadFull(c, length[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(length[:]))
		if n < 12 {
			return nil, errors.New("short DNS response")
		}
		raw = make([]byte, n)
		_, err = io.ReadFull(c, raw)
	} else {
		if _, err = c.Write(query); err != nil {
			return nil, err
		}
		raw = make([]byte, 65535)
		var n int
		n, err = c.Read(raw)
		raw = raw[:n]
	}
	if err != nil {
		return nil, err
	}
	var reply dnsmessage.Message
	if len(raw) < 12 || reply.Unpack(raw) != nil || !reply.Response || reply.OpCode != 0 || reply.ID != want.ID || len(reply.Questions) != 1 || reply.Questions[0].Type != want.Questions[0].Type || reply.Questions[0].Class != want.Questions[0].Class || !strings.EqualFold(reply.Questions[0].Name.String(), want.Questions[0].Name.String()) {
		return nil, errors.New("untrusted DNS response")
	}
	return raw, nil
}
func (p *nativeDNSProxy) lookup(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if network != "ip" && network != "ip4" && network != "ip6" {
		return nil, errors.New("invalid DNS address family")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	name, err := nativeDNSName(host)
	if err != nil {
		return nil, err
	}
	dn, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return nil, err
	}
	var result []netip.Addr
	for _, kind := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		if network == "ip4" && kind == dnsmessage.TypeAAAA || network == "ip6" && kind == dnsmessage.TypeA {
			continue
		}
		query := dnsmessage.Message{Header: dnsmessage.Header{RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dn, Type: kind, Class: dnsmessage.ClassINET}}}
		raw, _ := query.Pack()
		reply, err := p.exchange(ctx, raw)
		if err != nil {
			return nil, err
		}
		var m dnsmessage.Message
		if m.Unpack(reply) != nil || m.RCode != dnsmessage.RCodeSuccess {
			return nil, errors.New("DNS address lookup failed")
		}
		addresses, err := nativeAnswerAddresses(m, name, kind)
		if err != nil {
			return nil, err
		}
		result = append(result, addresses...)
	}
	if len(result) == 0 || len(result) > 32 {
		return nil, errors.New("DNS address count invalid")
	}
	return result, nil
}

func (p *nativeDNSProxy) renew(until time.Time, records []DNSRecord) {
	p.leaseMu.Lock()
	defer p.leaseMu.Unlock()
	p.until = until
	p.records = append([]DNSRecord(nil), records...)
}

func nativeAnswerAddresses(m dnsmessage.Message, host string, kind dnsmessage.Type) ([]netip.Addr, error) {
	seen := map[string]bool{}
	current := host
	for depth := 0; depth < 16; depth++ {
		if seen[current] {
			return nil, errors.New("DNS alias cycle")
		}
		seen[current] = true
		next := ""
		var addresses []netip.Addr
		for _, r := range m.Answers {
			if r.Header.Class != dnsmessage.ClassINET {
				return nil, errors.New("invalid DNS answer class")
			}
			name, err := nativeDNSName(r.Header.Name.String())
			if err != nil {
				return nil, err
			}
			if name != current {
				continue
			}
			switch body := r.Body.(type) {
			case *dnsmessage.CNAMEResource:
				alias, err := nativeDNSName(body.CNAME.String())
				if err != nil || next != "" && next != alias {
					return nil, errors.New("ambiguous DNS alias")
				}
				next = alias
			case *dnsmessage.AResource:
				if kind == dnsmessage.TypeA {
					addresses = append(addresses, netip.AddrFrom4(body.A))
				}
			case *dnsmessage.AAAAResource:
				if kind == dnsmessage.TypeAAAA {
					addresses = append(addresses, netip.AddrFrom16(body.AAAA))
				}
			}
		}
		if next != "" {
			if len(addresses) > 0 {
				return nil, errors.New("DNS alias and address conflict")
			}
			current = next
			continue
		}
		if len(addresses) > 32 {
			return nil, errors.New("DNS answer limit exceeded")
		}
		return addresses, nil
	}
	return nil, errors.New("DNS alias depth exceeded")
}

func (p *nativeDNSProxy) responseGate() chan struct{} {
	p.replyOnce.Do(func() { p.replyGate = make(chan struct{}, 1); p.replyGate <- struct{}{} })
	return p.replyGate
}
func (p *nativeDNSProxy) emitReply(ctx context.Context, write func() error) error {
	if p.quiesced.Load() {
		return errors.New("native DNS is quiesced")
	}
	gate := p.responseGate()
	select {
	case <-gate:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { gate <- struct{}{} }()
	if p.quiesced.Load() {
		return errors.New("native DNS is quiesced")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return write()
}

// Preserve listener ownership while making the final response-write boundary
// irreversible. Waiting for an in-progress write is bounded by cleanup context.
func (p *nativeDNSProxy) quiesce(ctx context.Context) error {
	if p == nil {
		return nil
	}
	p.quiesced.Store(true)
	if p.cancel != nil {
		p.cancel()
	}
	gate := p.responseGate()
	select {
	case <-gate:
		gate <- struct{}{}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
