package endpointservice

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
)

type nativeRecoveryPlatform struct {
	*nativeTestPlatform
	values        map[string]nativeValue
	events        *[]string
	flushFailures int
	flushes       int
	readFailures  map[string]bool
	afterFlush    func()
}

func (p *nativeRecoveryPlatform) ReadChange(_ context.Context, _ nativeSession, c nativeChange) (nativeValue, error) {
	if p.readFailures[c.ID] {
		return nativeValue{}, errors.New("DNS read unavailable")
	}
	return p.values[c.ID], nil
}
func (p *nativeRecoveryPlatform) CompareRestore(_ context.Context, _ nativeSession, c nativeChange) (nativeReceipt, error) {
	if !nativeValuesEqual(p.values[c.ID], c.After) {
		return nativeReceipt{}, errors.New("conflict")
	}
	*p.events = append(*p.events, c.ID)
	p.values[c.ID] = c.Before
	return nativeReceipt{ChangeID: c.ID, Outcome: "applied", Current: c.Before}, nil
}
func (p *nativeRecoveryPlatform) FlushResolverCache(context.Context, nativeSession) error {
	p.flushes++
	*p.events = append(*p.events, "flush")
	for _, id := range []string{"dns", "wg4", "wg6"} {
		if !p.values[id].Present && strings.HasPrefix(id, "wg") {
			continue
		}
		if p.values[id].DNS.Servers[0].IsLoopback() {
			return errors.New("flush before DNS restored")
		}
	}
	if p.flushFailures > 0 {
		p.flushFailures--
		return errors.New("flush failed")
	}
	if p.afterFlush != nil {
		p.afterFlush()
	}
	return nil
}

type nativeRecoveryWG struct {
	fakeSystem
	p               *nativeRecoveryPlatform
	changes         []nativeChange
	releaseFailures int
	releases        int
	absentProof     bool
}

func (w *nativeRecoveryWG) PrepareNativeDNS(context.Context, nativeSession, []netip.Addr) ([]nativeChange, error) {
	return w.changes, nil
}
func (w *nativeRecoveryWG) ReadNativeDNS(_ context.Context, _ nativeSession, c nativeChange) (nativeValue, error) {
	value := w.p.values[c.ID]
	if !value.Present && !nativeValuesEqual(value, c.Before) && !w.absentProof {
		return nativeValue{}, errors.New("WG scope absence not proved")
	}
	return value, nil
}
func (w *nativeRecoveryWG) CompareNativeDNS(_ context.Context, _ nativeSession, c nativeChange, restore bool) (nativeReceipt, error) {
	if !restore {
		return nativeReceipt{}, errors.New("restore fixture only")
	}
	current := w.p.values[c.ID]
	if nativeValuesEqual(current, c.Before) {
		return nativeReceipt{ChangeID: c.ID, Outcome: "not_applied", Current: current}, nil
	}
	if !nativeValuesEqual(current, c.After) {
		return nativeReceipt{}, errors.New("conflict")
	}
	*w.p.events = append(*w.p.events, c.ID)
	w.p.values[c.ID] = c.Before
	return nativeReceipt{ChangeID: c.ID, Outcome: "applied", Current: c.Before}, nil
}
func (w *nativeRecoveryWG) ReleaseNativeDNS(_ context.Context, _ nativeSession, changes []nativeChange) error {
	w.releases++
	*w.p.events = append(*w.p.events, "release")
	for _, c := range changes {
		if !w.p.values[c.ID].Present && w.absentProof {
			continue
		}
		if !nativeValuesEqual(w.p.values[c.ID], c.Before) {
			return errors.New("release before original DNS")
		}
	}
	if w.releaseFailures > 0 {
		w.releaseFailures--
		return errors.New("release failed")
	}
	return nil
}

type nativeRecoveryEngine struct {
	nativeTestEngine
	events *[]string
}

func (r *nativeRecoveryEngine) suspendNativeIngress(context.Context) error {
	*r.events = append(*r.events, "gate")
	return nil
}
func (r *nativeRecoveryEngine) Disable(context.Context) error {
	*r.events = append(*r.events, "components")
	return nil
}
func nativeRecoveryFixture(t *testing.T) (*CoordinatedExecutor, *nativeRecoveryPlatform, *nativeRecoveryWG, *[]string) {
	e, base, peer := nativeTestExecutor(t)
	events := []string{}
	p := &nativeRecoveryPlatform{nativeTestPlatform: base, values: map[string]nativeValue{}, events: &events}
	n := e.native
	n.platform = p
	n.guard.platform = p
	n.session = peer.session
	iface := nativeInterface{ID: "owned-tun", Name: "tun-owned", Index: 12, Kind: "tunnel"}
	route := nativeChange{ID: "route", Kind: "route", Scope: nativeScope{Interface: iface}, After: nativeValue{Present: true, Route: &nativeRoute{Destination: netip.MustParsePrefix("0.0.0.0/1"), Interface: iface}}}
	dns := func(id string, family uint8, before, after string) nativeChange {
		return nativeChange{ID: id, Kind: "dns", Scope: nativeScope{Family: family}, Before: nativeValue{Present: true, DNS: &nativeDNSConfig{Servers: []netip.Addr{netip.MustParseAddr(before)}}}, After: nativeValue{Present: true, DNS: &nativeDNSConfig{Servers: []netip.Addr{netip.MustParseAddr(after)}}}}
	}
	wg4, wg6 := dns("wg4", 4, "10.0.0.53", "127.0.0.1"), dns("wg6", 6, "fd00::53", "::1")
	physical := dns("dns", 4, "192.0.2.53", "127.0.0.1")
	proxy := nativeChange{ID: "proxy", Kind: "proxy", Field: "flags", Before: nativeValue{Present: true, Proxy: &nativeProxyValue{}}, After: nativeValue{Present: true, Proxy: &nativeProxyValue{Number: 1}}}
	n.journal = nativeJournal{Version: 1, Generation: 1, Owner: peer.owner, Pending: true, CacheFlushPending: true, DNSReleasePending: true, Steps: []nativeJournalStep{{Change: route, Stage: "written"}, {Owner: "wireguard", Change: wg4, Stage: "unknown"}, {Owner: "wireguard", Change: wg6, Stage: "written"}, {Change: physical, Stage: "written"}, {Change: proxy, Stage: "written"}}}
	for _, s := range n.journal.Steps {
		p.values[s.Change.ID] = s.Change.After
	}
	plan := TunnelPlan{DNSServers: []string{"10.0.0.53", "fd00::53"}}
	w := &nativeRecoveryWG{p: p, changes: []nativeChange{wg4, wg6}, fakeSystem: fakeSystem{current: plan.Readback()}}
	e.wireGuard = &Executor{system: w, previous: &plan, nativeDNS: []nativeChange{wg4, wg6}}
	e.mihomo = &nativeRecoveryEngine{events: &events}
	if err := saveNativeJournal(n.path, n.journal); err != nil {
		t.Fatal(err)
	}
	return e, p, w, &events
}
func TestNativeInterceptionRecoveryOrderingAcrossOwners(t *testing.T) {
	e, _, _, events := nativeRecoveryFixture(t)
	if err := e.restoreNativeLocked(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	want := []string{"gate", "proxy", "dns", "wg6", "wg4", "flush", "release", "route", "components"}
	if !reflect.DeepEqual(*events, want) {
		t.Fatal("recovery order", *events, want)
	}
}
func TestNativeInterceptionFlushFailureRetryDoesNotReplayDNSSetters(t *testing.T) {
	e, p, _, events := nativeRecoveryFixture(t)
	p.flushFailures = 1
	if err := e.restoreNativeLocked(context.Background(), false); err == nil || !e.native.status.CleanupPending {
		t.Fatal("flush failure reported success")
	}
	if (*events)[len(*events)-1] != "flush" {
		t.Fatal("components removed before successful flush", *events)
	}
	// Reload the durable interrupted recovery, as after service restart.
	j, err := loadNativeJournal(e.native.path)
	if err != nil {
		t.Fatal(err)
	}
	e.native.journal = j
	*events = nil
	if err = e.restoreNativeLocked(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*events, []string{"gate", "flush", "release", "route", "components"}) {
		t.Fatal("DNS setter replayed", *events)
	}
}
func TestNativeInterceptionReleaseRetryKeepsPinUntilSuccess(t *testing.T) {
	e, _, w, events := nativeRecoveryFixture(t)
	w.releaseFailures = 1
	if err := e.restoreNativeLocked(context.Background(), false); err == nil || !e.native.status.CleanupPending {
		t.Fatal("failed release was accepted")
	}
	if (*events)[len(*events)-1] != "release" {
		t.Fatal("route removed before release", *events)
	}
	owner := e.native.journal.Owner
	peer := NativePeer{owner: owner, pid: 42, session: &nativeTestSession{owner: owner}}
	if _, err := e.SetInterception(context.Background(), peer, InterceptionIntent{RequestID: "new-native", ExpectedGeneration: e.native.journal.Generation, SystemProxy: true}); err == nil || w.releases != 1 {
		t.Fatal("new native intent crossed an unfinished release")
	}
	*events = nil
	if err := e.restoreNativeLocked(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*events, []string{"gate", "flush", "release", "route", "components"}) || w.releases != 2 {
		t.Fatal("release retry replayed setter or revived pin", *events)
	}
}
func TestNativeInterceptionWGReadbackNeedsOriginalGrantAndActualAfter(t *testing.T) {
	e, _, _, _ := nativeRecoveryFixture(t)
	w := e.wireGuard.(*Executor)
	grant := w.previous.Readback()
	after := grant
	after.DNSServers = []string{"127.0.0.1", "::1"}
	if !w.nativeReadbackMatches(after, grant) {
		t.Fatal("verified delegated readback rejected")
	}
	if w.nativeReadbackMatches(grant, grant) {
		t.Fatal("original servers mistaken for actual delegated state")
	}
	wrong := grant
	wrong.DNSServers = []string{"10.0.0.99", "fd00::53"}
	if w.nativeReadbackMatches(after, wrong) {
		t.Fatal("changed original grant normalized")
	}
	after.DNSServers = []string{"127.0.0.2", "::1"}
	if w.nativeReadbackMatches(after, grant) {
		t.Fatal("foreign actual DNS normalized")
	}
}
func TestNativeInterceptionFamilyPartialWriteRecoversIndependently(t *testing.T) {
	e, p, _, events := nativeRecoveryFixture(t)
	for _, step := range e.native.journal.Steps {
		if step.Change.ID == "wg6" {
			p.values["wg6"] = step.Change.Before
		}
	}
	if err := e.restoreNativeLocked(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	for _, event := range *events {
		if event == "wg6" {
			t.Fatal("never-written family was overwritten")
		}
	}
}
func TestNativeInterceptionCapturePreservesWGWithoutLANBypass(t *testing.T) {
	s := nativeSnapshot{Interfaces: []nativeInterface{{ID: "physical", Kind: "physical", Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")}}}, Routes: []nativeRoute{{Destination: netip.MustParsePrefix("0.0.0.0/0"), Interface: nativeInterface{ID: "physical", Kind: "physical"}, Gateway: netip.MustParseAddr("192.0.2.1")}, {Destination: netip.MustParsePrefix("192.0.2.0/24"), Interface: nativeInterface{ID: "physical", Kind: "physical"}}, {Destination: netip.MustParsePrefix("10.0.0.0/16"), Interface: nativeInterface{ID: "wg", Kind: "tunnel"}}}}
	captures, exceptions, err := nativePlanCaptures(s, TunnelReadback{Routes: []string{"10.0.0.0/16"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range captures {
		if p.Overlaps(netip.MustParsePrefix("10.0.0.0/16")) {
			t.Fatal("WG overlap", p)
		}
	}
	if err = verifyNativeCoverage(s, nativeInterface{ID: "owned"}, captures, exceptions); err != nil {
		t.Fatal("LAN was silently bypassed", err)
	}
	foreign := nativeRoute{Destination: netip.MustParsePrefix("192.0.2.50/32"), Interface: nativeInterface{ID: "physical", Kind: "physical"}}
	s.Routes = append(s.Routes, foreign)
	if _, _, err = nativePlanCaptures(s, TunnelReadback{Routes: []string{"10.0.0.0/16"}}, nil); err == nil {
		t.Fatal("uncoverable foreign host route accepted")
	}
}

func TestNativeInterceptionFlushSuccessBeforeWALCrashIsRetryable(t *testing.T) {
	e, p, _, events := nativeRecoveryFixture(t)
	for i := range e.native.journal.Steps {
		step := &e.native.journal.Steps[i]
		if step.Change.Kind != "route" {
			p.values[step.Change.ID] = step.Change.Before
			step.Stage = "restored"
		}
	}
	if err := saveNativeJournal(e.native.path, e.native.journal); err != nil {
		t.Fatal(err)
	}
	if err := p.FlushResolverCache(context.Background(), e.native.session); err != nil {
		t.Fatal(err)
	}
	// OS flush succeeded, but the process died before committing the cleared flag.
	j, err := loadNativeJournal(e.native.path)
	if err != nil {
		t.Fatal(err)
	}
	e.native.journal = j
	*events = nil
	if err = e.restoreNativeLocked(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*events, []string{"gate", "flush", "release", "route", "components"}) || p.flushes != 2 {
		t.Fatal("crash retry replayed setters", *events, p.flushes)
	}
}

func TestNativeInterceptionWGAbsentFamilyBeforeIsPreserved(t *testing.T) {
	e, p, w, _ := nativeRecoveryFixture(t)
	wg := e.wireGuard.(*Executor)
	wg.previous.DNSServers = []string{"10.0.0.53"}
	w.current = wg.previous.Readback()
	w.changes[1].Before = nativeValue{}
	wg.nativeDNS = slices.Clone(w.changes)
	p.values["wg6"] = w.changes[1].After
	after := wg.previous.Readback()
	after.DNSServers = []string{"127.0.0.1", "::1"}
	if !wg.nativeReadbackMatches(after, wg.previous.Readback()) {
		t.Fatal("absent IPv6 registry baseline lost in delegated proof")
	}
	wg.nativeDNS = nil
	changes, err := wg.prepareNativeDNS(context.Background(), e.native.session, []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()})
	if err != nil || len(changes) != 2 || changes[1].Before.Present {
		t.Fatal("per-family absence was fabricated", changes, err)
	}
}

func TestNativeInterceptionRestoredDNSBarrierBeforeRetryFlushAndRelease(t *testing.T) {
	for _, kind := range []string{"unchanged", "physical-changed", "physical-unknown", "during-flush", "wg-changed", "wg-unknown", "wg-absent"} {
		t.Run(kind, func(t *testing.T) {
			e, p, w, events := nativeRecoveryFixture(t)
			p.flushFailures = 1
			if err := e.restoreNativeLocked(context.Background(), false); err == nil || !e.native.status.CleanupPending {
				t.Fatal("fixture did not stop at first flush")
			}
			original := p.values["dns"]
			switch kind {
			case "physical-changed":
				p.values["dns"] = nativeValue{Present: true, DNS: &nativeDNSConfig{Servers: []netip.Addr{netip.MustParseAddr("192.0.2.99")}}}
			case "physical-unknown":
				p.readFailures = map[string]bool{"dns": true}
			case "during-flush":
				p.afterFlush = func() {
					p.values["dns"] = nativeValue{Present: true, DNS: &nativeDNSConfig{Servers: []netip.Addr{netip.MustParseAddr("192.0.2.99")}}}
				}
			case "wg-changed":
				p.values["wg4"] = nativeValue{Present: true, DNS: &nativeDNSConfig{Servers: []netip.Addr{netip.MustParseAddr("10.0.0.99")}}}
			case "wg-unknown":
				p.values["wg4"] = nativeValue{}
			case "wg-absent":
				w.absentProof = true
				p.values["wg4"] = nativeValue{}
				p.values["wg6"] = nativeValue{}
			}
			*events = nil
			err := e.restoreNativeLocked(context.Background(), false)
			if kind == "unchanged" || kind == "wg-absent" {
				if err != nil || !reflect.DeepEqual(*events, []string{"gate", "flush", "release", "route", "components"}) {
					t.Fatal("verified retry failed/replayed setters", *events, err)
				}
				return
			}
			wantEvents := []string{"gate"}
			wantFlushes := 1
			if kind == "during-flush" {
				wantEvents = append(wantEvents, "flush")
				wantFlushes = 2
			}
			if err == nil || !e.native.status.CleanupPending || !e.native.journal.CacheFlushPending || !reflect.DeepEqual(*events, wantEvents) || p.flushes != wantFlushes || w.releases != 0 {
				t.Fatal("restored DNS bypassed retry barrier", *events, err, p.flushes, w.releases)
			}
			// Recover only after actual Before becomes observable; do not replay setters.
			p.values["dns"] = original
			p.readFailures = nil
			p.afterFlush = nil
			if kind == "wg-changed" || kind == "wg-unknown" {
				p.values["wg4"] = w.changes[0].Before
			}
			*events = nil
			if err = e.restoreNativeLocked(context.Background(), false); err != nil || !reflect.DeepEqual(*events, []string{"gate", "flush", "release", "route", "components"}) {
				t.Fatal("unchanged retry did not finish", *events, err)
			}
		})
	}
}
