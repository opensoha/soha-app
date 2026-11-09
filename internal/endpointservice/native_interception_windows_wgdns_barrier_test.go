package endpointservice

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

func TestWinNativeWGDNSReadProvenAbsent(t *testing.T) {
	f := newWinWGFixture()
	steps := f.prepare(t)
	old := f.iface
	f.iface.ID = "new-GUID-same-index"
	f.session.restoreOnly = true
	existsReads, metadataReads, dnsReads := 0, 0, 0
	ops := f.ops()
	ops.exists = func(target nativeInterface) (bool, error) {
		existsReads++
		if !reflect.DeepEqual(target, old) {
			t.Fatal("absence queried another scope")
		}
		return target.ID == f.iface.ID, nil
	}
	ops.read = func(context.Context, string) (TunnelReadback, nativeInterface, error) {
		metadataReads++
		return TunnelReadback{}, nativeInterface{}, errors.New("old adapter is gone")
	}
	ops.dns = func(nativeScope) (nativeValue, error) {
		dnsReads++
		return nativeValue{}, errors.New("old DNS key gone")
	}
	for _, c := range steps {
		value, err := f.state.read(context.Background(), &f.session, c, ops)
		if err != nil || !reflect.DeepEqual(value, nativeValue{}) {
			t.Errorf("positive old GUID absence blocked read barrier: %v", err)
		}
		if nativeValuesEqual(value, c.After) {
			t.Fatal("absence signed an After ACK")
		}

	}
	f.session.restoreOnly = false
	if r, err := f.state.compare(context.Background(), &f.session, steps[0], false, f.expected, ops); err == nil || r.Outcome == "absent" || r.Outcome == "applied" {
		t.Fatal("absence granted fresh apply to active session")
	}
	if existsReads != 3 || metadataReads != 0 || dnsReads != 0 || f.writes != 0 {
		t.Fatalf("gone original scope touched live metadata/new GUID: exists=%d metadata=%d dns=%d writes=%d", existsReads, metadataReads, dnsReads, f.writes)
	}
}
func TestWinNativeWGDNSReadMissingValueIsNotGone(t *testing.T) {
	f := newWinWGFixture()
	c := f.prepare(t)[0]
	f.session.restoreOnly = true
	ops := f.ops()
	ops.read = func(context.Context, string) (TunnelReadback, nativeInterface, error) { return f.raw, f.iface, nil }
	ops.dns = func(nativeScope) (nativeValue, error) { return nativeValue{}, nil }
	if _, err := f.state.read(context.Background(), &f.session, c, ops); err == nil {
		t.Fatal("missing DNS value on present original interface was mistaken for scope absence")
	}
}
func TestWinNativeWGDNSReadValidatesBeforeAbsence(t *testing.T) {
	for _, kind := range []string{"bad proof", "wrong step", "wrong family", "wrong name", "missing scope"} {
		t.Run(kind, func(t *testing.T) {
			f := newWinWGFixture()
			c := f.prepare(t)[0]
			switch kind {
			case "bad proof":
				c.Scope.ServiceID = "noncanonical"
			case "wrong step":
				c.ID = "unowned"
			case "wrong family":
				c.Scope.Family = 0
			case "wrong name":
				c.Scope.Interface.Name = "foreign"
			case "missing scope":
				c.Scope.Interface.ID = ""
			}
			ops := f.ops()
			reads := 0
			ops.exists = func(nativeInterface) (bool, error) { reads++; return false, nil }
			if _, err := f.state.read(context.Background(), &f.session, c, ops); err == nil || reads != 0 {
				t.Fatal("invalid proof reached OS absence lookup")
			}
		})
	}
}

type winWGBarrierOwner struct {
	fakeSystem
	f                  *winWGFixture
	ops                winNativeWGOps
	steps              []nativeChange
	events             *[]string
	compares, releases int
}

func (w *winWGBarrierOwner) PrepareNativeDNS(ctx context.Context, s nativeSession, servers []netip.Addr) ([]nativeChange, error) {
	return w.f.state.prepare(ctx, s, w.f.expected, servers, w.ops)
}
func (w *winWGBarrierOwner) ReadNativeDNS(ctx context.Context, s nativeSession, c nativeChange) (nativeValue, error) {
	return w.f.state.read(ctx, s, c, w.ops)
}
func (w *winWGBarrierOwner) CompareNativeDNS(ctx context.Context, s nativeSession, c nativeChange, restore bool) (nativeReceipt, error) {
	w.compares++
	return w.f.state.compare(ctx, s, c, restore, TunnelReadback{}, w.ops)
}
func (w *winWGBarrierOwner) ReleaseNativeDNS(ctx context.Context, s nativeSession, steps []nativeChange) error {
	w.releases++
	*w.events = append(*w.events, "release")
	return w.f.state.release(ctx, s, steps, w.ops, func(context.Context, winNativeWGProof) error { return nil })
}
func winWGStateBarrierFixture(t *testing.T, kind string) (*CoordinatedExecutor, *nativeRecoveryPlatform, *winWGBarrierOwner, *[]string) {
	t.Helper()
	e, p, _, events := nativeRecoveryFixture(t)
	f := newWinWGFixture()
	steps := f.prepare(t)
	f.session.restoreOnly = true
	old := f.iface
	ops := f.ops()
	switch kind {
	case "gone reused index":
		f.iface.ID = "new-GUID-same-index"
		ops.exists = func(target nativeInterface) (bool, error) {
			if !reflect.DeepEqual(target, old) {
				t.Fatal("recovery checked a replacement scope")
			}
			return target.ID == f.iface.ID, nil
		}
		ops.read = func(context.Context, string) (TunnelReadback, nativeInterface, error) {
			t.Error("gone old GUID read replacement metadata")
			return TunnelReadback{}, nativeInterface{}, errors.New("old grant gone")
		}
		ops.dns = func(nativeScope) (nativeValue, error) {
			t.Error("gone old GUID read replacement DNS")
			return nativeValue{}, errors.New("old DNS gone")
		}
	case "exists unknown":
		ops.exists = func(nativeInterface) (bool, error) { return false, errors.New("complete table permission error") }
	case "metadata unknown":
		ops.read = func(context.Context, string) (TunnelReadback, nativeInterface, error) {
			return TunnelReadback{}, nativeInterface{}, errors.New("metadata inaccessible")
		}
	case "DNS key missing":
		ops.read = func(context.Context, string) (TunnelReadback, nativeInterface, error) { return f.raw, f.iface, nil }
		ops.dns = func(nativeScope) (nativeValue, error) { return nativeValue{}, nil }
	}
	w := &winWGBarrierOwner{fakeSystem: fakeSystem{current: f.expected}, f: f, ops: ops, steps: steps, events: events}
	executor := e.wireGuard.(*Executor)
	executor.system = w
	executor.nativeDNS = steps
	e.native.session = &f.session
	e.native.journal.Owner = f.session.Owner()
	next := 0
	for i := range e.native.journal.Steps {
		step := &e.native.journal.Steps[i]
		if step.Owner == "wireguard" {
			step.Change = steps[next]
			next++
			step.Stage = "restored"
		} else if step.Change.Kind != "route" {
			p.values[step.Change.ID] = step.Change.Before
			step.Stage = "restored"
		}
	}
	// The existing platform cache fixture represents these exact WG scopes as absent.
	p.values["wg4"], p.values["wg6"] = nativeValue{}, nativeValue{}
	if err := saveNativeJournal(e.native.path, e.native.journal); err != nil {
		t.Fatal(err)
	}
	return e, p, w, events
}
func TestWinNativeWGDNSReadAcrossCommonRecoveryBarrier(t *testing.T) {
	for _, kind := range []string{"gone reused index", "exists unknown", "metadata unknown", "DNS key missing"} {
		t.Run(kind, func(t *testing.T) {
			e, p, w, events := winWGStateBarrierFixture(t, kind)
			err := e.restoreNativeLocked(context.Background(), false)
			if kind == "gone reused index" {
				if err != nil || !reflect.DeepEqual(*events, []string{"gate", "flush", "release", "route", "components"}) || w.releases != 1 || p.flushes != 1 || w.compares != 0 || w.f.writes != 0 {
					t.Fatal("positive absence failed barrier or replayed setter", *events, err, w.releases, p.flushes, w.compares, w.f.writes)
				}
				if w.f.state.binding != nil {
					t.Fatal("absent old WG pin not released")
				}
				return
			}
			if err == nil || !e.native.status.CleanupPending || !e.native.journal.CacheFlushPending || !reflect.DeepEqual(*events, []string{"gate"}) || p.flushes != 0 || w.releases != 0 || w.compares != 0 || w.f.writes != 0 {
				t.Fatal("unknown/missing value crossed common barrier", *events, err, p.flushes, w.releases)
			}
		})
	}
}

func TestWinNativeWGDNSReadAbsenceSessionAndOriginalMissing(t *testing.T) {
	for _, kind := range []string{"post validation", "cancel during proof", "cancel before"} {
		t.Run(kind, func(t *testing.T) {
			f := newWinWGFixture()
			c := f.prepare(t)[0]
			f.session.restoreOnly = true
			f.session.calls = 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "post validation" {
				f.session.failAt = 2
			}
			if kind == "cancel before" {
				cancel()
			}
			lookups := 0
			ops := f.ops()
			ops.exists = func(nativeInterface) (bool, error) {
				lookups++
				if kind == "cancel during proof" {
					cancel()
				}
				return false, nil
			}
			if _, err := f.state.read(ctx, &f.session, c, ops); err == nil {
				t.Fatal("absence bypassed session/context revalidation")
			}
			want := 1
			if kind == "cancel before" {
				want = 0
			}
			if lookups != want {
				t.Fatal("wrong authorization order", lookups)
			}
		})
	}
	f := newWinWGFixture()
	c := f.prepare(t)[1]
	f.session.restoreOnly = true
	value, err := f.state.read(context.Background(), &f.session, c, f.ops())
	if err != nil || !reflect.DeepEqual(value, c.Before) || c.Before.Present {
		t.Fatal("legitimate original missing DNS value no longer readable", err)
	}
	if nativeValuesEqual(value, c.After) {
		t.Fatal("original absent value signed After")
	}
	f.raw.Peer.PublicKey = "foreign"
	if _, err := f.state.read(context.Background(), &f.session, c, f.ops()); err == nil {
		t.Fatal("original absent DNS skipped complete live grant proof")
	}
}
