package endpointservice

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
)

func (e *CoordinatedExecutor) readNativeStep(ctx context.Context, step nativeJournalStep) (nativeValue, error) {
	if step.Owner == "wireguard" {
		wg, ok := e.wireGuard.(*Executor)
		if !ok {
			return nativeValue{}, errors.New("WG DNS owner unavailable")
		}
		return wg.readNativeDNS(ctx, e.native.session, step.Change)
	}
	return e.native.platform.ReadChange(ctx, e.native.session, step.Change)
}
func (e *CoordinatedExecutor) compareNativeStep(ctx context.Context, step nativeJournalStep, restore bool) (nativeReceipt, error) {
	if step.Owner == "wireguard" {
		wg, ok := e.wireGuard.(*Executor)
		if !ok {
			return nativeReceipt{}, errors.New("WG DNS owner unavailable")
		}
		return wg.compareNativeDNS(ctx, e.native.session, step.Change, restore)
	}
	if restore {
		return e.native.platform.CompareRestore(ctx, e.native.session, step.Change)
	}
	return e.native.platform.CompareApply(ctx, e.native.session, step.Change)
}
func (e *Executor) releaseNativeDNS(ctx context.Context, s nativeSession, changes []nativeChange) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	owner, ok := e.system.(nativeWGDNSOwner)
	if !ok {
		return errors.New("WG DNS owner unavailable")
	}
	if err := owner.ReleaseNativeDNS(ctx, s, changes); err != nil {
		return err
	}
	e.nativeDNS = nil
	return nil
}

func (c *MihomoController) suspendNativeIngress(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	gateErr := c.egress.close()
	c.egress = nil
	if c.nativeControl == nil {
		return errors.Join(gateErr, errors.New("trusted native controller scope required"))
	}
	running := false
	if c.process != nil {
		c.process.mu.Lock()
		running = c.process.status.State == "running"
		c.process.mu.Unlock()
	}
	if running {
		if err := c.request(ctx, http.MethodPatch, "/configs", []byte(`{"mixed-port":0}`), http.StatusNoContent, nil); err != nil {
			return errors.Join(gateErr, err)
		}
	}
	return gateErr
}

func (e *Executor) nativePeerEndpoint(ctx context.Context, s nativeSession) (netip.AddrPort, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.previous == nil {
		return netip.AddrPort{}, errors.New("active WG grant required")
	}
	actual, err := e.system.Readback(ctx)
	if err != nil || !e.nativeReadbackMatches(actual, e.previous.Readback()) {
		return netip.AddrPort{}, errors.New("WG peer grant changed")
	}
	reader, ok := e.system.(nativeWGPeerReader)
	if !ok {
		return netip.AddrPort{}, errors.New("numeric WG peer reader unavailable")
	}
	endpoint, err := reader.NativePeerEndpoint(ctx, s)
	if err != nil || !endpoint.IsValid() || endpoint.Port() == 0 || endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() {
		return netip.AddrPort{}, errors.Join(err, errors.New("invalid numeric WG peer"))
	}
	return endpoint, nil
}

// RecoverySnapshot reads only for cleanup. Normal Snapshot retains its active
// session validation and cannot use a restore-only session to enable traffic.
type nativeRecoverySnapshotReader interface {
	RecoverySnapshot(context.Context, nativeSession) (nativeSnapshot, error)
}

func (e *CoordinatedExecutor) recoverNativeOwnedProcess(ctx context.Context, record nativeOwnedProcessIdentity) error {
	recovery, ok := e.native.platform.(nativeOwnedProcessRecovery)
	if !ok {
		return errors.New("native process recovery unavailable")
	}
	controller, ok := e.mihomo.(*MihomoController)
	if !ok {
		return errors.New("owned controller recovery unavailable")
	}
	if !e.native.recoveryLockHeld {
		unlock, err := controller.nativeRecoveryLock(record.Proof)
		if err != nil {
			return err
		}
		defer unlock()
	}
	outcome, err := recovery.RecoverOwnedProcess(ctx, e.native.session, record)
	if err != nil || outcome != "stopped" && outcome != "gone" {
		return errors.Join(err, errors.New("old native process release unverified"))
	}
	readSnapshot := e.native.platform.Snapshot
	if reader, ok := e.native.platform.(nativeRecoverySnapshotReader); ok {
		readSnapshot = reader.RecoverySnapshot
	}
	snapshot, err := readSnapshot(ctx, e.native.session)
	if err != nil {
		return err
	}
	for _, step := range e.native.journal.Steps {
		if step.Change.Kind == "route" && step.Change.After.Route != nil && step.Change.After.Route.Interface.Kind == "tunnel" {
			for _, i := range snapshot.Interfaces {
				if i.ID == step.Change.After.Route.Interface.ID {
					return errors.New("old owned TUN interface remains")
				}
			}
		}
		value, err := e.readNativeStep(ctx, step)
		if err != nil {
			return err
		}
		if step.Owner != "wireguard" && !nativeValuesEqual(value, step.Change.Before) {
			return errors.New("native setting changed during process recovery")
		}
	}
	return nil
}
