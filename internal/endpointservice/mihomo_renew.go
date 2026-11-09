package endpointservice

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	api "github.com/opensoha/soha-contracts/gen/go/sohaapi"
	"time"
)

const mihomoLocalStopReason = "mihomo_locally_stopped"

func (e *CoordinatedExecutor) MihomoLocallyStopped() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.locallyStopped()
}
func (e *CoordinatedExecutor) locallyStopped() bool {
	c, ok := e.mihomo.(*MihomoController)
	if !ok || c.process == nil {
		return false
	}
	c.process.mu.Lock()
	defer c.process.mu.Unlock()
	return c.process.stopped
}

func projectionPolicyFingerprint(c *MihomoConfiguration) string {
	if c == nil {
		return ""
	}
	var data any
	if c.Projection != nil {
		p := *c.Projection
		p.ExpiresAt = time.Time{}
		p.Credential.CredentialID = ""
		p.Credential.Secret = ""
		p.Credential.ExpiresAt = time.Time{}
		p.Groups = append([]api.NetworkProxyGroup(nil), p.Groups...)
		for i := range p.Groups {
			p.Groups[i].SelectedNodeID = ""
		}
		data = p
	} else if c.DirectProjection != nil {
		p := *c.DirectProjection
		p.ExpiresAt = time.Time{}
		p.Groups = append([]api.NetworkProxyGroup(nil), p.Groups...)
		for i := range p.Groups {
			p.Groups[i].SelectedNodeID = ""
		}
		data = p
	} else {
		return ""
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return "invalid"
	}
	defer clear(raw)
	return fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
}
func projectionLease(c MihomoConfiguration, until time.Time) time.Time {
	if p := c.Projection; p != nil {
		if p.ExpiresAt.Before(until) {
			until = p.ExpiresAt
		}
		if p.Credential.ExpiresAt.Before(until) {
			until = p.Credential.ExpiresAt
		}
	}
	if p := c.DirectProjection; p != nil && p.ExpiresAt.Before(until) {
		until = p.ExpiresAt
	}
	return until
}

// RenewProjection is the sole in-place lease path. It cannot change policy,
// revive a stopped instance, or extend an old stream beyond its own credential.
func (e *CoordinatedExecutor) RenewProjection(ctx context.Context, desired ConfigurationDesired, now time.Time) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if desired.Mihomo == nil {
		return false, nil
	}
	if e.native != nil && e.native.session != nil {
		if err := e.verifyNativeLocked(ctx); err != nil {
			e.recoverMihomo(ctx, "native_readback_mismatch")
			return false, err
		}
		if e.native.journal.Binding != nativeBindingHash(e.native.identity, *desired.Mihomo) || projectionPolicyFingerprint(e.native.base) != projectionPolicyFingerprint(desired.Mihomo) {
			if err := e.restoreNativeLocked(ctx, false); err != nil {
				return false, err
			}
			return false, nil
		}
	}
	stopped := e.locallyStopped()
	var old MihomoConfiguration
	if e.previousMihomo != nil {
		old = e.previousMihomo.Configuration
		if e.proxyNarrowed && e.proxyDesired != nil {
			old = *e.proxyDesired
		}
	} else if stopped && e.proxyDesired != nil {
		old = *e.proxyDesired
	} else {
		return false, nil
	}
	if old.Projection != nil && desired.Mihomo.Projection != nil {
		a, b := old.Projection, desired.Mihomo.Projection
		if a.BundleID == b.BundleID && a.Revision == b.Revision && a.ProjectionHash == b.ProjectionHash && a.ProcessEpoch == b.ProcessEpoch && a.CredentialEpoch == b.CredentialEpoch && (a.Credential.CredentialID != b.Credential.CredentialID || a.Credential.Secret != b.Credential.Secret) {
			if !stopped || old.Projection.Credential.ExpiresAt.After(now) {
				return false, errors.New("credential mutation requires cold reauthorization")
			}
		}
		if a.ProcessEpoch != b.ProcessEpoch {
			return false, errors.New("projection boot identity changed")
		}
		if a.BundleID != b.BundleID || a.Revision != b.Revision || a.ProjectionHash != b.ProjectionHash || a.ProcessEpoch != b.ProcessEpoch || a.CredentialEpoch != b.CredentialEpoch {
			return false, nil
		}
	}
	if projectionPolicyFingerprint(&old) == "" || projectionPolicyFingerprint(&old) != projectionPolicyFingerprint(desired.Mihomo) {
		if e.narrowTemplate != nil {
			return e.tryNarrowProjection(ctx, desired, now)
		}
		return false, nil
	}
	if e.proxyNarrowed && !stopped {
		return e.tryNarrowProjection(ctx, desired, now)
	}
	c, ok := e.mihomo.(*MihomoController)
	if !ok {
		return false, nil
	}
	fail := func() (bool, error) {
		e.recoverMihomo(ctx, "projection_renewal_failed")
		return false, errors.New("projection renewal failed")
	}
	if err := e.bindMihomoVPN(ctx, &old); err != nil {
		return fail()
	}
	if stopped {
		if err := c.Verify(ctx, nil); err != nil {
			return fail()
		}
		verifier, ok := e.wireGuard.(interface {
			Verify(context.Context, ConfigurationDesired, time.Time) ApplyOutcome
		})
		if !ok {
			return false, nil
		}
		if outcome := verifier.Verify(ctx, desired, now); outcome.Status != "applied" {
			return fail()
		}
		next := cloneMihomoConfiguration(*desired.Mihomo)
		next.DNSRecords = old.DNSRecords
		next.VPNRoutes = old.VPNRoutes
		next.VPNInterface = old.VPNInterface
		next.EnforcementUntil = projectionLease(next, desired.ValidUntil)
		if err := e.composePersonal(&next); err != nil {
			return fail()
		}
		e.proxyDesired = &next
		return true, nil
	}
	if !e.mihomoActive {
		return false, nil
	}
	if err := c.Verify(ctx, &old); err != nil {
		return fail()
	}
	next := cloneMihomoConfiguration(old)
	next.Projection = cloneMihomoConfiguration(*desired.Mihomo).Projection
	next.DirectProjection = cloneMihomoConfiguration(*desired.Mihomo).DirectProjection
	next.EnforcementUntil = projectionLease(next, desired.ValidUntil)
	if !next.EnforcementUntil.After(now) {
		return fail()
	}
	// Local group choices remain local preferences inside the same allowed groups.
	for i, g := range configurationGroups(next) {
		for _, prior := range configurationGroups(old) {
			if g.GroupID == prior.GroupID {
				if next.Projection != nil {
					next.Projection.Groups[i].SelectedNodeID = prior.SelectedNodeID
				} else {
					next.DirectProjection.Groups[i].SelectedNodeID = prior.SelectedNodeID
				}
			}
		}
	}
	c.mu.Lock()
	ownerOK := true
	if c.process != nil {
		c.process.mu.Lock()
		ownerOK = c.process.cmd != nil && c.process.status.State == "running" && !c.process.stopped
		c.process.mu.Unlock()
	}
	if !ownerOK || c.egress == nil {
		c.mu.Unlock()
		return fail()
	}
	c.egress.refreshProjection(next.Projection)
	err := c.egress.refreshLease(next.EnforcementUntil)
	if err == nil {
		current := cloneMihomoConfiguration(next)
		c.current = &current
	}
	c.mu.Unlock()
	if err != nil {
		return fail()
	}
	if e.native != nil && e.native.session != nil {
		n := e.native
		base := cloneMihomoConfiguration(next)
		base.NativePlan = nil
		base.DNSMode = n.base.DNSMode
		base.FakeIPRange = n.base.FakeIPRange
		n.base = &base
		n.guard.mu.Lock()
		binding := n.guard.binding
		n.guard.mu.Unlock()
		if err := n.guard.renewLease(ctx, binding, next.EnforcementUntil); err != nil {
			return fail()
		}
		if n.dns != nil {
			n.dns.renew(next.EnforcementUntil, next.DNSRecords)
		}
		if n.forward != nil && n.forward.proxy != nil {
			n.forward.proxy.renew(next.EnforcementUntil, nil)
		}
	}
	e.previousMihomo.Configuration = next
	e.proxyDesired = &next
	return true, nil
}
func (manager *Manager) reportProjection(ctx context.Context, desired ConfigurationDesired, status, reason string) error {
	if desired.Mihomo == nil {
		return nil
	}
	p := desired.Mihomo.Projection
	if p == nil && desired.Mihomo.DirectProjection != nil {
		tag := directProjectionTag(*desired.Mihomo.DirectProjection)
		p = &tag
	}
	if p == nil {
		return nil
	}
	control, ok := manager.control.(interface {
		ReportMihomoProjection(context.Context, string, api.NetworkProxyProjectionApplied) error
	})
	if !ok {
		return errors.New("projection receipt unavailable")
	}
	if manager.proxyLocallyStopped() && (status == "applied" || reason == mihomoLocalStopReason) {
		status = "rejected"
		reason = mihomoLocalStopReason
	}
	return control.ReportMihomoProjection(ctx, p.ProfileID, api.NetworkProxyProjectionApplied{BundleID: p.BundleID, Revision: p.Revision, ProjectionHash: p.ProjectionHash, ProcessEpoch: p.ProcessEpoch, Status: api.NetworkProxyProjectionAppliedStatus(status), ReasonCode: reason})
}

func (manager *Manager) proxyLocallyStopped() bool {
	state, ok := manager.executor.(interface{ MihomoLocallyStopped() bool })
	return ok && state.MihomoLocallyStopped()
}
func applyLocalProxyStatus(status *Status, desired ConfigurationDesired, stopped, pendingReceipt bool) {
	applyDesiredStatus(status, desired)
	if stopped {
		status.ValidUntil = desired.ValidUntil
		status.Diagnostic = mihomoLocalStopReason
		if pendingReceipt {
			status.Diagnostic = "mihomo_stop_receipt_pending"
		}
		if desired.WireGuard == nil {
			status.State = StateDisconnected
		}
	}
}

// Only an explicit local stop with a successfully accepted/verified endpoint
// configuration may defer proxy receipts. Every other failure keeps fail-closed.
func (manager *Manager) deliverProjectionReceipt(ctx context.Context, desired ConfigurationDesired, status, reason string) error {
	localStop := manager.proxyLocallyStopped() && (reason == mihomoLocalStopReason || status == "applied")
	err := manager.reportProjection(ctx, desired, status, reason)
	pending := err != nil && localStop
	manager.stateMu.Lock()
	manager.proxyReceiptPending = pending
	manager.stateMu.Unlock()
	if coordinator, ok := manager.executor.(*CoordinatedExecutor); ok {
		coordinator.mu.Lock()
		coordinator.proxyReceiptPending = pending
		coordinator.mu.Unlock()
	}
	if pending {
		return nil
	}
	return err
}
func (manager *Manager) projectionReceiptPending() bool {
	manager.stateMu.RLock()
	defer manager.stateMu.RUnlock()
	return manager.proxyReceiptPending
}
