package endpointservice

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type nativeEnginePlan struct {
	ProbeHost         string
	DNSBypassHosts    []string
	TUN               bool
	Device            string
	FakeIPPool        netip.Prefix
	TUNAddress        netip.Prefix
	FakeIPv6Pool      netip.Prefix
	TUNAddress6       netip.Prefix
	DNSUpstream       netip.AddrPort
	PhysicalInterface string
	NodeInterfaces    map[string]string
}
type nativeInterception struct {
	recoveryLockHeld                 bool
	uiExpectedServer, uiExpectedUser string
	uiScope                          NativeUIScope
	uiPeerPID                        uint32
	uiOwner                          nativeOwner
	uiRetired                        map[string]bool
	uiLease                          atomic.Int64
	platform                         nativePlatform
	guard                            *nativeGuard
	path                             string
	journal                          nativeJournal
	status                           InterceptionStatus
	session                          nativeSession
	presence                         *UIProcessPresence
	identity                         string
	controls                         []string
	invalidJournal                   bool
	subscriptionState                *mihomoAppState
	base                             *MihomoConfiguration
	dns                              *nativeDNSProxy
	forward                          *nativeDNSForward
}

func (e *CoordinatedExecutor) ConfigureNativeInterception(config Config, presence *UIProcessPresence, clients ...*http.Client) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	p, platformErr := newNativeInterceptionPlatform(config, presence)
	n := &nativeInterception{platform: p, path: filepath.Join(config.StateDirectory, "native-interception", "journal"), presence: presence, guard: &nativeGuard{platform: p}}
	identityRaw, _ := json.Marshal([]string{config.ControlURL, config.RuntimeID, config.DeviceID})
	n.identity = fmt.Sprintf("sha256:%x", sha256.Sum256(identityRaw))
	n.guard.internal = map[netip.AddrPort]bool{}
	origins := []string{config.ControlURL, config.IngestURL}
	if origin, _, err := config.nativeUIBinding(); err == nil {
		origins = append(origins, origin)
	}
	for _, origin := range origins {
		u, err := url.Parse(origin)
		if err != nil || u.Hostname() == "" {
			continue
		}
		n.controls = append(n.controls, u.Hostname())
		if u.Hostname() == "localhost" {
			port := 443
			if u.Scheme == "http" {
				port = 80
			}
			if u.Port() != "" {
				port, _ = strconv.Atoi(u.Port())
			}
			if port > 0 && port <= 65535 {
				for _, ip := range []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()} {
					n.guard.internal[netip.AddrPortFrom(ip, uint16(port))] = true
				}
			}
		}
		ip, err := netip.ParseAddr(u.Hostname())
		if err == nil && ip.IsLoopback() {
			port := 443
			if u.Scheme == "http" {
				port = 80
			}
			if u.Port() != "" {
				port, _ = strconv.Atoi(u.Port())
			}
			if port > 0 && port <= 65535 {
				n.guard.internal[netip.AddrPortFrom(ip, uint16(port))] = true
			}
		}
	}

	n.status.State = interceptionInactive
	n.status.ObservedAt = time.Now().UTC()
	if platformErr != nil || p == nil || presence == nil || presence.verify == nil {
		n.status.Capabilities.ReasonCode = "trusted_native_ui_unavailable"
	} else {
		n.status.Capabilities = InterceptionCapabilities{SystemProxy: true, TUN: true}
		if config.MihomoProcess.Ownership != "soha_owned" {
			n.status.Capabilities = InterceptionCapabilities{ReasonCode: "native_owned_engine_required"}
		} else if !nativeKernelSupported(config.MihomoProcess.Version) {
			n.status.Capabilities = InterceptionCapabilities{ReasonCode: "native_kernel_version_unsupported"}
		}
	}
	if server, user, bindingErr := config.nativeUIBinding(); bindingErr != nil {
		n.status.Capabilities = InterceptionCapabilities{ReasonCode: bindingErr.Error()}
	} else {
		n.uiExpectedServer = server
		n.uiExpectedUser = user
	}
	if presence != nil && (n.status.Capabilities.SystemProxy || n.status.Capabilities.TUN) {
		presence.authenticate = p.Authenticate
	}
	var err error
	n.journal, err = loadNativeJournal(n.path)
	if err != nil {
		n.invalidJournal = true
		n.journal = nativeJournal{Version: 1, Pending: true}
		n.status.ReasonCode = "native_journal_unreadable"
	}
	if n.journal.Pending || len(n.journal.Steps) > 0 || n.journal.CacheFlushPending || n.journal.DNSReleasePending || n.journal.Process != nil {
		n.status.State = interceptionCleanupPending
		n.status.CleanupPending = true
		n.guard.blocked = true
	}
	n.status.Generation = n.journal.Generation
	e.native = n
	for _, c := range clients {
		if err := n.guard.attach(c); err != nil {
			return err
		}
	}
	if controller, ok := e.mihomo.(*MihomoController); ok {
		controller.nativeEgress = n.guard
	}
	// A restart only restores owned changes. It never replays an enable request.
	if n.status.CleanupPending && err == nil && p != nil {
		return e.restoreNativeLocked(context.Background(), false)
	}
	return nil
}
func (e *CoordinatedExecutor) LocalProxyInterception() InterceptionStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.native == nil {
		return InterceptionStatus{State: interceptionInactive, ObservedAt: time.Now().UTC(), Capabilities: InterceptionCapabilities{ReasonCode: "native_interception_not_configured"}}
	}
	return e.nativeStatusLocked()
}
func (e *CoordinatedExecutor) authenticateInterception(ctx context.Context, c net.Conn) (NativePeer, error) {
	e.mu.Lock()
	n := e.native
	e.mu.Unlock()
	if n == nil || n.platform == nil {
		return NativePeer{}, errors.New("native authentication unavailable")
	}
	return n.platform.Authenticate(ctx, c)
}
func (e *CoordinatedExecutor) SetInterception(ctx context.Context, peer NativePeer, intent InterceptionIntent) (InterceptionStatus, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := e.native
	if n == nil {
		return InterceptionStatus{}, errors.New("native interception not configured")
	}
	fail := func(err error) (InterceptionStatus, error) { return n.status, err }
	if peer.session == nil || peer.pid == 0 || peer.owner != peer.session.Owner() || peer.owner.UserID == "" || peer.owner.SessionID == "" || peer.session.Validate(ctx, false) != nil {
		return fail(errors.New("trusted current native UI required"))
	}
	defer func() {
		if n.session != peer.session {
			peer.session.Close()
		}
	}()
	if n.invalidJournal {
		return fail(errors.New("native recovery journal requires administrator repair"))
	}
	if !identifierPattern.MatchString(intent.RequestID) {
		return fail(errors.New("invalid native request identifier"))
	}
	if n.journal.Owner == peer.owner && n.journal.Request.RequestID == intent.RequestID {
		if n.journal.Request != intent {
			return fail(errors.New("native request identifier reused"))
		}
		return n.status, nil
	}
	if intent.ExpectedGeneration != n.journal.Generation || n.journal.Generation == math.MaxUint64 {
		return fail(errors.New("native generation conflict"))
	}
	if (intent.SystemProxy && !n.status.Capabilities.SystemProxy) || (intent.TUN && !n.status.Capabilities.TUN) {
		return fail(errors.New("native capability unavailable"))
	}
	if (n.status.CleanupPending || n.session != nil) && (n.journal.Owner.UserID != "" && n.journal.Owner != peer.owner) {
		return fail(errors.New("another native owner requires restoration"))
	}
	if !intent.SystemProxy && !intent.TUN {
		n.journal.Generation++
		n.journal.Owner = peer.owner
		n.journal.Request = intent
		n.journal.Request.ExpectedGeneration = intent.ExpectedGeneration
		n.journal.Pending = len(n.journal.Steps) > 0
		if err := saveNativeJournal(n.path, n.journal); err != nil {
			return fail(err)
		}
		n.status.Generation = n.journal.Generation
		n.status.DesiredSystemProxy = false
		n.status.DesiredTUN = false
		err := e.restoreNativeLocked(ctx, true)
		return n.status, err
	}
	if n.status.CleanupPending {
		return fail(errors.New("native cleanup required"))
	}
	if reason := n.uiScopeReason(nil); reason != "" || n.uiPeerPID != peer.pid || n.uiOwner != peer.owner {
		return fail(errors.New("current authenticated native UI scope required"))
	}
	if e.previousMihomo == nil || !e.mihomoActive {
		return fail(errors.New("verified active proxy configuration required"))
	}
	base := cloneMihomoConfiguration(e.previousMihomo.Configuration)
	if n.base != nil {
		base = cloneMihomoConfiguration(*n.base)
	}
	base.NativePlan = nil
	if reason := n.uiScopeReason(&base); reason != "" {
		return fail(errors.New("native UI does not match the enrolled proxy principal"))
	}
	var subscriptionState *mihomoAppState
	if base.Mode == "app_subscription" {
		if _, err := nativeSubscriptionBinding(base, e.previousMihomo.AppState); err != nil {
			return fail(err)
		}
		value := *e.previousMihomo.AppState
		subscriptionState = &value
	}
	if !base.EnforcementUntil.After(time.Now()) || base.Protection == nil {
		return fail(errors.New("valid native authorization required"))
	}
	if c, ok := e.mihomo.(*MihomoController); ok {
		status := c.ProcessStatus()
		if status.Ownership != "soha_owned" {
			return fail(errors.New("native interception requires the owned engine"))
		}
		if !nativeKernelSupported(status.Version) {
			return fail(errors.New("native interception requires the verified supported kernel version"))
		}
	}
	if n.session != nil {
		if err := e.restoreNativeLocked(ctx, false); err != nil {
			return fail(err)
		}
	}
	snapshot, err := n.platform.Snapshot(ctx, peer.session)
	if err != nil {
		return fail(err)
	}
	if intent.TUN && !nativeHasGlobalIPv6(snapshot) {
		n.status.ReasonCode = "native_ipv6_unavailable"
		return fail(errors.New("native TUN requires a global-unicast IPv6 interface address"))
	}
	var processIdentity *nativeOwnedProcessIdentity
	if recovery, ok := n.platform.(nativeOwnedProcessRecovery); ok {
		controller, ok := e.mihomo.(*MihomoController)
		if !ok {
			return fail(errors.New("owned native controller required"))
		}
		proof, err := controller.nativeOwnedProof()
		if err != nil {
			return fail(err)
		}
		record, err := recovery.CaptureOwnedProcess(ctx, peer.session, proof)
		if err != nil {
			return fail(err)
		}
		if record.Incarnation == "" || !reflect.DeepEqual(record.Proof, proof) {
			return fail(errors.New("native process capture mismatch"))
		}
		processIdentity = &record
	} else if runtime.GOOS == "darwin" {
		if _, ok := e.mihomo.(*MihomoController); ok {
			return fail(errors.New("native process recovery unavailable"))
		}
	}
	n.journal = nativeJournal{Version: 1, Generation: n.journal.Generation + 1, Owner: peer.owner, Request: intent, Pending: true, Binding: nativeBindingHash(n.identity, base)}
	n.journal.Process = processIdentity
	n.journal.UIBindingHash = nativeUIScopeBinding(n.uiScope)
	if subscriptionState != nil {
		n.journal.SubscriptionBinding, _ = nativeSubscriptionBinding(base, subscriptionState)
	}
	if c, ok := e.mihomo.(*MihomoController); ok {
		n.journal.ProcessEpoch = c.ProcessStatus().ProcessEpoch
	}
	if err = saveNativeJournal(n.path, n.journal); err != nil {
		return fail(err)
	}
	n.session = peer.session
	n.base = &base
	n.subscriptionState = subscriptionState
	n.status.Generation = n.journal.Generation
	n.status.DesiredSystemProxy = intent.SystemProxy
	n.status.DesiredTUN = intent.TUN
	n.status.State = interceptionPreparing
	n.status.ReasonCode = ""
	err = e.enableNativeLocked(ctx, snapshot, base, intent)
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = peer.session.Validate(ctx, false)
	}
	if err != nil {
		cleanupErr := e.restoreNativeLocked(ctx, true)
		n.status.ReasonCode = "native_apply_failed"
		if !n.status.CleanupPending {
			n.status.State = interceptionFailed
		}
		return fail(errors.Join(err, cleanupErr))
	}
	n.status.SystemProxy = intent.SystemProxy
	n.status.TUN = intent.TUN
	n.status.State = interceptionActive
	n.status.ObservedAt = time.Now().UTC()
	return n.status, nil
}
func (e *CoordinatedExecutor) enableNativeLocked(ctx context.Context, s nativeSnapshot, c MihomoConfiguration, intent InterceptionIntent) error {
	n := e.native
	wg := TunnelReadback{}
	if w, ok := e.wireGuard.(*Executor); ok {
		var err error
		wg, err = w.nativeReadback(ctx)
		if err != nil {
			return err
		}
	}
	binding := &nativeEgressBinding{snapshot: s, session: n.session, wg: wg, until: c.EnforcementUntil, uiLease: &n.uiLease}
	dns, err := startNativeDNS(s.Resolvers, c.DNSRecords, c.EnforcementUntil, n.guard.DialPinned)
	if err != nil {
		return err
	}
	n.dns = dns
	binding.dns = dns
	n.guard.set(binding, false)
	controls, err := nativeControlAddresses(ctx, dns, n.controls)
	if err != nil {
		return err
	}
	if wg.Peer.Endpoint != "" {
		w, ok := e.wireGuard.(*Executor)
		if !ok {
			return errors.New("verified WG peer unavailable")
		}
		peer, err := w.nativePeerEndpoint(ctx, n.session)
		if err != nil {
			return err
		}
		controls = append(controls, peer.Addr())
	}
	ep := &nativeEnginePlan{TUN: intent.TUN, DNSUpstream: dns.endpoint(), NodeInterfaces: map[string]string{}}
	for _, host := range n.controls {
		if _, err := netip.ParseAddr(host); err != nil {
			if name, err := nativeDNSName(host); err == nil {
				ep.DNSBypassHosts = append(ep.DNSBypassHosts, name)
			}
		}
	}
	if wg.Peer.Endpoint != "" {
		host, _, _ := net.SplitHostPort(wg.Peer.Endpoint)
		if _, err := netip.ParseAddr(host); err != nil {
			if name, err := nativeDNSName(host); err == nil {
				ep.DNSBypassHosts = append(ep.DNSBypassHosts, name)
			}
		}
	}
	slices.Sort(ep.DNSBypassHosts)
	ep.DNSBypassHosts = slices.Compact(ep.DNSBypassHosts)
	for _, r := range s.Routes {
		if r.Destination.IsValid() && r.Destination.Bits() == 0 && r.Destination.Addr().Is4() && r.Interface.Kind == "physical" {
			if ep.PhysicalInterface != "" && ep.PhysicalInterface != r.Interface.Name {
				return errors.New("ambiguous physical default")
			}
			ep.PhysicalInterface = r.Interface.Name
		}
	}
	if ep.PhysicalInterface == "" {
		return errors.New("physical default unavailable")
	}
	for _, r := range s.Routes {
		if r.Destination.IsValid() && r.Destination.Bits() == 0 && r.Destination.Addr().Is6() && r.Interface.Kind == "physical" && r.Interface.Name != ep.PhysicalInterface {
			return errors.New("dual-stack physical defaults are ambiguous")
		}
	}
	if intent.TUN {
		ep.Device = "SohaMihomo"
		if runtime.GOOS == "darwin" {
			ep.Device = "utun233"
		}
		ep.FakeIPPool, err = chooseNativePool(s, wg)
		if err != nil {
			return err
		}
		ep.TUNAddress = netip.PrefixFrom(ep.FakeIPPool.Addr().Next(), 30)
		ep.FakeIPv6Pool, err = chooseNativeIPv6Pool(s, wg, c.Protection)
		if err != nil {
			return err
		}
		ep.TUNAddress6 = netip.PrefixFrom(ep.FakeIPv6Pool.Addr().Next(), 126)
		for _, i := range s.Interfaces {
			if i.Name == ep.Device {
				return errors.New("native TUN interface already exists")
			}
		}
		n.forward, err = reserveNativeDNS()
		if err != nil {
			return err
		}
		n.forward.proxy.renew(c.EnforcementUntil, nil)
		c.DNSMode = "fake_ip"
		c.FakeIPRange = ep.FakeIPPool.String()
	}
	c.NativePlan = ep
	c.Egress = n.guard
	if err = n.session.Validate(ctx, false); err != nil {
		return err
	}
	if err = e.prepareNativeQuiesce(ctx, c); err != nil {
		return err
	}
	if n.forward != nil {
		n.forward.releaseIPv4()
	}
	if err = e.applyNativeEngineLocked(ctx, c); err != nil {
		return err
	}
	if err = n.session.Validate(ctx, false); err != nil {
		return err
	}
	if n.forward != nil {
		if err = n.forward.start(); err != nil {
			return err
		}
	}
	actual, err := n.platform.Snapshot(ctx, n.session)
	if err != nil {
		return err
	}
	binding = &nativeEgressBinding{snapshot: actual, session: n.session, wg: wg, until: c.EnforcementUntil, dns: dns, uiLease: &n.uiLease}
	n.guard.set(binding, false)
	plan := nativeInterceptionPlan{SystemProxy: intent.SystemProxy, TUN: intent.TUN, ProxyEndpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(c.MixedPort))}
	if intent.TUN {
		for _, i := range actual.Interfaces {
			if i.Name == ep.Device {
				plan.TUNInterface = i
			}
		}
		if plan.TUNInterface.ID == "" || plan.TUNInterface.Index == 0 {
			return errors.New("native TUN readback missing")
		}
		found, found6 := false, false
		for _, p := range plan.TUNInterface.Addresses {
			if p == ep.TUNAddress6 {
				found6 = true
			}
			if p == ep.TUNAddress {
				found = true
			}
		}
		if !found || !found6 {
			return errors.New("native TUN address mismatch")
		}
		plan.DNSServers = []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()}
		plan.CapturePrefixes, _, err = nativePlanCaptures(s, wg, controls)
		if err != nil {
			return err
		}
	}
	if intent.TUN {
		if err = e.verifyNativeListenerOwnership(ctx); err != nil {
			return err
		}
	}
	changes, err := n.platform.PlanChanges(s, plan)
	if err != nil {
		return err
	}
	steps := make([]nativeJournalStep, 0, len(changes)+2)
	for _, c := range changes {
		steps = append(steps, nativeJournalStep{Owner: "platform", Change: c, Stage: "prepared"})
	}
	if intent.TUN {
		if w, ok := e.wireGuard.(*Executor); ok {
			delegations, err := w.prepareNativeDNS(ctx, n.session, plan.DNSServers)
			if err != nil {
				return err
			}
			for _, c := range delegations {
				steps = append(steps, nativeJournalStep{Owner: "wireguard", Change: c, Stage: "prepared"})
			}
		}
	}
	priority := func(kind string) int {
		switch kind {
		case "route":
			return 0
		case "dns":
			return 1
		default:
			return 2
		}
	}
	slices.SortStableFunc(steps, func(a, b nativeJournalStep) int { return priority(a.Change.Kind) - priority(b.Change.Kind) })
	preflight := n.journal
	preflight.Steps = steps
	if err = validateNativeJournal(preflight); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, planned := range steps {
		if !validNativeChange(planned.Change) || seen[planned.Change.ID] {
			return errors.New("invalid or duplicate native change")
		}
		seen[planned.Change.ID] = true
	}
	n.journal.Steps = steps
	for _, step := range steps {
		if step.Change.Kind == "dns" {
			n.journal.CacheFlushPending = true
		}
		if step.Owner == "wireguard" {
			n.journal.DNSReleasePending = true
		}
	}
	if err = saveNativeJournal(n.path, n.journal); err != nil {
		return err
	}
	for i := range n.journal.Steps {
		step := &n.journal.Steps[i]
		change := step.Change
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = n.session.Validate(ctx, false); err != nil {
			return err
		}
		receipt, applyErr := e.compareNativeStep(ctx, *step, false)
		step.Stage = "unknown"
		if receipt.ChangeID == change.ID && receipt.Outcome == "applied" && nativeValuesEqual(receipt.Current, change.After) {
			step.Stage = "written"
		}
		if saveErr := saveNativeJournal(n.path, n.journal); saveErr != nil {
			return errors.Join(applyErr, saveErr)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if applyErr != nil || step.Stage != "written" {
			return errors.Join(applyErr, errors.New("native write not verified"))
		}
	}
	actual, err = n.platform.Snapshot(ctx, n.session)
	if err != nil {
		return err
	}
	if intent.TUN {
		_, exceptions, err := nativePlanCaptures(s, wg, controls)
		if err != nil {
			return err
		}
		if err = verifyNativeCoverage(actual, plan.TUNInterface, plan.CapturePrefixes, exceptions); err != nil {
			return err
		}
	}
	binding = &nativeEgressBinding{snapshot: actual, session: n.session, wg: wg, until: c.EnforcementUntil, dns: dns, uiLease: &n.uiLease}
	n.guard.set(binding, false)
	if err = e.verifyNativeLocked(ctx); err != nil {
		return err
	}
	if intent.TUN {
		if controller, ok := e.mihomo.(*MihomoController); ok {
			if err = controller.verifyNativeProbe(ctx, plan.TUNInterface, ep); err != nil {
				return err
			}
		} else {
			return errors.New("native TUN health unavailable")
		}
	}
	if intent.TUN {
		if err = n.forward.start(); err != nil {
			return err
		}
	}
	n.status.Impact = InterceptionImpact{SystemProxyScope: "current_user", NetworkService: s.PrimaryServiceName, IPv4: intent.TUN, IPv6: intent.TUN, DNS: intent.TUN}
	if runtime.GOOS == "darwin" {
		n.status.Impact.SystemProxyScope = "network_service"
	}
	return nil
}
func chooseNativePool(s nativeSnapshot, wg TunnelReadback) (netip.Prefix, error) {
	for _, text := range []string{"198.18.0.0/16", "198.19.0.0/16"} {
		p := netip.MustParsePrefix(text)
		conflict := false
		for _, i := range s.Interfaces {
			for _, a := range i.Addresses {
				if p.Overlaps(a) {
					conflict = true
				}
			}
		}
		for _, r := range s.Routes {
			if r.Destination.IsValid() && r.Destination.Bits() > 0 && p.Overlaps(r.Destination) {
				conflict = true
			}
		}
		for _, r := range wg.Routes {
			if a, e := netip.ParsePrefix(r); e != nil || p.Overlaps(a) {
				conflict = true
			}
		}
		if !conflict {
			return p, nil
		}
	}
	return netip.Prefix{}, errors.New("native fake-IP pool conflicts with existing network")
}
func (e *CoordinatedExecutor) applyNativeEngineLocked(ctx context.Context, c MihomoConfiguration) error {
	if c.Mode == "app_subscription" {
		r, ok := e.mihomo.(MihomoAppRuntime)
		if !ok {
			return errors.New("subscription runtime unavailable")
		}
		// App-owned source and selection live in the private AppState, never
		// in the Core configuration/ACK. Keep both across Native transforms.
		if e.previousMihomo == nil || e.previousMihomo.AppState == nil {
			return errors.New("configured subscription state required")
		}
		state := *e.previousMihomo.AppState
		if e.native != nil && e.native.subscriptionState != nil {
			state = *e.native.subscriptionState
		}
		if _, err := nativeSubscriptionBinding(c, &state); err != nil {
			return err
		}
		status, err := r.ApplySubscription(ctx, c, state.SubscriptionURL, state.SelectedProxy)
		if err != nil {
			return err
		}
		if !validMihomoAppStatus(status, c) || status.SelectedProxy != state.SelectedProxy {
			return errors.New("native subscription readback mismatch")
		}
		e.appStatus = status
		e.previousMihomo.AppStatus = cloneMihomoAppStatus(status)
		e.previousMihomo.AppState = &state
	} else {
		if _, err := e.mihomo.Apply(ctx, c); err != nil {
			return err
		}
	}
	if e.previousMihomo == nil {
		e.previousMihomo = &mihomoAppliedState{}
	}
	e.previousMihomo.Configuration = cloneMihomoConfiguration(c)
	e.mihomoActive = true
	return nil
}
func (e *CoordinatedExecutor) verifyNativeLocked(ctx context.Context) error {
	n := e.native
	if n == nil || n.session == nil {
		return nil
	}
	if err := n.session.Validate(ctx, false); err != nil {
		return err
	}
	if n.uiScopeReason(n.base) != "" || n.journal.UIBindingHash != nativeUIScopeBinding(n.uiScope) {
		return errors.New("native UI scope expired or changed")
	}
	if n.base == nil || n.journal.Binding != nativeBindingHash(n.identity, *n.base) {
		return errors.New("native enrollment identity changed")
	}
	if n.base.Mode == "app_subscription" {
		if e.previousMihomo == nil {
			return errors.New("native subscription identity unavailable")
		}
		binding, err := nativeSubscriptionBinding(*n.base, e.previousMihomo.AppState)
		if err != nil || binding != n.journal.SubscriptionBinding {
			return errors.New("native subscription identity changed")
		}
	}
	if err := e.verifyNativeListenerOwnership(ctx); err != nil {
		return err
	}
	for _, step := range n.journal.Steps {
		value, err := e.readNativeStep(ctx, step)
		if err != nil || !nativeValuesEqual(value, step.Change.After) {
			return errors.New("native OS state drifted")
		}
	}
	verifier, ok := e.mihomo.(interface {
		Verify(context.Context, *MihomoConfiguration) error
	})
	if !ok || e.previousMihomo == nil {
		return errors.New("native engine readback unavailable")
	}
	return verifier.Verify(ctx, &e.previousMihomo.Configuration)
}
func (e *CoordinatedExecutor) restoreNativeLocked(parent context.Context, restoreEngine bool) error {
	n := e.native
	if n == nil {
		return nil
	}
	if n.invalidJournal {
		return errors.New("native recovery journal requires administrator repair")
	}
	if n.session == nil && !n.journal.Pending && len(n.journal.Steps) == 0 && !n.journal.CacheFlushPending && !n.journal.DNSReleasePending {
		return nil
	}
	if controller, ok := e.mihomo.(*MihomoController); ok {
		controller.mu.Lock()
		controller.nativeControlRequired = true
		controller.mu.Unlock()
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 15*time.Second)
	defer cancel()
	n.status.State = interceptionStopping
	n.guard.set(nil, true)
	n.journal.Request.SystemProxy = false
	n.journal.Request.TUN = false
	n.status.DesiredSystemProxy = false
	n.status.DesiredTUN = false
	pending := func(reason string, err error) error {
		n.status.State = interceptionCleanupPending
		n.status.CleanupPending = true
		n.status.ReasonCode = reason
		n.status.ObservedAt = time.Now().UTC()
		return err
	}
	if err := saveNativeJournal(n.path, n.journal); err != nil {
		return pending("native_journal_write_failed", err)
	}
	if n.session == nil && (len(n.journal.Steps) > 0 || n.journal.CacheFlushPending || n.journal.DNSReleasePending || n.journal.Process != nil || n.journal.Quiesce != nil) {
		if n.platform == nil {
			return pending("native_restore_session_unavailable", errors.New("native platform unavailable"))
		}
		session, err := n.platform.AcquireRestoreSession(ctx, n.journal.Owner)
		if err != nil {
			return pending("native_restore_session_unavailable", err)
		}
		n.session = session
	}
	if _, real := e.mihomo.(*MihomoController); real && n.journal.Quiesce == nil {
		// Missing material does not prove an untouched engine. In particular,
		// failed preparation must never enter the legacy unpinned stop path.
		return pending("native_control_scope_unavailable", errors.New("trusted native controller stop material unavailable"))
	}
	unlock, err := e.nativeRestoreOwnerLock()
	if err != nil {
		return pending("native_owner_lock_unavailable", err)
	}
	defer unlock()
	if n.forward != nil {
		if err := n.forward.quiesce(ctx); err != nil {
			return pending("native_dns_quiesce_failed", err)
		}
	}
	// Keep DNS/TUN alive until DNS restoration, cache invalidation and WG peer
	// release finish, but close all managed business entry points immediately.
	if controller, ok := e.mihomo.(*MihomoController); ok && n.journal.Quiesce != nil {
		if err := controller.quiesceOwnedNativeIngress(ctx, n.session, n.platform, n.journal.Quiesce); err != nil {
			return pending("native_dns_quiesce_failed", err)
		}
	} else if quiescer, ok := e.mihomo.(interface{ suspendNativeIngress(context.Context) error }); ok {
		if err := quiescer.suspendNativeIngress(ctx); err != nil {
			return pending("native_ingress_stop_failed", err)
		}
	}
	for _, kind := range []string{"proxy", "dns"} {
		var failures []error
		for i := len(n.journal.Steps) - 1; i >= 0; i-- {
			step := &n.journal.Steps[i]
			if step.Change.Kind != kind || step.Stage == "restored" {
				continue
			}
			if err := e.restoreNativeStep(ctx, step); err != nil {
				failures = append(failures, err)
			}
			if err := saveNativeJournal(n.path, n.journal); err != nil {
				failures = append(failures, err)
				break
			}
		}
		if len(failures) > 0 {
			return pending("native_restore_conflict", errors.Join(failures...))
		}
	}
	// A durable restored marker prevents setter replay; it is not a fresh
	// observation. Recheck every DNS scope before flushing/releasing anything.
	dnsBarrier := func() error {
		for _, step := range n.journal.Steps {
			if step.Change.Kind != "dns" {
				continue
			}
			value, err := e.readNativeStep(ctx, step)
			absent := step.Owner == "wireguard" && nativeValuesEqual(value, nativeValue{})
			if err != nil || step.Stage != "restored" || !nativeValuesEqual(value, step.Change.Before) && !absent {
				n.journal.CacheFlushPending = true
				saveErr := saveNativeJournal(n.path, n.journal)
				return pending("native_restore_conflict", errors.Join(err, saveErr, errors.New("restored DNS no longer matches original scope")))
			}
		}
		return nil
	}
	if err := dnsBarrier(); err != nil {
		return err
	}
	if n.journal.CacheFlushPending {
		if err := n.platform.FlushResolverCache(ctx, n.session); err != nil {
			return pending("native_cache_flush_failed", err)
		}
		n.journal.CacheFlushPending = false
		if err := saveNativeJournal(n.path, n.journal); err != nil {
			return pending("native_journal_write_failed", err)
		}
		if err := dnsBarrier(); err != nil {
			return err
		}
	}
	if n.journal.DNSReleasePending {
		changes := []nativeChange{}
		for _, step := range n.journal.Steps {
			if step.Owner == "wireguard" {
				changes = append(changes, step.Change)
			}
		}
		wg, ok := e.wireGuard.(*Executor)
		if !ok {
			return pending("native_wg_release_failed", errors.New("WG DNS owner unavailable"))
		}
		if err := wg.releaseNativeDNS(ctx, n.session, changes); err != nil {
			n.journal.CacheFlushPending = true
			_ = saveNativeJournal(n.path, n.journal)
			return pending("native_wg_release_failed", err)
		}
		n.journal.DNSReleasePending = false
		if err := saveNativeJournal(n.path, n.journal); err != nil {
			return pending("native_journal_write_failed", err)
		}
	}
	var failures []error
	for i := len(n.journal.Steps) - 1; i >= 0; i-- {
		step := &n.journal.Steps[i]
		if step.Change.Kind != "route" || step.Stage == "restored" {
			continue
		}
		if err := e.restoreNativeStep(ctx, step); err != nil {
			failures = append(failures, err)
		}
		if err := saveNativeJournal(n.path, n.journal); err != nil {
			failures = append(failures, err)
			break
		}
	}
	if len(failures) > 0 {
		return pending("native_restore_conflict", errors.Join(failures...))
	}
	if n.forward != nil {
		n.forward.close()
		n.forward = nil
	}
	if n.dns != nil {
		n.dns.close()
		n.dns = nil
	}
	if (n.base != nil || n.journal.Pending) && e.mihomo != nil {
		if err := e.mihomo.Disable(ctx); err != nil {
			return pending("native_engine_stop_failed", err)
		}
	}
	if n.journal.Process != nil {
		if err := e.recoverNativeOwnedProcess(ctx, *n.journal.Process); err != nil {
			return pending("native_process_recovery_failed", err)
		}
		n.journal.Process = nil
		if err := saveNativeJournal(n.path, n.journal); err != nil {
			return pending("native_journal_write_failed", err)
		}
	}
	n.status.SystemProxy = false
	n.status.TUN = false
	n.status.ObservedAt = time.Now().UTC()
	n.journal.Steps = nil
	n.journal.Pending = false
	n.journal.Quiesce = nil
	if err := saveNativeJournal(n.path, n.journal); err != nil {
		return pending("native_journal_write_failed", err)
	}
	if n.session != nil {
		n.session.Close()
		n.session = nil
	}
	if controller, ok := e.mihomo.(*MihomoController); ok {
		controller.mu.Lock()
		controller.nativeControl = nil
		controller.nativeControlRequired = false
		controller.mu.Unlock()
	}
	base := n.base
	n.base = nil
	defer func() { n.subscriptionState = nil }()
	n.guard.set(nil, false)
	n.status.State = interceptionInactive
	n.status.CleanupPending = false
	n.status.ReasonCode = ""
	// Cleanup is durable and the exact old process has been released. A normal
	// owned start must acquire its own lock rather than deadlock on this attempt.
	unlock()
	if restoreEngine && base != nil && base.EnforcementUntil.After(time.Now()) {
		base.NativePlan = nil
		if err := e.applyNativeEngineLocked(ctx, *base); err != nil {
			n.status.State = interceptionFailed
			n.status.ReasonCode = "native_proxy_restore_failed"
			return err
		}
	}
	return nil
}
func (e *CoordinatedExecutor) restoreNativeStep(ctx context.Context, step *nativeJournalStep) error {
	if step.Owner == "wireguard" {
		receipt, err := e.compareNativeStep(ctx, *step, true)
		if err == nil && receipt.ChangeID == step.Change.ID && (nativeValuesEqual(receipt.Current, step.Change.Before) || receipt.Outcome == "absent" && !receipt.Current.Present) {
			step.Stage = "restored"
			return nil
		}
		step.Stage = "unknown"
		return errors.Join(err, errors.New("WG DNS restoration unverified"))
	}
	current, err := e.readNativeStep(ctx, *step)
	if err != nil {
		step.Stage = "unknown"
		return err
	}
	if nativeValuesEqual(current, step.Change.Before) {
		step.Stage = "restored"
		return nil
	}
	if !nativeValuesEqual(current, step.Change.After) {
		step.Stage = "conflict"
		return errors.New("native setting changed externally")
	}
	receipt, err := e.compareNativeStep(ctx, *step, true)
	if err == nil && receipt.ChangeID == step.Change.ID && (receipt.Outcome == "applied" || receipt.Outcome == "not_applied") && nativeValuesEqual(receipt.Current, step.Change.Before) {
		step.Stage = "restored"
		return nil
	}
	step.Stage = "unknown"
	return errors.Join(err, errors.New("native restoration unverified"))
}
func (e *CoordinatedExecutor) RunInterceptionMonitor(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.mu.Lock()
			n := e.native
			if n != nil && n.session != nil && n.status.State == interceptionActive {
				check, cancel := context.WithTimeout(ctx, time.Second)
				_, err := n.guard.state(check)
				if err == nil {
					err = e.verifyNativeLocked(check)
				}
				if err == nil && n.presence != nil {
					state, _ := n.presence.Snapshot(time.Now())
					if state != "online" {
						err = errors.New("native UI offline")
					}
				}
				if err != nil {
					_ = e.restoreNativeLocked(check, true)
					if !n.status.CleanupPending {
						n.status.State = interceptionSuspended
						n.status.ReasonCode = "native_session_or_network_changed"
					}
				}
				cancel()
			}
			e.mu.Unlock()
		}
	}
}

func nativeBindingHash(identity string, c MihomoConfiguration) string {
	// Immutable enrollment/profile/credential identity, not rotating expirations.
	key := struct{ Identity, Profile, Bundle, Credential string }{Identity: identity, Profile: c.ProfileID, Bundle: c.BundleID}
	if c.Projection != nil {
		key.Credential = fmt.Sprint(c.Projection.CredentialEpoch, "/", c.Projection.ProcessEpoch, "/", c.Projection.RuntimeID, "/", projectionCredentialKey(c.Projection))
	}
	if c.DirectProjection != nil {
		key.Credential = c.DirectProjection.BundleID + "/" + c.DirectProjection.ProcessEpoch + "/" + c.DirectProjection.RuntimeID
	}
	raw, _ := json.Marshal(key)
	return fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
}
func (e *CoordinatedExecutor) AttachNativeHTTPClient(client *http.Client) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.native == nil {
		return nil
	}
	return e.native.guard.attach(client)
}
func (e *CoordinatedExecutor) verifyNativeListenerOwnership(ctx context.Context) error {
	n := e.native
	if n == nil || n.base == nil || !n.journal.Request.TUN {
		return nil
	}
	process, ok := e.mihomo.(interface{ ProcessStatus() MihomoProcessStatus })
	if !ok {
		return errors.New("native process identity unavailable")
	}
	before := process.ProcessStatus()
	if before.Ownership != "soha_owned" || before.State != "running" || before.PID < 1 || before.ProcessEpoch == "" {
		return errors.New("native process identity unavailable")
	}
	for _, network := range []string{"tcp", "udp"} {
		if err := n.platform.VerifyListenerOwner(ctx, n.session, network, netip.MustParseAddrPort("127.0.0.1:53"), uint32(before.PID)); err != nil {
			return err
		}
		if err := n.platform.VerifyListenerOwner(ctx, n.session, network, netip.MustParseAddrPort("[::1]:53"), uint32(os.Getpid())); err != nil {
			return err
		}
	}
	after := process.ProcessStatus()
	if before.PID != after.PID || before.ProcessEpoch != after.ProcessEpoch || !before.StartedAt.Equal(after.StartedAt) || after.State != "running" {
		return errors.New("native process incarnation changed")
	}
	return nil
}

func chooseNativeIPv6Pool(s nativeSnapshot, wg TunnelReadback, protection *MihomoProtection) (netip.Prefix, error) {
	for _, raw := range []string{"fdfe:dcba:9876::/48", "fdfe:dcba:9875::/48"} {
		p := netip.MustParsePrefix(raw)
		conflict := false
		for _, i := range s.Interfaces {
			for _, a := range i.Addresses {
				if p.Overlaps(a) {
					conflict = true
				}
			}
		}
		for _, r := range s.Routes {
			if r.Destination.IsValid() && r.Destination.Bits() > 0 && p.Overlaps(r.Destination) {
				conflict = true
			}
		}
		values := append([]string(nil), wg.Routes...)
		if protection != nil {
			values = append(values, protection.CIDRs...)
		}
		for _, v := range values {
			a, e := netip.ParsePrefix(v)
			if e != nil || p.Overlaps(a) {
				conflict = true
			}
		}
		if !conflict {
			return p, nil
		}
	}
	return netip.Prefix{}, errors.New("native IPv6 pool conflicts with existing network")
}

func nativeKernelSupported(version string) bool {
	for _, field := range strings.Fields(version) {
		if field == "v1.19.30" {
			return true
		}
	}
	return false
}
func (e *CoordinatedExecutor) previewInterception(ctx context.Context, connection net.Conn) InterceptionStatus {
	status := e.LocalProxyInterception()
	if status.State == interceptionActive || status.CleanupPending || !status.Capabilities.SystemProxy && !status.Capabilities.TUN {
		return status
	}
	peer, err := e.authenticateInterception(ctx, connection)
	if err == nil && (peer.session == nil || peer.pid == 0 || peer.owner != peer.session.Owner()) {
		if peer.session != nil {
			peer.session.Close()
		}
		return status
	}
	if err != nil {
		return status
	}
	defer peer.session.Close()
	e.mu.Lock()
	defer e.mu.Unlock()
	snapshot, err := e.native.platform.Snapshot(ctx, peer.session)
	if err == nil {
		err = peer.session.Validate(ctx, false)
	}
	if err != nil {
		return status
	}
	if status.Capabilities.TUN && !nativeHasGlobalIPv6(snapshot) {
		status.Capabilities.TUN = false
		status.Capabilities.ReasonCode = "native_ipv6_unavailable"
	}
	impact := InterceptionImpact{SystemProxyScope: "current_user", NetworkService: snapshot.PrimaryServiceName, DNS: status.Capabilities.TUN}
	if runtime.GOOS == "darwin" {
		impact.SystemProxyScope = "network_service"
	}
	for _, i := range snapshot.Interfaces {
		if i.Kind == "physical" {
			for _, a := range i.Addresses {
				if a.Addr().IsGlobalUnicast() {
					if a.Addr().Is4() {
						impact.IPv4 = true
					} else {
						impact.IPv6 = true
					}
				}
			}
		}
	}
	status.Impact = impact
	return status
}

func nativeSubscriptionBinding(c MihomoConfiguration, state *mihomoAppState) (string, error) {
	if state == nil || state.Cleared || state.ProfileID != c.ProfileID || state.ProfileRevision != c.ProfileRevision || !validSubscriptionURL(state.SubscriptionURL) || !validMihomoName(state.SelectedProxy) {
		return "", errors.New("subscription state identity mismatch")
	}
	raw, _ := json.Marshal(state)
	defer clear(raw)
	return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)), nil
}

// Selection is the sole mutable part of an active App-owned subscription.
// Source/profile stay fixed; a successful guarded controller selection and full
// readback precede advancing the trusted private state snapshot and journal hash.
func (e *CoordinatedExecutor) selectNativeAppLocked(ctx context.Context, node string) (MihomoAppStatus, error) {
	fail := func(err error) (MihomoAppStatus, error) { return e.currentMihomoAppStatus(), err }
	if !validMihomoName(node) || e.native == nil || e.native.session == nil || e.previousMihomo == nil || e.native.subscriptionState == nil {
		return fail(errors.New("native App subscription unavailable"))
	}
	if err := e.verifyNativeLocked(ctx); err != nil {
		e.recoverMihomo(ctx, "native_readback_mismatch")
		return fail(err)
	}
	selector, ok := e.mihomo.(interface {
		selectLocal(context.Context, MihomoConfiguration, string, string) error
	})
	if !ok {
		return fail(errors.New("guarded subscription selection unavailable"))
	}
	c := cloneMihomoConfiguration(e.previousMihomo.Configuration)
	if err := selector.selectLocal(ctx, c, c.SelectorGroup, node); err != nil {
		if errors.Is(err, errSelectionReadback) {
			e.recoverMihomo(ctx, "selection_readback_failed")
		}
		return fail(err)
	}
	if err := e.verifyNativeLocked(ctx); err != nil {
		e.recoverMihomo(ctx, "native_readback_mismatch")
		return fail(err)
	}
	n := e.native
	state := *n.subscriptionState
	state.SelectedProxy = node
	binding, err := nativeSubscriptionBinding(*n.base, &state)
	if err == nil {
		err = saveMihomoAppState(e.appStatePath, state)
	}
	if err != nil {
		e.recoverMihomo(ctx, "mihomo_state_save_failed")
		return fail(err)
	}
	trustedState := state
	n.subscriptionState = &trustedState
	e.previousMihomo.AppState = &state
	e.appStatus.SelectedProxy = node
	e.previousMihomo.AppStatus = cloneMihomoAppStatus(e.appStatus)
	n.journal.SubscriptionBinding = binding
	if err = saveNativeJournal(n.path, n.journal); err != nil {
		e.recoverMihomo(ctx, "native_journal_write_failed")
		return fail(err)
	}
	return e.currentMihomoAppStatus(), nil
}
