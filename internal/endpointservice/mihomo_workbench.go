package endpointservice

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"time"

	api "github.com/opensoha/soha-contracts/gen/go/sohaapi"
)

var errSelectionReadback = errors.New("selection outcome unavailable")

type ProxyAction struct {
	Kind           string `json:"kind"`
	GroupID        string `json:"groupId,omitempty"`
	NodeID         string `json:"nodeId,omitempty"`
	ProbeProfileID string `json:"probeProfileId,omitempty"`
	ConnectionID   string `json:"connectionId,omitempty"`
	ProcessEpoch   string `json:"processEpoch,omitempty"`
}
type ProxyCapability struct {
	Name       string `json:"name"`
	State      string `json:"state"`
	ReasonCode string `json:"reasonCode,omitempty"`
}
type ProxyNode struct {
	NodeID string `json:"nodeId"`
	Label  string `json:"label"`
}
type ProxyTraffic struct {
	ProcessEpoch           string    `json:"processEpoch"`
	ObservedAt             time.Time `json:"observedAt"`
	UploadTotal            int64     `json:"uploadTotal"`
	DownloadTotal          int64     `json:"downloadTotal"`
	UploadBytesPerSecond   *float64  `json:"uploadBytesPerSecond"`
	DownloadBytesPerSecond *float64  `json:"downloadBytesPerSecond"`
	State                  string    `json:"state"`
}
type ProxyConnection struct {
	ConnectionID string     `json:"connectionId"`
	Destination  string     `json:"destination,omitempty"`
	Network      string     `json:"network,omitempty"`
	Upload       int64      `json:"upload"`
	Download     int64      `json:"download"`
	StartedAt    *time.Time `json:"startedAt,omitempty"`
}
type ProxyConnections struct {
	ProcessEpoch  string            `json:"processEpoch"`
	ObservedAt    time.Time         `json:"observedAt"`
	TotalActive   int               `json:"totalActive"`
	ReturnedCount int               `json:"returnedCount"`
	Truncated     bool              `json:"truncated"`
	Items         []ProxyConnection `json:"items"`
}
type ProxyLog struct {
	Sequence   int64     `json:"sequence"`
	OccurredAt time.Time `json:"occurredAt"`
	Level      string    `json:"level"`
	Message    string    `json:"message"`
}
type ProxyDiagnostic struct {
	Code    string `json:"code"`
	State   string `json:"state"`
	Message string `json:"message"`
}
type ProxyDNS struct {
	Name      string    `json:"name"`
	Addresses []string  `json:"addresses"`
	ExpiresAt time.Time `json:"expiresAt"`
}
type ProxyProbe struct {
	NodeID              string  `json:"nodeId"`
	LatencyMilliseconds float64 `json:"latencyMilliseconds"`
}
type ProxyWorkbench struct {
	ProbeProfiles    []string                `json:"probeProfiles"`
	Engine           string                  `json:"engine"`
	Mode             string                  `json:"mode"`
	DeliveryMode     string                  `json:"deliveryMode"`
	ProfileID        string                  `json:"profileId"`
	BundleID         string                  `json:"bundleId"`
	Revision         int64                   `json:"revision"`
	OrgRevision      int64                   `json:"orgRevision"`
	PersonalRevision int64                   `json:"personalRevision"`
	State            string                  `json:"state"`
	ReasonCode       string                  `json:"reasonCode,omitempty"`
	Process          MihomoProcessStatus     `json:"process"`
	Capabilities     []ProxyCapability       `json:"capabilities"`
	Nodes            []ProxyNode             `json:"nodes"`
	Groups           []api.NetworkProxyGroup `json:"groups"`
	Rules            api.NetworkProxyRules   `json:"rules"`
	MaskedRules      []api.NetworkProxyRule  `json:"maskedRules"`
	Traffic          ProxyTraffic            `json:"traffic"`
	Connections      ProxyConnections        `json:"connections"`
	Logs             []ProxyLog              `json:"logs"`
	Diagnostics      []ProxyDiagnostic       `json:"diagnostics"`
	DNS              []ProxyDNS              `json:"dns"`
	Probe            *ProxyProbe             `json:"probe,omitempty"`
}
type localProxyObservation struct {
	nativeEpoch                  string
	nativeUpload, nativeDownload int64
	traffic                      ProxyTraffic
	epoch                        string
	logs                         []ProxyLog
	sequence                     int64
}

func (e *CoordinatedExecutor) proxyConfiguration() (MihomoConfiguration, error) {
	if e.proxyDesired == nil {
		return MihomoConfiguration{}, errors.New("proxy is not configured")
	}
	return cloneMihomoConfiguration(*e.proxyDesired), nil
}
func (e *CoordinatedExecutor) reapplyProxy(ctx context.Context, c MihomoConfiguration) error {
	if e.native != nil && e.native.session != nil {
		dnsMode, pool := e.native.base.DNSMode, e.native.base.FakeIPRange
		if err := e.restoreNativeLocked(ctx, false); err != nil {
			return err
		}
		c.NativePlan = nil
		c.DNSMode = dnsMode
		c.FakeIPRange = pool
	}
	if !c.EnforcementUntil.After(time.Now()) {
		return errors.New("proxy authorization expired")
	}
	if c.Mode == "app_subscription" {
		state, err := loadMihomoAppState(e.appStatePath)
		if err != nil || state.Cleared {
			return errors.New("app subscription unavailable")
		}
		_, err = e.applyMihomoAppState(ctx, c, state)
		return err
	}
	if err := e.quiesceMihomo(ctx); err != nil {
		return err
	}
	if err := e.bindMihomoVPN(ctx, &c); err != nil {
		return err
	}
	if err := e.composePersonal(&c); err != nil {
		return err
	}
	readback, err := e.mihomo.Apply(ctx, c)
	if err != nil {
		e.recoverMihomo(ctx, "proxy_apply_failed")
		return errors.New("proxy apply failed")
	}
	if readback.ProfileID != c.ProfileID || readback.ProtectionHash != mihomoProtectionHash(c) {
		e.recoverMihomo(ctx, "proxy_readback_failed")
		return errors.New("proxy readback failed")
	}
	e.rememberManagedMihomo(c)
	e.proxyDesired = &c
	return nil
}
func (e *CoordinatedExecutor) Proxy(ctx context.Context, action *ProxyAction, input *api.NetworkProxyRulesInput) (ProxyWorkbench, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return ProxyWorkbench{}, err
	}
	c, configurationErr := e.proxyConfiguration()
	controller, ok := e.mihomo.(*MihomoController)
	if !ok {
		return ProxyWorkbench{}, errors.New("mihomo adapter unavailable")
	}
	var operationErr error
	var probe *ProxyProbe
	if input != nil {
		if configurationErr != nil {
			return e.workbench(ctx, controller, c, nil), configurationErr
		}
		if err := e.storePersonal(*input, c); err != nil {
			return e.workbench(ctx, controller, c, nil), err
		}
		if e.mihomoActive {
			operationErr = e.reapplyProxy(ctx, c)
		} else {
			operationErr = e.composePersonal(&c)
			e.proxyDesired = &c
		}
	} else if action != nil {
		if !validProxyAction(*action) {
			return e.workbench(ctx, controller, c, nil), errors.New("invalid local proxy action")
		}
		switch action.Kind {
		case "start", "stop", "restart":
			if action.Kind == "restart" {
				operationErr = controller.setProcessRunning(ctx, false)
			}
			if operationErr == nil {
				operationErr = controller.setProcessRunning(ctx, action.Kind != "stop")
			}
			if action.Kind == "stop" && controller.process != nil {
				e.mihomoActive = false
				e.previousMihomo = nil
				e.appStatus = MihomoAppStatus{}
			} else if operationErr == nil && configurationErr == nil {
				operationErr = e.reapplyProxy(ctx, c)
			}
		case "refresh_status":
		case "repair":
			if configurationErr != nil {
				operationErr = configurationErr
			} else {
				operationErr = e.reapplyProxy(ctx, c)
			}
		case "refresh_subscription":
			// Refreshing provider material is distinct from reading observations.
			if configurationErr != nil {
				operationErr = configurationErr
			} else {
				operationErr = e.reapplyProxy(ctx, c)
			}
		case "select":
			if c.Mode == "app_subscription" && e.native != nil && e.native.session != nil {
				if action.GroupID != c.SelectorGroup {
					operationErr = errors.New("node is outside authorized group")
				} else {
					_, operationErr = e.selectNativeAppLocked(ctx, action.NodeID)
				}
				break
			}
			operationErr = controller.selectLocal(ctx, c, action.GroupID, action.NodeID)
			if errors.Is(operationErr, errSelectionReadback) {
				e.recoverMihomo(ctx, "selection_readback_failed")
			}
			if operationErr == nil {
				if c.Projection != nil || c.DirectProjection != nil {
					for i, g := range configurationGroups(c) {
						if g.GroupID == action.GroupID {
							if c.Projection != nil {
								c.Projection.Groups[i].SelectedNodeID = action.NodeID
							} else {
								c.DirectProjection.Groups[i].SelectedNodeID = action.NodeID
							}
						}
					}
				}
				if action.GroupID == c.SelectorGroup {
					c.SelectedProxy = action.NodeID
					if e.previousMihomo != nil {
						e.previousMihomo.Configuration.SelectedProxy = action.NodeID
					}
					if e.previousMihomo != nil && e.previousMihomo.AppState != nil {
						state := *e.previousMihomo.AppState
						state.SelectedProxy = action.NodeID
						operationErr = saveMihomoAppState(e.appStatePath, state)
						if operationErr == nil {
							e.previousMihomo.AppState = &state
							e.appStatus.SelectedProxy = action.NodeID
						}
					}
				}
				e.proxyDesired = &c
				if e.previousMihomo != nil {
					if e.proxyNarrowed {
						if action.GroupID == c.SelectorGroup {
							e.previousMihomo.Configuration.SelectedProxy = c.SelectedProxy
						}
					} else {
						e.previousMihomo.Configuration = cloneMihomoConfiguration(c)
					}
				}
			}
		case "probe":
			probe, operationErr = controller.probeLocal(ctx, c, action.NodeID, action.ProbeProfileID)
		case "close":
			operationErr = controller.closeLocal(ctx, action.ConnectionID, action.ProcessEpoch)
		}
		controller.recordLocal(action.Kind, operationErr == nil)
	}
	view := e.workbench(ctx, controller, c, probe)
	if operationErr != nil {
		view.ReasonCode = "local_operation_failed"
	}
	return view, operationErr
}
func validProxyAction(a ProxyAction) bool {
	if len(a.GroupID) > 128 || len(a.NodeID) > 128 || len(a.ConnectionID) > 128 || len(a.ProcessEpoch) > 128 || len(a.ProbeProfileID) > 128 {
		return false
	}
	switch a.Kind {
	case "select":
		return validMihomoName(a.GroupID) && validMihomoName(a.NodeID) && a.ConnectionID == "" && a.ProcessEpoch == "" && a.ProbeProfileID == ""
	case "probe":
		return validMihomoName(a.NodeID) && identifierPattern.MatchString(a.ProbeProfileID) && a.GroupID == "" && a.ConnectionID == "" && a.ProcessEpoch == ""
	case "close":
		return identifierPattern.MatchString(a.ConnectionID) && identifierPattern.MatchString(a.ProcessEpoch) && a.GroupID == "" && a.NodeID == "" && a.ProbeProfileID == ""
	case "start", "stop", "restart", "refresh_subscription", "refresh_status", "repair":
		return a.GroupID == "" && a.NodeID == "" && a.ConnectionID == "" && a.ProcessEpoch == "" && a.ProbeProfileID == ""
	}
	return false
}
func (c *MihomoController) recordLocal(kind string, success bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.observer.sequence++
	level, message := "info", "Local proxy operation completed"
	if !success {
		level, message = "warning", "Local proxy operation failed"
	}
	c.observer.logs = append(c.observer.logs, ProxyLog{Sequence: c.observer.sequence, OccurredAt: time.Now().UTC(), Level: level, Message: message + ": " + kind})
	if len(c.observer.logs) > 100 {
		c.observer.logs = c.observer.logs[len(c.observer.logs)-100:]
	}
}
func (e *CoordinatedExecutor) workbench(ctx context.Context, controller *MihomoController, c MihomoConfiguration, probe *ProxyProbe) ProxyWorkbench {
	view := ProxyWorkbench{Engine: "mihomo", Mode: c.Mode, DeliveryMode: c.DeliveryMode, ProfileID: c.ProfileID, BundleID: c.BundleID, OrgRevision: c.OrgRevision, State: "stopped", Nodes: []ProxyNode{}, Groups: []api.NetworkProxyGroup{}, MaskedRules: []api.NetworkProxyRule{}, DNS: []ProxyDNS{}, Diagnostics: []ProxyDiagnostic{}, Probe: probe}
	view.Rules = api.NetworkProxyRules{Rules: []api.NetworkProxyRule{}, EffectiveRules: []api.NetworkProxyRule{}, Conflicts: []api.NetworkProxyRuleConflict{}}
	view.ProbeProfiles = []string{}
	for id := range controller.probeProfiles {
		view.ProbeProfiles = append(view.ProbeProfiles, id)
	}
	sort.Strings(view.ProbeProfiles)
	if e.proxyReceiptPending {
		view.Diagnostics = append(view.Diagnostics, ProxyDiagnostic{Code: "projection_receipt", State: "pending", Message: "Local stop receipt is pending; the next configuration poll will retry"})
	}
	if e.proxyNarrowed && e.mihomoActive {
		view.Diagnostics = append(view.Diagnostics, ProxyDiagnostic{Code: "native_rule_snapshot", State: "pending", Message: "The native guarded rule snapshot is retained; revoked nodes are denied by the local gate. Restart applies the effective rules."})
	}
	view.Process = controller.ProcessStatus()
	if c.ProfileID == "" {
		view.State = "unconfigured"
		view.ReasonCode = "configuration_unavailable"
	}
	if e.mihomoActive {
		view.State = "running"
	}
	if c.Projection != nil {
		view.Revision = c.Projection.Revision
		for _, n := range c.Projection.Nodes {
			view.Nodes = append(view.Nodes, ProxyNode{NodeID: n.NodeID, Label: n.Label})
		}
		view.Groups = append(view.Groups, c.Projection.Groups...)
	} else if c.DirectProjection != nil {
		view.Revision = c.DirectProjection.Revision
		view.Groups = append(view.Groups, c.DirectProjection.Groups...)
		for _, id := range configurationNodeIDs(c) {
			view.Nodes = append(view.Nodes, ProxyNode{NodeID: id, Label: id})
		}

	} else if e.previousMihomo != nil && e.previousMihomo.AppState != nil {
		for _, name := range e.appStatus.Proxies {
			view.Nodes = append(view.Nodes, ProxyNode{NodeID: name, Label: name})
		}
		view.Groups = append(view.Groups, api.NetworkProxyGroup{GroupID: c.SelectorGroup, Label: c.SelectorGroup, NodeIDs: slices.Clone(e.appStatus.Proxies), SelectedNodeID: e.appStatus.SelectedProxy, Type: "select"})
	}
	if err := e.loadPersonal(); err != nil {
		view.State = "unavailable"
		view.ReasonCode = "personal_rules_unavailable"
		view.Diagnostics = append(view.Diagnostics, ProxyDiagnostic{Code: "personal_rules", State: "unavailable", Message: "Personal rule storage requires repair"})
	}
	if rules, err := e.composeRules(c); err == nil {
		view.Rules = rules
		view.PersonalRevision = rules.PersonalRevision
		effective := map[string]bool{}
		masked := map[string]bool{}
		for _, conflict := range rules.Conflicts {
			masked[conflict.RuleID] = true
		}
		for _, r := range rules.EffectiveRules {
			effective[r.RuleID] = true
		}
		for _, r := range rules.Rules {
			if r.Enabled && (!effective[r.RuleID] || masked[r.RuleID]) {
				view.MaskedRules = append(view.MaskedRules, r)
			}
		}
	}
	for _, d := range c.DNSRecords {
		view.DNS = append(view.DNS, ProxyDNS{Name: d.Hostname, Addresses: slices.Clone(d.Addresses), ExpiresAt: d.ExpiresAt})
	}
	if len(view.Nodes) > 0 {
		hasMain := false
		for _, g := range view.Groups {
			if g.GroupID == c.SelectorGroup {
				hasMain = true
			}
		}
		if !hasMain {
			ids := []string{}
			for _, n := range view.Nodes {
				ids = append(ids, n.NodeID)
			}
			view.Groups = append(view.Groups, api.NetworkProxyGroup{GroupID: c.SelectorGroup, Label: c.SelectorGroup, NodeIDs: ids, SelectedNodeID: c.SelectedProxy, Type: "select"})
		}
	}
	for i := range view.Groups {
		if view.Groups[i].GroupID == c.SelectorGroup && c.SelectedProxy != "" {
			view.Groups[i].SelectedNodeID = c.SelectedProxy
		}
	}
	for _, name := range []string{"process_control", "select", "probe", "traffic", "connections", "close_connection", "logs", "diagnostics", "dns", "rules", "subscription_refresh"} {
		state, reason := "available", ""
		if !e.mihomoActive && (name == "select" || name == "probe" || name == "traffic" || name == "connections" || name == "close_connection") {
			state, reason = "unavailable", "proxy_not_active"
		}
		if name == "process_control" && view.Process.Ownership == "external" {
			state, reason = "unsupported", "external_process_control"
		}
		if name == "close_connection" && view.Process.Ownership == "external" {
			state, reason = "unsupported", "engine_epoch_unavailable"
		}
		if name == "probe" && len(controller.probeProfiles) == 0 {
			state, reason = "unavailable", "probe_profile_not_installed"
		}
		view.Capabilities = append(view.Capabilities, ProxyCapability{Name: name, State: state, ReasonCode: reason})
	}
	view.Capabilities = append(view.Capabilities, ProxyCapability{Name: "sing-box", State: "unsupported", ReasonCode: "adapter_not_installed"}, ProxyCapability{Name: "v2ray", State: "unsupported", ReasonCode: "adapter_not_installed"})
	if controller.egress != nil && controller.egress.udpSourceUnsupported {
		view.Diagnostics = append(view.Diagnostics, ProxyDiagnostic{Code: "udp_source_tls_options", State: "unsupported", Message: "Some SOCKS5 source options require the native TCP path; UDP is unsupported for those nodes"})
	}
	udpState, udpReason := "unavailable", "guarded_transport_inactive"
	if e.mihomoActive && view.Process.Ownership == "soha_owned" && view.Process.State == "running" && controller.egress != nil && controller.egress.socksReady.Load() && controller.egress.packetUntil().After(time.Now()) {
		udpState, udpReason = "available", "guarded_transport"
	}
	view.Capabilities = append(view.Capabilities, ProxyCapability{Name: "udp", State: udpState, ReasonCode: udpReason})
	view.Diagnostics = append(view.Diagnostics, ProxyDiagnostic{Code: "guarded_udp", State: udpState, Message: "UDP uses the guarded transport; individual upstream nodes may support TCP only"})
	traffic, connections, err := controller.observeLocal(ctx)
	view.Traffic, view.Connections = traffic, connections
	if errors.Is(err, errBusinessCounterEpoch) || errors.Is(err, errBusinessCounterSample) {
		code := "traffic_sample_unsettled"
		if errors.Is(err, errBusinessCounterEpoch) {
			code = "business_counter_epoch_unavailable"
		}
		for i := range view.Capabilities {
			if view.Capabilities[i].Name == "traffic" {
				view.Capabilities[i].State = "unavailable"
				view.Capabilities[i].ReasonCode = code
			}
		}
		view.Diagnostics = append(view.Diagnostics, ProxyDiagnostic{Code: code, State: view.Traffic.State, Message: "Business traffic counters are unavailable or unsettled; rates are not inferred"})
	} else if err != nil {
		if e.mihomoActive {
			view.State = "unavailable"
			view.ReasonCode = "controller_unavailable"
		}
		for i, capability := range view.Capabilities {
			if capability.Name == "traffic" || capability.Name == "connections" || capability.Name == "select" || capability.Name == "probe" || capability.Name == "close_connection" || capability.Name == "udp" {
				if capability.State != "unsupported" {
					view.Capabilities[i].State = "unavailable"
					view.Capabilities[i].ReasonCode = "controller_unavailable"
				}
			}
		}
		view.Traffic.State = "unavailable"
		for i := range view.Diagnostics {
			if view.Diagnostics[i].Code == "guarded_udp" {
				view.Diagnostics[i].State = "unavailable"
			}
		}
		view.Diagnostics = append(view.Diagnostics, ProxyDiagnostic{Code: "controller_observation", State: "unavailable", Message: "Fresh controller observation is unavailable"})
	}
	controller.mu.Lock()
	view.Logs = append([]ProxyLog{}, controller.observer.logs...)
	controller.mu.Unlock()
	if !c.EnforcementUntil.After(time.Now()) && c.ProfileID != "" {
		view.State = "unavailable"
		view.ReasonCode = "authorization_expired"
	}
	return view
}
func (c *MihomoController) selectLocal(ctx context.Context, configuration MihomoConfiguration, groupID, nodeID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.applied.Mode == "" || !configuration.EnforcementUntil.After(time.Now()) {
		return errors.New("proxy is not active")
	}
	allowed := false
	if configuration.Projection != nil || configuration.DirectProjection != nil {
		for _, g := range configurationGroups(configuration) {
			if g.GroupID == groupID && slices.Contains(g.NodeIDs, nodeID) {
				allowed = true
			}
		}
		if groupID == configuration.SelectorGroup {
			for _, id := range configurationNodeIDs(configuration) {
				if id == nodeID {
					allowed = true
				}
			}
		}
	} else {
		group, err := c.proxyGroup(ctx, configuration)
		allowed = err == nil && groupID == configuration.SelectorGroup && slices.Contains(group.All, nodeID)
	}
	if !allowed {
		return errors.New("node is outside authorized group")
	}
	raw, _ := json.Marshal(map[string]string{"name": nodeID})
	path := "/proxies/" + url.PathEscape(groupID)
	if err := c.request(ctx, http.MethodPut, path, raw, http.StatusNoContent, nil); err != nil {
		return errSelectionReadback
	}
	var actual struct {
		Now string `json:"now"`
	}
	if c.request(ctx, http.MethodGet, path, nil, http.StatusOK, &actual) != nil || actual.Now != nodeID {
		return errSelectionReadback
	}
	if groupID == configuration.SelectorGroup {
		c.applied.SelectedProxy = nodeID
	}
	return nil
}
func (c *MihomoController) probeLocal(ctx context.Context, configuration MihomoConfiguration, nodeID, profileID string) (*ProxyProbe, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	probeURL, ok := c.probeProfiles[profileID]
	if !ok || c.applied.Mode == "" || !configuration.EnforcementUntil.After(time.Now()) {
		return nil, errors.New("approved probe unavailable")
	}
	allowed := false
	if configuration.Projection != nil {
		for _, n := range configuration.Projection.Nodes {
			if n.NodeID == nodeID {
				allowed = true
			}
		}
	} else {
		group, err := c.proxyGroup(ctx, configuration)
		allowed = err == nil && slices.Contains(group.All, nodeID)
	}
	if !allowed {
		return nil, errors.New("probe node unauthorized")
	}
	var result struct {
		Delay float64 `json:"delay"`
	}
	path := "/proxies/" + url.PathEscape(nodeID) + "/delay?url=" + url.QueryEscape(probeURL) + "&timeout=" + strconv.Itoa(3000)
	if c.request(ctx, http.MethodGet, path, nil, http.StatusOK, &result) != nil || result.Delay < 0 || result.Delay > 3000 {
		return nil, errors.New("approved probe failed")
	}
	return &ProxyProbe{NodeID: nodeID, LatencyMilliseconds: result.Delay}, nil
}
func (c *MihomoController) localEpoch() string {
	if c.process != nil {
		c.process.mu.Lock()
		defer c.process.mu.Unlock()
		return c.process.status.ProcessEpoch
	}
	return c.observer.epoch
}
func (c *MihomoController) observeLocal(ctx context.Context) (ProxyTraffic, ProxyConnections, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.observeLocalLocked(ctx)
}
func (c *MihomoController) observeLocalLocked(ctx context.Context) (ProxyTraffic, ProxyConnections, error) {
	now := time.Now().UTC()
	epoch := c.localEpoch()
	ownerActive := true
	if c.process != nil {
		c.process.mu.Lock()
		ownerActive = c.process.cmd != nil && c.process.status.State == "running" && !c.process.stopped
		c.process.mu.Unlock()
	}
	empty := ProxyConnections{ProcessEpoch: epoch, ObservedAt: now, Items: []ProxyConnection{}}
	if c.applied.Mode == "" || !ownerActive {
		return ProxyTraffic{ProcessEpoch: epoch, ObservedAt: now, State: "unavailable"}, empty, errors.New("proxy inactive")
	}
	raw, sampleErr := c.readBusinessSnapshotLocked(ctx)
	counterError := errors.Is(sampleErr, errBusinessCounterEpoch) || errors.Is(sampleErr, errBusinessCounterSample)
	if sampleErr != nil && !counterError {
		return ProxyTraffic{ProcessEpoch: epoch, State: "unavailable"}, empty, sampleErr
	}
	previous := c.observer.traffic
	traffic := ProxyTraffic{ProcessEpoch: epoch, ObservedAt: now, UploadTotal: raw.UploadTotal, DownloadTotal: raw.DownloadTotal, State: "unknown"}
	if sampleErr != nil {
		traffic = ProxyTraffic{ProcessEpoch: epoch, State: "unavailable"}
		if previous.ProcessEpoch == epoch && !previous.ObservedAt.IsZero() && !errors.Is(sampleErr, errBusinessCounterEpoch) {
			traffic = previous
			traffic.State = "unknown"
			traffic.UploadBytesPerSecond = nil
			traffic.DownloadBytesPerSecond = nil
		}
	} else {
		delta := now.Sub(previous.ObservedAt).Seconds()
		if previous.ProcessEpoch == epoch && delta > 0 && delta <= 60 && raw.UploadTotal >= previous.UploadTotal && raw.DownloadTotal >= previous.DownloadTotal {
			up, down := float64(raw.UploadTotal-previous.UploadTotal)/delta, float64(raw.DownloadTotal-previous.DownloadTotal)/delta
			traffic.UploadBytesPerSecond, traffic.DownloadBytesPerSecond = &up, &down
			traffic.State = "fresh"
		} else if !previous.ObservedAt.IsZero() && delta > 60 {
			traffic.State = "gap"
		}
		c.observer.traffic = traffic
	}
	empty.ProcessEpoch = epoch
	empty.TotalActive = len(raw.Connections)
	empty.Truncated = len(raw.Connections) > 200
	for _, item := range raw.Connections[:min(200, len(raw.Connections))] {
		if !identifierPattern.MatchString(item.ID) || item.Upload < 0 || item.Download < 0 {
			continue
		}
		destination := item.Metadata.Host
		if !validEndpointHost(destination) {
			destination = item.Metadata.DestinationIP
		}
		if !validEndpointHost(destination) {
			destination = ""
		}
		network := item.Metadata.Network
		if network != "tcp" && network != "udp" {
			network = ""
		}
		value := ProxyConnection{ConnectionID: item.ID, Destination: destination, Network: network, Upload: item.Upload, Download: item.Download}
		if !item.Start.IsZero() {
			started := item.Start
			value.StartedAt = &started
		}
		empty.Items = append(empty.Items, value)
	}
	empty.ReturnedCount = len(empty.Items)
	empty.Truncated = empty.TotalActive > empty.ReturnedCount
	return traffic, empty, sampleErr
}
func (c *MihomoController) closeLocal(ctx context.Context, id, epoch string) error {
	if c.process == nil {
		return ErrMihomoProcessUnsupported
	}
	_, snapshot, err := c.observeLocal(ctx)
	if err != nil && !errors.Is(err, errBusinessCounterSample) {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.process.mu.Lock()
	active := c.process.cmd != nil && c.process.status.State == "running" && !c.process.stopped
	c.process.mu.Unlock()
	if !active || epoch == "" || epoch != c.localEpoch() || snapshot.ProcessEpoch != epoch {
		return errors.New("stale connection epoch")
	}
	found := false
	for _, item := range snapshot.Items {
		if item.ConnectionID == id {
			found = true
		}
	}
	if !found {
		return errors.New("connection absent from current bounded snapshot")
	}
	if err := c.request(ctx, http.MethodDelete, "/connections/"+url.PathEscape(id), nil, http.StatusNoContent, nil); err != nil {
		return errors.New("connection close failed")
	}
	var actual struct {
		Connections []struct {
			ID string `json:"id"`
		} `json:"connections"`
	}
	if c.request(ctx, http.MethodGet, "/connections", nil, http.StatusOK, &actual) != nil {
		return errors.New("connection close readback unavailable")
	}
	for _, item := range actual.Connections {
		if item.ID == id {
			return errors.New("connection still present")
		}
	}
	return nil
}
