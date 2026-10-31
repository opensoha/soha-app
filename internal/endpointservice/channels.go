package endpointservice

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	ec "github.com/opensoha/soha-contracts/endpointcontrol"
)

const channelStateDescription = "OpenSoha endpoint native channel state"

type ChannelSystem interface {
	Reconcile(context.Context, ec.Controls) []ec.Channel
	Close() error
}
type ChannelControl interface {
	ChannelDesired(context.Context) (ec.Desired, error)
	ChannelReport(context.Context, ec.Receipt) error
}
type ChannelStatus struct {
	PolicyVersion    int64        `json:"policyVersion"`
	PolicyFresh      bool         `json:"policyFresh"`
	ControlReachable bool         `json:"controlReachable"`
	LastObservedAt   time.Time    `json:"lastObservedAt"`
	Channels         []ec.Channel `json:"channels"`
	Diagnostic       string       `json:"diagnostic"`
}
type channelFloor struct {
	Identity string      `json:"identity"`
	Revision int64       `json:"revision"`
	Controls ec.Controls `json:"controls"`
}
type ChannelManager struct {
	mu                                  sync.RWMutex
	control                             ChannelControl
	system                              ChannelSystem
	deviceID, runtimeID, path, identity string
	floor                               channelFloor
	status                              ChannelStatus
	validUntil                          time.Time
}

func NewChannelManager(config Config, control ChannelControl, system ChannelSystem) (*ChannelManager, error) {
	if control == nil || system == nil || !filepath.IsAbs(config.StateDirectory) {
		return nil, errors.New("native channel dependencies required")
	}
	id := channelIdentity(config)
	m := &ChannelManager{control: control, system: system, deviceID: config.DeviceID, runtimeID: config.RuntimeID, path: filepath.Join(config.StateDirectory, "channel-floor.json"), identity: id, floor: channelFloor{Identity: id}, status: ChannelStatus{Channels: []ec.Channel{}, Diagnostic: "waiting_for_control"}}
	raw, err := readFileBounded(m.path, 32768, true)
	if errors.Is(err, os.ErrNotExist) {
		if pending, ok := system.(interface{ PersistentRestrictions() bool }); ok && pending.PersistentRestrictions() {
			return nil, errors.New("native channel floor missing after policy acceptance; restore the protected state")
		}
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	plain, err := unprotectSecret(raw, channelStateDescription)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	if ec.Decode(plain, &m.floor) != nil || m.floor.Identity != id || m.floor.Revision < 1 {
		return nil, errors.New("native channel floor is invalid or belongs to another identity")
	}
	return m, nil
}
func (m *ChannelManager) Status() ChannelStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := m.status
	s.Channels = slices.Clone(s.Channels)
	return s
}
func (m *ChannelManager) accept(d ec.Desired, now time.Time) error {
	if !ec.ValidDesired(d, now) || d.DeviceID != m.deviceID || d.RuntimeID != m.runtimeID || d.PolicyVersion < m.floor.Revision || d.PolicyVersion == m.floor.Revision && d.Controls != m.floor.Controls {
		return errors.New("channel policy expired, regressed or changed without publication")
	}
	if !d.Configured {
		m.validUntil = d.ValidUntil
		return nil
	}
	floor := channelFloor{Identity: m.identity, Revision: d.PolicyVersion, Controls: d.Controls}
	if recorder, ok := m.system.(interface{ RecordPolicyAcceptance() error }); ok {
		if err := recorder.RecordPolicyAcceptance(); err != nil {
			return err
		}
	}
	raw, _ := json.Marshal(floor)
	if err := saveProtectedState(m.path, raw, channelStateDescription); err != nil {
		return err
	}
	m.floor = floor
	m.validUntil = d.ValidUntil
	return nil
}
func (m *ChannelManager) Run(ctx context.Context) (retErr error) {
	defer func() { retErr = errors.Join(retErr, m.system.Close()) }()
	next := time.Time{}
	for ctx.Err() == nil {
		var desired *ec.Desired
		now := time.Now().UTC()
		if !now.Before(next) {
			request, cancel := context.WithTimeout(ctx, 5*time.Second)
			d, err := m.control.ChannelDesired(request)
			cancel()
			m.mu.Lock()
			m.status.ControlReachable = err == nil
			if err == nil {
				err = m.accept(d, time.Now().UTC())
				if err == nil {
					desired = &d
				}
			}
			if err != nil {
				m.status.Diagnostic = "control_or_policy_unavailable"
			} else {
				m.status.Diagnostic = "native_scope_only"
			}
			m.mu.Unlock()
			next = now.Add(20 * time.Second)
		}
		m.mu.RLock()
		controls := m.floor.Controls
		revision := m.floor.Revision
		m.mu.RUnlock()
		run, cancel := context.WithTimeout(ctx, 5*time.Second)
		channels := unconfiguredChannels()
		if revision > 0 {
			channels = m.system.Reconcile(run, controls)
		}
		cancel()
		m.mu.Lock()
		m.status.PolicyVersion = revision
		m.status.PolicyFresh = time.Now().Before(m.validUntil)
		m.status.LastObservedAt = time.Now().UTC()
		m.status.Channels = slices.Clone(channels)
		m.mu.Unlock()
		if desired != nil {
			report := ec.Receipt{SchemaVersion: ec.Version, DeviceID: m.deviceID, RuntimeID: m.runtimeID, CredentialID: desired.CredentialID, PolicyVersion: revision, Challenge: desired.Challenge, ObservedAt: time.Now().UTC(), Channels: channels}
			send, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := m.control.ChannelReport(send, report)
			cancel()
			if err != nil {
				m.mu.Lock()
				m.status.ControlReachable = false
				m.status.Diagnostic = "receipt_unconfirmed"
				m.mu.Unlock()
			}
		}
		if !waitFor(ctx, 2*time.Second) {
			return nil
		}
	}
	return nil
}
func (client *ControlClient) ChannelDesired(ctx context.Context) (ec.Desired, error) {
	var result struct {
		Data ec.Desired `json:"data"`
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, client.runtimeURL("channel-controls"), nil)
	if err != nil {
		return result.Data, err
	}
	res, err := client.http.Do(req)
	if err != nil {
		return result.Data, err
	}
	raw, err := readRuntimeResponse(res, http.StatusOK)
	if err != nil {
		return result.Data, err
	}
	if ec.Decode(raw, &result) != nil || !ec.ValidDesired(result.Data, time.Now().UTC()) || result.Data.RuntimeID != client.runtimeID {
		return result.Data, errors.New("invalid native channel desired state")
	}
	return result.Data, nil
}
func (client *ControlClient) ChannelReport(ctx context.Context, in ec.Receipt) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	_, err = client.post(ctx, client.runtimeURL("channel-controls/receipt"), raw, "", http.StatusNoContent)
	return err
}

func unconfiguredChannels() []ec.Channel {
	return []ec.Channel{{Name: "usb", Scope: "current_usb_volumes", State: "unconfigured", ReasonCode: "not_published"}, {Name: "print", Scope: "local_new_print_jobs", State: "unconfigured", ReasonCode: "not_published"}, {Name: "clipboard", Scope: "enrolled_console_win32", State: "unconfigured", ReasonCode: "not_published"}}
}

func (m *ChannelManager) Healthy(now time.Time) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.floor.Revision == 0 {
		return true
	} // Unconfigured is not a DLP protection claim.
	if !m.status.PolicyFresh || !m.status.ControlReachable || now.Sub(m.status.LastObservedAt) > 10*time.Second {
		return false
	}
	for _, c := range m.status.Channels {
		if c.State != "controlled" && c.State != "not_present" && c.State != "off" {
			return false
		}
	}
	return len(m.status.Channels) == 3
}

func channelIdentity(config Config) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(config.ControlURL+"\x00"+config.DeviceID+"\x00"+config.RuntimeID+"\x00"+config.AllowedUserSID)))
}
