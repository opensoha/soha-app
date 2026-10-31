package endpointservice

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
)

const configurationFloorDescription = "OpenSoha endpoint configuration floor"

var configurationDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type configurationFloor struct {
	PendingCleanup       *pendingVPNCleanup `json:"pendingCleanup,omitempty"`
	Version              int                `json:"version"`
	Identity             string             `json:"identity"`
	ConfigurationVersion int                `json:"configurationVersion"`
	PolicyVersion        int                `json:"policyVersion"`
	Digest               string             `json:"digest"`
}

type pendingVPNCleanup struct {
	SessionID string   `json:"sessionId"`
	LeaseIDs  []string `json:"leaseIds"`
	Reason    string   `json:"reason"`
}

func validConfigurationFloor(floor configurationFloor, identity string) bool {
	if floor.Version != 1 || floor.Identity != identity {
		return false
	}
	if pending := floor.PendingCleanup; pending != nil {
		if !identifierPattern.MatchString(pending.SessionID) || !identifierPattern.MatchString(pending.Reason) || len(pending.LeaseIDs) == 0 || len(pending.LeaseIDs) > 768 {
			return false
		}
		for _, id := range pending.LeaseIDs {
			if !identifierPattern.MatchString(id) {
				return false
			}
		}
	}
	// A failed first connect may need revocation before any configuration was
	// received. Its completed cleanup must not fabricate a content hash either.
	if floor.ConfigurationVersion == 0 && floor.PolicyVersion == 0 && floor.Digest == "" {
		return true
	}
	return floor.ConfigurationVersion > 0 && floor.PolicyVersion > 0 && configurationDigestPattern.MatchString(floor.Digest)
}

func (manager *Manager) floorIdentity() string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(manager.options.ControlURL+"\x00"+manager.options.RuntimeID+"\x00"+manager.options.DeviceID)))
}

func (manager *Manager) restoreConfigurationFloor() error {
	path := manager.options.ConfigurationStatePath
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) || manager.options.ControlURL == "" {
		return errors.New("endpoint configuration floor path or control identity is invalid")
	}
	raw, err := readFileBounded(path, 128<<10, true)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read endpoint configuration floor: %w", err)
	}
	plain, err := unprotectSecret(raw, configurationFloorDescription)
	if err != nil {
		return fmt.Errorf("unprotect endpoint configuration floor: %w", err)
	}
	defer clear(plain)
	var floor configurationFloor
	if err := decodeStrict(plain, &floor); err != nil || !validConfigurationFloor(floor, manager.floorIdentity()) {
		return errors.New("endpoint configuration floor identity or version is invalid")
	}
	manager.configurationFloor = floor
	if pending := floor.PendingCleanup; pending != nil {
		manager.status.SessionID = pending.SessionID
		manager.status.State, manager.status.Diagnostic = StateDegraded, "cleanup_pending"
		manager.leaseIDs, manager.cleanupReason = slices.Clone(pending.LeaseIDs), pending.Reason
	}
	return nil
}

func (manager *Manager) rememberConfiguration(desired ConfigurationDesired) error {
	raw, err := endpointEnforcementPayload(desired)
	if err != nil {
		return err
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
	floor := manager.configurationFloor
	if floor.PendingCleanup != nil {
		return errors.New("endpoint session cleanup is pending")
	}
	if desired.ConfigurationVersion < 1 || desired.PolicyVersion < 1 || desired.ConfigurationVersion < floor.ConfigurationVersion || desired.PolicyVersion < floor.PolicyVersion || desired.ConfigurationVersion == floor.ConfigurationVersion && digest != floor.Digest {
		return errors.New("endpoint configuration regressed or changed without a version")
	}
	if desired.ConfigurationVersion == floor.ConfigurationVersion {
		return nil
	}
	floor = configurationFloor{Version: 1, Identity: manager.floorIdentity(), ConfigurationVersion: desired.ConfigurationVersion, PolicyVersion: desired.PolicyVersion, Digest: digest}
	if err := manager.saveConfigurationFloor(floor); err != nil {
		return err
	}
	manager.configurationFloor = floor
	return nil
}

func endpointEnforcementPayload(desired ConfigurationDesired) ([]byte, error) {
	// Admission has its own restriction-epoch floor; intervals are operational.
	// Core attaches both independently of the VPN configuration version.
	desired.Admission = nil
	desired.RuntimeIntervals = nil
	return json.Marshal(desired)
}

func (manager *Manager) saveConfigurationFloor(floor configurationFloor) error {
	if manager.options.ConfigurationStatePath != "" {
		raw, err := json.Marshal(floor)
		if err != nil {
			return err
		}
		if err := saveProtectedState(manager.options.ConfigurationStatePath, raw, configurationFloorDescription); err != nil {
			return fmt.Errorf("commit endpoint configuration floor: %w", err)
		}
	}
	return nil
}

func (manager *Manager) beginVPNCleanup(sessionID string, leaseIDs []string, reason string) error {
	if sessionID == "" || len(leaseIDs) == 0 {
		return nil
	}
	floor := manager.configurationFloor
	floor.Version, floor.Identity = 1, manager.floorIdentity()
	floor.PendingCleanup = &pendingVPNCleanup{SessionID: sessionID, LeaseIDs: slices.Clone(leaseIDs), Reason: reason}
	manager.configurationFloor = floor
	return manager.saveConfigurationFloor(floor)
}

func (manager *Manager) finishVPNCleanup() error {
	floor := manager.configurationFloor
	if floor.PendingCleanup == nil {
		return nil
	}
	floor.PendingCleanup = nil
	if err := manager.saveConfigurationFloor(floor); err != nil {
		return err
	}
	manager.configurationFloor = floor
	return nil
}
