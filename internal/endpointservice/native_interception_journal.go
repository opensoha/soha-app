package endpointservice

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

type nativeJournalStep struct {
	Owner  string       `json:"owner,omitempty"` // empty/platform or wireguard
	Change nativeChange `json:"change"`
	Stage  string       `json:"stage"` // prepared, written, restored, conflict, unknown
}
type nativeJournal struct {
	Quiesce             *nativeDNSQuiescePlan       `json:"quiesce,omitempty"`
	SubscriptionBinding string                      `json:"subscriptionBinding,omitempty"`
	UIBindingHash       string                      `json:"uiBindingHash,omitempty"`
	Process             *nativeOwnedProcessIdentity `json:"process,omitempty"`
	CacheFlushPending   bool                        `json:"cacheFlushPending,omitempty"`
	DNSReleasePending   bool                        `json:"dnsReleasePending,omitempty"`
	Binding             string                      `json:"binding,omitempty"`
	Version             int                         `json:"version"`
	Generation          uint64                      `json:"generation"`
	Owner               nativeOwner                 `json:"owner"`
	Request             InterceptionIntent          `json:"request"`
	Steps               []nativeJournalStep         `json:"steps,omitempty"`
	Pending             bool                        `json:"pending"`
	ProcessEpoch        string                      `json:"processEpoch,omitempty"`
}

const nativeMaxJournalChanges = 1024
const nativeMaxJournalBytes = 3 << 20
const nativeJournalDescription = "OpenSoha local network interception"

func loadNativeJournal(path string) (nativeJournal, error) {
	raw, err := readFileBounded(path, 4<<20, true)
	if errors.Is(err, os.ErrNotExist) {
		return nativeJournal{Version: 1}, nil
	}
	if err != nil {
		return nativeJournal{}, err
	}
	plain, err := unprotectSecret(raw, nativeJournalDescription)
	if err != nil {
		return nativeJournal{}, err
	}
	defer clear(plain)
	var j nativeJournal
	if decodeStrict(plain, &j) != nil || j.Version != 1 || len(j.Steps) > nativeMaxJournalChanges || !validNativeQuiescePlan(j.Quiesce) || j.Quiesce != nil && (j.Quiesce.Binding != j.Binding || j.Quiesce.Process.Proof.ProcessEpoch != j.ProcessEpoch || j.Process != nil && !reflect.DeepEqual(*j.Process, j.Quiesce.Process)) {
		return nativeJournal{}, errors.New("invalid native recovery journal")
	}
	if err := validateNativeJournal(j); err != nil {
		return nativeJournal{}, err
	}
	for _, s := range j.Steps {
		if (s.Owner != "" && s.Owner != "platform" && s.Owner != "wireguard") || !validNativeChange(s.Change) {
			return nativeJournal{}, errors.New("invalid native recovery step")
		}
	}
	return j, nil
}
func saveNativeJournal(path string, j nativeJournal) error {
	if !filepath.IsAbs(path) || j.Version != 1 || len(j.Steps) > nativeMaxJournalChanges {
		return errors.New("invalid native journal")
	}
	for _, s := range j.Steps {
		if (s.Owner != "" && s.Owner != "platform" && s.Owner != "wireguard") || !validNativeChange(s.Change) {
			return errors.New("invalid native change")
		}
	}
	if err := validateNativeJournal(j); err != nil {
		return err
	}
	raw, err := json.Marshal(j)
	if err != nil {
		return err
	}
	if len(raw) > nativeMaxJournalBytes {
		return errors.New("native journal exceeds safe size")
	}
	if err = saveProtectedState(path, raw, nativeJournalDescription); err != nil {
		return err
	}
	// fsync the containing directory where supported. Windows reports unsupported.
	return syncNativeJournalDirectory(filepath.Dir(path))
}
func validNativeChange(c nativeChange) bool {
	if len(c.Scope.ServiceID) > 32768 || strings.IndexFunc(c.Scope.ServiceID, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return false
	}

	if c.ID == "" || len(c.ID) > 1024 || strings.IndexFunc(c.ID, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return false
	}
	for _, v := range []nativeValue{c.Before, c.After} {
		count := 0
		if v.Route != nil {
			count++
		}
		if v.DNS != nil {
			count++
		}
		if v.Proxy != nil {
			count++
		}
		if count > 1 || v.Present && count != 1 {
			return false
		}
		switch c.Kind {
		case "route":
			if v.DNS != nil || v.Proxy != nil {
				return false
			}
			if v.Route != nil && (!v.Route.Destination.IsValid() || v.Route.Destination != v.Route.Destination.Masked() || v.Route.Interface.ID == "" || v.Route.Interface.Index == 0) {
				return false
			}
		case "dns":
			if v.Route != nil || v.Proxy != nil {
				return false
			}
			if v.DNS != nil && len(v.DNS.Servers) > 32 {
				return false
			}
		case "proxy":
			if v.Route != nil || v.DNS != nil || c.Field == "" || len(c.Field) > 128 {
				return false
			}
			if v.Proxy != nil && (len(v.Proxy.Text) > 32768 || len(v.Proxy.Strings) > 1024) {
				return false
			}
		default:
			return false
		}
	}
	return true
}
func nativeValuesEqual(a, b nativeValue) bool { return reflect.DeepEqual(a, b) }

func validateNativeJournal(j nativeJournal) error {
	if !validNativeQuiescePlan(j.Quiesce) || j.Quiesce != nil && (j.Quiesce.Binding != j.Binding || j.Quiesce.Process.Proof.ProcessEpoch != j.ProcessEpoch || j.Process != nil && !reflect.DeepEqual(*j.Process, j.Quiesce.Process)) {
		return errors.New("invalid native quiesce journal binding")
	}
	if len(j.Steps) > nativeMaxJournalChanges {
		return errors.New("native change count exceeds safe limit")
	}
	if j.Quiesce != nil && !j.Quiesce.DNS {
		for _, step := range j.Steps {
			if step.Change.Kind == "dns" {
				return errors.New("DNS change lacks a DNS quiesce plan")
			}
		}
	}
	raw, err := json.Marshal(j)
	if err != nil {
		return err
	}
	if len(raw) > nativeMaxJournalBytes {
		return errors.New("native recovery journal exceeds safe limit")
	}
	return nil
}
