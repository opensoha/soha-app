//go:build windows

package endpointservice

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	ec "github.com/opensoha/soha-contracts/endpointcontrol"
	"golang.org/x/sys/windows"
)

type printerJournal struct {
	Original    string `json:"original"`
	ExpectedACL string `json:"expectedAcl"`
}
type channelJournal struct {
	Identity string                    `json:"identity"`
	Version  int                       `json:"version"`
	Printers map[string]printerJournal `json:"printers"`
}
type windowsChannels struct {
	config    Config
	journal   channelJournal
	volumes   map[string]windows.Handle
	clipboard *clipboardGuard
	accepted  bool
}

func NativeChannelsSupported() bool { return true }
func NewNativeChannelSystem(config Config) (ChannelSystem, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return nil, errors.New("native channel controls require the LocalSystem service")
	}
	if !validSID(config.AllowedUserSID) {
		return nil, errors.New("native channel controls require an enrolled Windows SID")
	}
	if err := registerNativeChannelOwner(config); err != nil {
		return nil, err
	}
	s := &windowsChannels{config: config, volumes: map[string]windows.Handle{}, journal: channelJournal{Identity: channelIdentity(config), Version: 1, Printers: map[string]printerJournal{}}}
	marker, err := nativeChannelMarkerPath()
	if err != nil {
		return nil, err
	}
	owner, err := loadNativeChannelOwner(marker)
	if err != nil {
		return nil, err
	}
	s.accepted = owner.Accepted
	raw, err := readFileBounded(s.journalPath(), 256<<10, true)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	plain, err := unprotectSecret(raw, channelStateDescription)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	if decodeStrict(plain, &s.journal) != nil || s.journal.Version != 1 || s.journal.Identity != channelIdentity(config) || s.journal.Printers == nil || len(s.journal.Printers) > 256 {
		return nil, errors.New("native printer ownership journal is invalid")
	}
	return s, nil
}
func (s *windowsChannels) journalPath() string {
	return filepath.Join(s.config.StateDirectory, "channel-printers.json")
}
func (s *windowsChannels) saveJournal() error {
	raw, err := json.Marshal(s.journal)
	if len(raw) > 256<<10 {
		return errors.New("native printer journal exceeds bounded storage")
	}
	if err != nil {
		return err
	}
	return saveProtectedState(s.journalPath(), raw, channelStateDescription)
}
func (s *windowsChannels) Reconcile(ctx context.Context, c ec.Controls) []ec.Channel {
	return []ec.Channel{s.reconcileUSB(ctx, c.USB), s.reconcilePrinters(ctx, c.Print), s.reconcileClipboard(ctx, c.Clipboard)}
}
func (s *windowsChannels) Close() error {
	var errs []error
	for name, h := range s.volumes {
		errs = append(errs, windows.CloseHandle(h))
		delete(s.volumes, name)
	}
	if s.clipboard != nil {
		err := s.clipboard.close()
		errs = append(errs, err)
		if err == nil {
			s.clipboard = nil
		}
	}
	// Printer ACLs and their restoration journal survive service stop/crash.
	return errors.Join(errs...)
}
func channelResult(name, scope string, enabled bool) ec.Channel {
	state, reason := "off", "disabled"
	if enabled {
		state, reason = "controlled", "native_scope_only"
	}
	return ec.Channel{Name: name, Scope: scope, State: state, ReasonCode: reason}
}

func (s *windowsChannels) PersistentRestrictions() bool {
	return s.accepted || len(s.journal.Printers) > 0
}
func (s *windowsChannels) RecordPolicyAcceptance() error {
	if s.accepted {
		return nil
	}
	marker, err := nativeChannelMarkerPath()
	if err != nil {
		return err
	}
	owner := nativeChannelOwner{Version: 1, Identity: channelIdentity(s.config), StateDirectory: s.config.StateDirectory, Accepted: true}
	raw, err := json.Marshal(owner)
	if err != nil {
		return err
	}
	if err := saveProtectedState(marker, raw, channelStateDescription); err != nil {
		return err
	}
	s.accepted = true
	return nil
}
