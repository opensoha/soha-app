//go:build windows

package endpointservice

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"unsafe"

	ec "github.com/opensoha/soha-contracts/endpointcontrol"
	"golang.org/x/sys/windows"
)

var enumChannelPrinters = windows.NewLazySystemDLL("winspool.drv").NewProc("EnumPrintersW")

type channelPrinterInfo struct {
	Name       *uint16
	Server     *uint16
	Attributes uint32
}

func localChannelPrinters() ([]string, error) {
	var needed, count uint32
	ok, _, initialErr := enumChannelPrinters.Call(2, 0, 4, 0, 0, uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&count)))
	if ok == 0 && initialErr != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, initialErr
	}
	if needed == 0 {
		return []string{}, nil
	}
	if needed > 1<<20 {
		return nil, errors.New("printer inventory too large")
	}
	buffer := make([]byte, needed)
	ok, _, err := enumChannelPrinters.Call(2, 0, 4, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&count)))
	if ok == 0 {
		return nil, err
	}
	if count > 256 || uintptr(count)*unsafe.Sizeof(channelPrinterInfo{}) > uintptr(len(buffer)) {
		return nil, errors.New("invalid printer inventory")
	}
	names := []string{}
	for _, p := range unsafe.Slice((*channelPrinterInfo)(unsafe.Pointer(&buffer[0])), int(count)) {
		name := windows.UTF16PtrToString(p.Name)
		server := windows.UTF16PtrToString(p.Server)
		if server != "" || strings.HasPrefix(name, `\\`) {
			continue
		}
		if name == "" || len(name) > 256 {
			return nil, errors.New("invalid local printer identity")
		}
		names = append(names, name)
	}
	return names, nil
}
func printerDescriptor(name string) (*windows.SECURITY_DESCRIPTOR, string, error) {
	sd, err := windows.GetNamedSecurityInfo(name, windows.SE_PRINTER, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, "", err
	}
	hash, err := printerACLHash(sd)
	return sd, hash, err
}
func printerACLHash(sd *windows.SECURITY_DESCRIPTOR) (string, error) {
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || printerACLSize(acl) < 8 {
		return "", errors.New("printer has no bounded explicit ACL")
	}
	raw := unsafe.Slice((*byte)(unsafe.Pointer(acl)), printerACLSize(acl))
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func writePrinterACL(name string, sd *windows.SECURITY_DESCRIPTOR) error {
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("printer ACL unavailable")
	}
	return windows.SetNamedSecurityInfo(name, windows.SE_PRINTER, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
func (s *windowsChannels) restrictPrinter(name string) error {
	sd, current, err := printerDescriptor(name)
	if err != nil {
		return err
	}
	if journal, ok := s.journal.Printers[name]; ok {
		if current == journal.ExpectedACL {
			return nil
		}
		original, err := windows.SecurityDescriptorFromString(journal.Original)
		if err != nil {
			return err
		}
		hash, err := printerACLHash(original)
		if err != nil {
			return err
		}
		if current != hash {
			return errors.New("printer permissions changed outside Soha")
		}
		world, err := windows.CreateWellKnownSid(windows.WinWorldSid)
		if err != nil {
			return err
		}
		expected, err := restrictedPrinterDescriptor(original, world)
		if err != nil {
			return err
		}
		return writePrinterACLIfUnchanged(name, current, expected)
	}
	world, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		return err
	}
	expected, err := restrictedPrinterDescriptor(sd, world)
	if err != nil {
		return err
	}
	hash, err := printerACLHash(expected)
	if err != nil {
		return err
	}
	if hash == current {
		return nil
	} // A pre-existing restriction is never adopted or removed.
	s.journal.Printers[name] = printerJournal{Original: sd.String(), ExpectedACL: hash}
	if err := s.saveJournal(); err != nil {
		delete(s.journal.Printers, name)
		return err
	}
	if err := writePrinterACLIfUnchanged(name, current, expected); err != nil {
		return err
	}
	_, actual, err := printerDescriptor(name)
	if err != nil {
		return err
	}
	if actual != hash {
		return errors.New("printer ACL readback mismatch")
	}
	return nil
}
func restrictedPrinterDescriptor(sd *windows.SECURITY_DESCRIPTOR, world *windows.SID) (*windows.SECURITY_DESCRIPTOR, error) {
	return windows.BuildSecurityDescriptor(nil, nil, []windows.EXPLICIT_ACCESS{{AccessPermissions: 8, AccessMode: windows.DENY_ACCESS, Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, TrusteeValue: windows.TrusteeValueFromSID(world)}}}, nil, sd)
}
func (s *windowsChannels) restorePrinter(name string, journal printerJournal, present bool) error {
	if present {
		sd, current, err := printerDescriptor(name)
		_ = sd
		if err != nil {
			return err
		}
		original, err := windows.SecurityDescriptorFromString(journal.Original)
		if err != nil {
			return err
		}
		hash, err := printerACLHash(original)
		if err != nil {
			return err
		}
		if current != hash && current != journal.ExpectedACL {
			return errors.New("printer ACL restoration conflicts with an external change")
		}
		if current != hash {
			if err := writePrinterACLIfUnchanged(name, current, original); err != nil {
				return err
			}
		}
	}
	delete(s.journal.Printers, name)
	if err := s.saveJournal(); err != nil {
		s.journal.Printers[name] = journal
		return err
	}
	return nil
}
func (s *windowsChannels) reconcilePrinters(ctx context.Context, enabled bool) ec.Channel {
	result := channelResult("print", "local_new_print_jobs", enabled)
	names, err := localChannelPrinters()
	if err != nil {
		result.State = "failed"
		result.ReasonCode = "printer_inventory_failed"
		return result
	}
	present := map[string]bool{}
	for _, name := range names {
		present[name] = true
	}
	if !enabled {
		for name, j := range s.journal.Printers {
			if ctx.Err() != nil || s.restorePrinter(name, j, present[name]) != nil {
				result.State = "conflict"
				result.ReasonCode = "printer_restore_pending"
			}
		}
		return result
	}
	result.Targets = len(names)
	for _, name := range names {
		if ctx.Err() != nil {
			result.State = "partial"
			result.ReasonCode = "native_deadline"
			break
		}
		if err := s.restrictPrinter(name); err != nil {
			result.State = "partial"
			result.ReasonCode = "printer_acl_unconfirmed"
		} else {
			result.Controlled++
		}
	}
	if result.Targets == 0 && result.State == "controlled" {
		result.State = "not_present"
		result.ReasonCode = "no_local_print_queues"
	}
	return result
}

func printerACLSize(acl *windows.ACL) int {
	if acl == nil {
		return 0
	}
	header := unsafe.Slice((*byte)(unsafe.Pointer(acl)), 8)
	return int(binary.LittleEndian.Uint16(header[2:4]))
}

// Windows exposes no atomic ACL compare/exchange. Recheck immediately before
// setting and require readback; administrator ACL edits need coordination.
func writePrinterACLIfUnchanged(name, current string, desired *windows.SECURITY_DESCRIPTOR) error {
	_, fresh, err := printerDescriptor(name)
	if err != nil {
		return err
	}
	if fresh != current {
		return errors.New("printer ACL changed before write")
	}
	if err := writePrinterACL(name, desired); err != nil {
		return err
	}
	want, err := printerACLHash(desired)
	if err != nil {
		return err
	}
	_, actual, err := printerDescriptor(name)
	if err != nil {
		return err
	}
	if actual != want {
		return errors.New("printer ACL readback mismatch")
	}
	return nil
}
