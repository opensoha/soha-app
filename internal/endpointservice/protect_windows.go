//go:build windows

package endpointservice

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func protectSecret(payload []byte, description string) ([]byte, error) {
	if len(payload) == 0 {
		return nil, errors.New("secret is empty")
	}
	name, err := windows.UTF16PtrFromString(description)
	if err != nil {
		return nil, err
	}
	in := windows.DataBlob{Size: uint32(len(payload)), Data: &payload[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, name, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func unprotectSecret(payload []byte, _ string) ([]byte, error) {
	if len(payload) == 0 {
		return nil, errors.New("protected secret is empty")
	}
	in := windows.DataBlob{Size: uint32(len(payload)), Data: &payload[0]}
	var name *uint16
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, &name, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	if name != nil {
		defer windows.LocalFree(windows.Handle(unsafe.Pointer(name)))
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func secureStateDirectory(path string) error {
	return securePathDACL(path, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
}

func secureSecretFile(path string, _ os.FileInfo) error {
	return securePathDACL(path, windows.NO_INHERITANCE)
}

func securePathDACL(path string, inheritance uint32) error {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	entries := []windows.EXPLICIT_ACCESS{
		{AccessPermissions: windows.GENERIC_ALL, AccessMode: windows.GRANT_ACCESS, Inheritance: inheritance, Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER, TrusteeValue: windows.TrusteeValueFromSID(system)}},
		{AccessPermissions: windows.GENERIC_ALL, AccessMode: windows.GRANT_ACCESS, Inheritance: inheritance, Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_GROUP, TrusteeValue: windows.TrusteeValueFromSID(administrators)}},
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
