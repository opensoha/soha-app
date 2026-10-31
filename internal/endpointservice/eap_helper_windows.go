//go:build windows

package endpointservice

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func callEAPUserHelper(ctx context.Context, expectedSID string, request eapUserRequest) (eapUserResponse, error) {
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || !current.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return eapUserResponse{}, errors.New("EAP user helper requires the LocalSystem service")
	}
	sessionID := windows.WTSGetActiveConsoleSessionId()
	if sessionID == 0xffffffff {
		return eapUserResponse{}, errors.New("EAP requires an active local desktop user")
	}
	var token windows.Token
	if err := windows.WTSQueryUserToken(sessionID, &token); err != nil {
		return eapUserResponse{}, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user.User.Sid.String() != expectedSID || user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return eapUserResponse{}, errors.New("active desktop user does not match the enrolled EAP user")
	}
	request.ExpectedSID = expectedSID
	raw, err := json.Marshal(request)
	if err != nil || len(raw) > 256<<10 {
		return eapUserResponse{}, errors.New("EAP user request exceeds the safe size")
	}
	executable, lock, err := trustedEAPHelperExecutable()
	if err != nil {
		return eapUserResponse{}, err
	}
	defer windows.CloseHandle(lock)
	environment, err := token.Environ(false)
	if err != nil {
		return eapUserResponse{}, err
	}
	timeout := 45 * time.Second
	if request.Action == "install" {
		timeout = 90 * time.Second
	}
	operationCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	output, err := runEAPUserProcess(operationCtx, executable, token, environment, raw)
	if err != nil {
		return eapUserResponse{}, errors.New("EAP user operation did not complete")
	}
	if windows.WTSGetActiveConsoleSessionId() != sessionID {
		return eapUserResponse{}, errors.New("desktop session changed during the EAP operation")
	}
	var result eapUserResponse
	if err := decodeStrict(output, &result); err != nil || !result.OK || len(result.CSR) > 4096 || len(result.ProfileXML) > 128<<10 || result.Fingerprint != "" && !validReadbackHash(result.Fingerprint) {
		return eapUserResponse{}, errors.New("EAP user helper returned an invalid receipt")
	}
	return result, nil
}

func trustedEAPHelperExecutable() (string, windows.Handle, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", 0, err
	}
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", 0, err
	}
	executable, programFiles = filepath.Clean(executable), filepath.Clean(programFiles)
	if !strings.HasPrefix(strings.ToLower(executable), strings.ToLower(programFiles)+string(filepath.Separator)) || !strings.EqualFold(filepath.Base(executable), "soha-app-service.exe") {
		return "", 0, errors.New("EAP service must be installed in the protected Program Files directory")
	}
	installer, _, _, err := windows.LookupSID("", `NT SERVICE\TrustedInstaller`)
	if err != nil {
		return "", 0, err
	}
	for path := executable; ; path = filepath.Dir(path) {
		if err := verifyEAPExecutablePath(path, installer); err != nil {
			return "", 0, err
		}
		if strings.EqualFold(path, programFiles) {
			break
		}
	}
	name, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return "", 0, err
	}
	lock, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return "", 0, err
	}
	return executable, lock, nil
}

func verifyEAPExecutablePath(path string, installer *windows.SID) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(name)
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("EAP helper path is unavailable or uses a reparse point")
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil || !trustedEAPWindowsOwner(owner, installer) {
		return errors.New("EAP helper path has an untrusted owner")
	}
	acl, _, err := descriptor.DACL()
	if err != nil || acl == nil || acl.AceCount > 128 {
		return errors.New("EAP helper path has no bounded DACL")
	}
	writes := uint32(windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER)
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, index, &ace); err != nil {
			return err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("EAP helper path has an unsupported access rule")
		}
		if uint32(ace.Mask)&writes != 0 && !trustedEAPWindowsOwner((*windows.SID)(unsafe.Pointer(&ace.SidStart)), installer) {
			return errors.New("EAP helper path is writable outside trusted administrators")
		}
	}
	return nil
}

func trustedEAPWindowsOwner(sid, installer *windows.SID) bool {
	return sid != nil && sid.IsValid() && (sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || installer != nil && sid.Equals(installer))
}
