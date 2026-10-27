//go:build windows

package endpointservice

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func NewUIProcessPresence(config Config) (*UIProcessPresence, error) {
	if config.UIExecutable == "" && config.UICodeIdentity == "" {
		return nil, nil
	}
	if !validReadbackHash(config.UICodeIdentity) || !validSID(config.AllowedUserSID) {
		return nil, errors.New("Windows UI presence requires a pinned SHA256 and desktop SID")
	}
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return nil, err
	}
	executable := filepath.Clean(config.UIExecutable)
	if !strings.HasPrefix(strings.ToLower(executable), strings.ToLower(filepath.Clean(programFiles))+string(filepath.Separator)) {
		return nil, errors.New("trusted Windows UI must be installed under Program Files")
	}
	installer, _, _, err := windows.LookupSID("", `NT SERVICE\TrustedInstaller`)
	if err != nil {
		return nil, err
	}
	for path := executable; ; path = filepath.Dir(path) {
		if err := verifyEAPExecutablePath(path, installer); err != nil {
			return nil, err
		}
		if strings.EqualFold(path, programFiles) {
			break
		}
	}
	file, err := os.Open(executable)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	identity, err := file.Stat()
	if err != nil || !identity.Mode().IsRegular() || identity.Size() > 512<<20 {
		return nil, errors.New("trusted UI is not a bounded regular executable")
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, io.LimitReader(file, (512<<20)+1)); err != nil || fmt.Sprintf("sha256:%x", digest.Sum(nil)) != config.UICodeIdentity {
		return nil, errors.New("UI binary does not match its administrator-pinned hash")
	}
	return &UIProcessPresence{verify: func(connection net.Conn) error {
		pipe, ok := connection.(interface{ Fd() uintptr })
		if !ok {
			return errors.New("UI presence requires a native Windows pipe")
		}
		var pid uint32
		if err := windows.GetNamedPipeClientProcessId(windows.Handle(pipe.Fd()), &pid); err != nil || pid == 0 {
			return errors.New("UI process has no authenticated pipe PID")
		}
		process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(process)
		var token windows.Token
		if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
			return err
		}
		defer token.Close()
		user, err := token.GetTokenUser()
		if err != nil || user.User.Sid.String() != config.AllowedUserSID {
			return errors.New("UI process does not match the enrolled desktop user")
		}
		var session uint32
		if err := windows.ProcessIdToSessionId(pid, &session); err != nil || session != windows.WTSGetActiveConsoleSessionId() {
			return errors.New("UI process is outside the active desktop session")
		}
		name := make([]uint16, 32768)
		size := uint32(len(name))
		if err := windows.QueryFullProcessImageName(process, 0, &name[0], &size); err != nil || !strings.EqualFold(filepath.Clean(windows.UTF16ToString(name[:size])), executable) {
			return errors.New("UI process image does not match its provisioned executable")
		}
		current, err := os.Stat(executable)
		if err != nil || !os.SameFile(identity, current) || current.Size() != identity.Size() || !current.ModTime().Equal(identity.ModTime()) {
			return errors.New("UI executable changed; administrator reprovisioning is required")
		}
		return nil
	}}, nil
}
