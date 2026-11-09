//go:build windows

package endpointservice

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"io"
	"os/exec"
	"path/filepath"
	"syscall"
)

func (p *winNativePlatform) FlushResolverCache(ctx context.Context, s nativeSession) error {
	if _, ok := s.(*winNativeSession); !ok {
		return errors.New("untrusted native restore session")
	}
	return winNativeFlush(ctx, s, func(ctx context.Context) error {
		directory, err := windows.GetSystemDirectory()
		if err != nil {
			return errors.New("system cache utility unavailable")
		}
		executable := filepath.Join(directory, "ipconfig.exe")
		installer, _, _, err := windows.LookupSID("", `NT SERVICE\TrustedInstaller`)
		if err != nil {
			return errors.New("system cache utility identity unavailable")
		}
		if err := verifyEAPExecutablePath(executable, installer); err != nil {
			return errors.New("system cache utility identity invalid")
		}
		name, err := windows.UTF16PtrFromString(executable)
		if err != nil {
			return errors.New("system cache utility path invalid")
		}
		lock, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			return errors.New("system cache utility unavailable")
		}
		defer windows.CloseHandle(lock)
		cmd := exec.CommandContext(ctx, executable, "/flushdns")
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
		if err := cmd.Run(); err != nil {
			return errors.New("DNS resolver cache flush did not complete")
		}
		return nil
	})
}
