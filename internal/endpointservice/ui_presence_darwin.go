//go:build darwin && cgo

package endpointservice

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <stdlib.h>
int soha_verify_ui_code(int pid, const char *path, const char *requirement);
*/
import "C"

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

func NewUIProcessPresence(config Config) (*UIProcessPresence, error) {
	if config.UIExecutable == "" && config.UICodeIdentity == "" {
		return nil, nil
	}
	value := strings.TrimPrefix(config.UICodeIdentity, "cdhash:")
	decoded, err := hex.DecodeString(value)
	if err != nil || config.AllowedUserUID == nil || value == config.UICodeIdentity || len(decoded) != 20 && len(decoded) != 32 || value != strings.ToLower(value) {
		return nil, errors.New("macOS UI presence requires a pinned CodeDirectory hash and desktop UID")
	}
	requirement := `cdhash H"` + value + `"`
	if err := verifyDarwinUICode(0, config.UIExecutable, requirement); err != nil {
		return nil, err
	}
	return &UIProcessPresence{verify: func(connection net.Conn) error {
		peer, ok := connection.(*net.UnixConn)
		if !ok {
			return errors.New("UI presence requires a native Unix socket")
		}
		uid, err := darwinPeerUID(peer)
		if err != nil || uid != *config.AllowedUserUID {
			return errors.New("UI process does not match the enrolled desktop user")
		}
		raw, err := peer.SyscallConn()
		if err != nil {
			return err
		}
		pid := 0
		var socketErr error
		if err := raw.Control(func(fd uintptr) { pid, socketErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID) }); err != nil {
			return err
		}
		if socketErr != nil || pid < 1 {
			return errors.New("UI process has no authenticated peer PID")
		}
		return verifyDarwinUICode(pid, "", requirement)
	}}, nil
}

func verifyDarwinUICode(pid int, path, requirement string) error {
	cPath, cRequirement := C.CString(path), C.CString(requirement)
	defer C.free(unsafe.Pointer(cPath))
	defer C.free(unsafe.Pointer(cRequirement))
	if status := C.soha_verify_ui_code(C.int(pid), cPath, cRequirement); status != 0 {
		return fmt.Errorf("UI code does not match the administrator-pinned code identity (OSStatus %d)", int(status))
	}
	return nil
}
