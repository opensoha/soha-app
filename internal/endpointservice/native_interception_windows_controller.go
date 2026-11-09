//go:build windows

package endpointservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/windows"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

func (p *winNativePlatform) controllerCalls() winControllerCalls {
	return winControllerCalls{
		session: func(ctx context.Context, s nativeSession, restore bool) error {
			if actual, ok := s.(*winNativeSession); !ok || actual == nil || actual.Owner().UserID != p.config.AllowedUserSID {
				return errWinController
			}
			return s.Validate(ctx, restore)
		},
		proof: func(proof nativeOwnedProcessProof) bool {
			return filepath.IsAbs(proof.LaunchDirectory) && filepath.Clean(proof.LaunchDirectory) == proof.LaunchDirectory && filepath.IsAbs(proof.ExecutablePath) && filepath.Clean(proof.ExecutablePath) == proof.ExecutablePath && winControllerProofValid(proof, p.config.StateDirectory)
		},
		parent: func() (uint32, uint64, error) {
			created, _, err := winControllerProcessTime(windows.CurrentProcess())
			return uint32(os.Getpid()), created, err
		},
		open: func(ctx context.Context, proof nativeOwnedProcessProof, stamp *winControllerStamp) (winControllerLease, bool, error) {
			return winControllerOpen(ctx, proof, stamp, p.config.StateDirectory)
		},
		dial: func(ctx context.Context, endpoint netip.AddrPort) (net.Conn, error) {
			network := "tcp6"
			if endpoint.Addr().Is4() {
				network = "tcp4"
			}
			dialer := net.Dialer{Timeout: 5 * time.Second}
			return dialer.DialContext(ctx, network, endpoint.String())
		},
		tuples: winControllerSystemTuples, servicePID: uint32(os.Getpid()),
	}
}
func (p *winNativePlatform) CaptureOwnedProcess(ctx context.Context, s nativeSession, proof nativeOwnedProcessProof) (nativeOwnedProcessIdentity, error) {
	return winControllerCapture(ctx, s, proof, p.controllerCalls())
}
func (p *winNativePlatform) DialOwnedController(ctx context.Context, s nativeSession, record nativeOwnedProcessIdentity, endpoint netip.AddrPort) (net.Conn, bool, error) {
	return winControllerDial(ctx, s, record, endpoint, p.controllerCalls())
}

// Capture is intentionally implemented without RecoverOwnedProcess: Windows keeps its Job owner.

// The deny-write/delete image lease keeps its verified hash immutable; each inspection rechecks the same file and live process.
type winControllerNativeLease struct {
	process, parent                        windows.Handle
	locks                                  []windows.Handle
	binary, directory, service             windows.Handle
	binaryInfo, directoryInfo, serviceInfo windows.ByHandleFileInformation
	proof                                  nativeOwnedProcessProof
	hash, parentPath                       string
	once                                   sync.Once
}

func (l *winControllerNativeLease) Close() error {
	l.once.Do(func() {
		for _, h := range l.locks {
			_ = windows.CloseHandle(h)
		}
		if l.parent != 0 {
			_ = windows.CloseHandle(l.parent)
		}
		if l.process != 0 {
			_ = windows.CloseHandle(l.process)
		}
	})
	return nil
}
func winControllerProcessTime(h windows.Handle) (uint64, bool, error) {
	event, err := windows.WaitForSingleObject(h, 0)
	if err != nil {
		return 0, false, err
	}
	if event == windows.WAIT_OBJECT_0 {
		return 0, true, nil
	}
	if event != uint32(windows.WAIT_TIMEOUT) {
		return 0, false, errWinController
	}
	var c, e, k, u windows.Filetime
	if err := windows.GetProcessTimes(h, &c, &e, &k, &u); err != nil {
		return 0, false, err
	}
	return uint64(c.HighDateTime)<<32 | uint64(c.LowDateTime), false, nil
}
func winControllerOpen(ctx context.Context, proof nativeOwnedProcessProof, expected *winControllerStamp, state string) (lease winControllerLease, gone bool, err error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return nil, false, errWinController
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ|windows.SYNCHRONIZE, false, proof.PID)
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return nil, true, nil
		}
		return nil, false, err
	}
	l := &winControllerNativeLease{process: h, proof: proof}
	keep := false
	defer func() {
		if !keep {
			l.Close()
		}
	}()
	created, dead, err := winControllerProcessTime(h)
	if err != nil {
		return nil, false, err
	}
	if dead || expected != nil && created != expected.Created {
		return nil, true, nil
	}
	var machine, native uint16
	if err := windows.IsWow64Process2(h, &machine, &native); err != nil || machine != 0 || runtime.GOARCH == "amd64" && native != 0x8664 || runtime.GOARCH == "arm64" && native != 0xaa64 {
		return nil, false, errWinController
	}
	basic, err := winControllerBasic(h)
	if err != nil {
		return nil, false, err
	}
	if basic.UniqueProcessId != uintptr(proof.PID) || basic.InheritedFromUniqueProcessId < 2 || basic.InheritedFromUniqueProcessId > 4294967295 {
		return nil, false, errWinController
	}
	if expected != nil && uint64(basic.InheritedFromUniqueProcessId) != expected.ParentPID {
		return nil, false, errWinController
	}
	l.parent, err = windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(basic.InheritedFromUniqueProcessId))
	if err != nil {
		return nil, false, err
	}
	parentCreated, _, err := winControllerProcessTime(l.parent)
	if err != nil || parentCreated == 0 {
		return nil, false, errWinController
	}
	if expected != nil && parentCreated != expected.ParentCreated {
		return nil, false, errWinController
	}
	parentPath, err := winControllerImage(l.parent)
	if err != nil {
		return nil, false, err
	}
	servicePath, serviceLock, err := trustedEAPHelperExecutable()
	if err != nil {
		return nil, false, err
	}
	l.locks = append(l.locks, serviceLock)
	l.service = serviceLock
	l.parentPath = servicePath
	if !strings.EqualFold(filepath.Clean(parentPath), filepath.Clean(servicePath)) {
		return nil, false, errWinController
	}
	if err := windows.GetFileInformationByHandle(serviceLock, &l.serviceInfo); err != nil {
		return nil, false, err
	}
	if err := winControllerSystemUser(h); err != nil {
		return nil, false, err
	}
	if err := winControllerSystemUser(l.parent); err != nil {
		return nil, false, err
	}
	installer, _, _, err := windows.LookupSID("", `NT SERVICE\TrustedInstaller`)
	if err != nil {
		return nil, false, err
	}
	var dirs []string
	for dir := filepath.Clean(proof.LaunchDirectory); ; dir = filepath.Dir(dir) {
		dirs = append(dirs, dir)
		if parent := filepath.Dir(dir); parent == dir {
			break
		}
	}
	slices.Reverse(dirs)
	for _, dir := range dirs {
		name, err := windows.UTF16PtrFromString(dir)
		if err != nil {
			return nil, false, err
		}
		handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			return nil, false, err
		}
		l.locks = append(l.locks, handle)
		private := strings.EqualFold(dir, filepath.Clean(state)) || strings.HasPrefix(strings.ToLower(dir), strings.ToLower(filepath.Clean(state))+string(filepath.Separator))
		if err := winControllerPathACL(dir, installer, private); err != nil {
			return nil, false, err
		}
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(handle, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return nil, false, errWinController
		}
		if strings.EqualFold(dir, proof.LaunchDirectory) {
			l.directory = handle
			l.directoryInfo = info
		}
	}
	configPath := filepath.Join(proof.LaunchDirectory, "config.yaml")
	if err := winControllerPathACL(configPath, installer, true); err != nil {
		return nil, false, err
	}
	configName, err := windows.UTF16PtrFromString(configPath)
	if err != nil {
		return nil, false, err
	}
	config, err := windows.CreateFile(configName, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, false, err
	}
	l.locks = append(l.locks, config)
	var configInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(config, &configInfo); err != nil || configInfo.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return nil, false, errWinController
	}
	if err := verifyEAPExecutablePath(proof.ExecutablePath, installer); err != nil {
		return nil, false, err
	}
	if err := winControllerPathACL(proof.ExecutablePath, installer, true); err != nil {
		return nil, false, err
	}
	name, err := windows.UTF16PtrFromString(proof.ExecutablePath)
	if err != nil {
		return nil, false, err
	}
	l.binary, err = windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, false, err
	}
	l.locks = append(l.locks, l.binary)
	if err := windows.GetFileInformationByHandle(l.binary, &l.binaryInfo); err != nil || l.binaryInfo.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || l.binaryInfo.FileSizeHigh != 0 || l.binaryInfo.FileSizeLow == 0 || l.binaryInfo.FileSizeLow > 256<<20 {
		return nil, false, errWinController
	}
	var duplicate windows.Handle
	if err := windows.DuplicateHandle(windows.CurrentProcess(), l.binary, windows.CurrentProcess(), &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, false, err
	}
	file := os.NewFile(uintptr(duplicate), "owned-controller-image")
	digest := sha256.New()
	n, readErr := io.Copy(digest, io.LimitReader(file, (256<<20)+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || n != int64(l.binaryInfo.FileSizeLow) {
		return nil, false, errWinController
	}
	l.hash = hex.EncodeToString(digest.Sum(nil))
	if l.hash != proof.BinarySHA256 {
		return nil, false, errWinController
	}
	observed, dead, err := l.Inspect(ctx)
	if err != nil {
		return nil, false, err
	}
	if dead {
		return nil, true, nil
	}
	if expected != nil && observed.Stamp.Created != expected.Created {
		return nil, true, nil
	}
	if err := winControllerCheck(observed, proof, expected); err != nil {
		return nil, false, err
	}
	keep = true
	return l, false, nil
}
func winControllerPathACL(path string, installer *windows.SID, private bool) error {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil || !trustedEAPWindowsOwner(owner, installer) {
		return errWinController
	}
	acl, _, err := descriptor.DACL()
	if err != nil || acl == nil || acl.AceCount > 128 {
		return errWinController
	}
	risk := uint32(windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | 0x40 /* FILE_DELETE_CHILD */ | windows.FILE_WRITE_ATTRIBUTES | windows.FILE_WRITE_EA)
	if private {
		risk = ^uint32(0)
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errWinController
		}
		if uint32(ace.Mask)&risk != 0 && !trustedEAPWindowsOwner((*windows.SID)(unsafe.Pointer(&ace.SidStart)), installer) {
			return errWinController
		}
	}
	return nil
}
func winControllerBasic(h windows.Handle) (windows.PROCESS_BASIC_INFORMATION, error) {
	var p windows.PROCESS_BASIC_INFORMATION
	var size uint32
	err := windows.NtQueryInformationProcess(h, windows.ProcessBasicInformation, unsafe.Pointer(&p), uint32(unsafe.Sizeof(p)), &size)
	if err != nil || size < uint32(unsafe.Sizeof(p)) || p.PebBaseAddress == nil {
		return p, errWinController
	}
	return p, nil
}
func winControllerImage(h windows.Handle) (string, error) {
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil || size == 0 || size >= uint32(len(buf)) {
		return "", errWinController
	}
	return windows.UTF16ToString(buf[:size]), nil
}
func winControllerSystemUser(h windows.Handle) error {
	var token windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return errWinController
	}
	return nil
}
func winControllerMemory(h windows.Handle, address uintptr, target unsafe.Pointer, size uintptr) error {
	if address < 65536 || size == 0 || size > 65536 || address > ^uintptr(0)-size {
		return errWinController
	}
	var read uintptr
	if err := windows.ReadProcessMemory(h, address, (*byte)(target), size, &read); err != nil || read != size {
		return errWinController
	}
	return nil
}
func winControllerString(h windows.Handle, s windows.NTUnicodeString) (string, error) {
	if s.Length%2 != 0 || s.MaximumLength%2 != 0 || s.Length > s.MaximumLength || s.Length > 65532 || s.Buffer == nil {
		return "", errWinController
	}
	if s.Length == 0 {
		return "", nil
	}
	buf := make([]uint16, s.Length/2)
	if err := winControllerMemory(h, uintptr(unsafe.Pointer(s.Buffer)), unsafe.Pointer(&buf[0]), uintptr(s.Length)); err != nil {
		return "", err
	}
	for i := 0; i < len(buf); i++ {
		v := buf[i]
		if v == 0 {
			return "", errWinController
		}
		if v >= 0xd800 && v <= 0xdbff {
			if i+1 >= len(buf) || buf[i+1] < 0xdc00 || buf[i+1] > 0xdfff {
				return "", errWinController
			}
			i++
		} else if v >= 0xdc00 && v <= 0xdfff {
			return "", errWinController
		}
	}
	return string(utf16.Decode(buf)), nil
}
func (l *winControllerNativeLease) Inspect(ctx context.Context) (winControllerObserved, bool, error) {
	var o winControllerObserved
	if err := ctx.Err(); err != nil {
		return o, false, err
	}
	created, dead, err := winControllerProcessTime(l.process)
	if err != nil || dead {
		return o, dead, err
	}
	basic, err := winControllerBasic(l.process)
	if err == nil && basic.UniqueProcessId != uintptr(l.proof.PID) {
		return o, false, errWinController
	}
	if err != nil {
		return o, false, err
	}
	parentCreated, _, err := winControllerProcessTime(l.parent)
	if err != nil || parentCreated == 0 {
		return o, false, errWinController
	}
	var peb windows.PEB
	pebSize := unsafe.Offsetof(peb.ProcessParameters) + unsafe.Sizeof(peb.ProcessParameters)
	if err := winControllerMemory(l.process, uintptr(unsafe.Pointer(basic.PebBaseAddress)), unsafe.Pointer(&peb), pebSize); err != nil || peb.ProcessParameters == nil {
		return o, false, errWinController
	}
	var params windows.RTL_USER_PROCESS_PARAMETERS
	parameterSize := unsafe.Offsetof(params.CommandLine) + unsafe.Sizeof(params.CommandLine)
	if err := winControllerMemory(l.process, uintptr(unsafe.Pointer(peb.ProcessParameters)), unsafe.Pointer(&params), parameterSize); err != nil {
		return o, false, err
	}
	if params.Length < uint32(parameterSize) || params.MaximumLength < params.Length || params.MaximumLength > 1<<20 || params.Flags&1 == 0 {
		return o, false, errWinController
	}
	image, err := winControllerString(l.process, params.ImagePathName)
	if err != nil {
		return o, false, err
	}
	command, err := winControllerString(l.process, params.CommandLine)
	if err != nil {
		return o, false, err
	}
	args, err := windows.DecomposeCommandLine(command)
	if err != nil || len(args) != 5 {
		return o, false, errWinController
	}
	actual, err := winControllerImage(l.process)
	if err != nil || !strings.EqualFold(filepath.Clean(actual), filepath.Clean(image)) {
		return o, false, errWinController
	}
	parentPath, err := winControllerImage(l.parent)
	if err != nil || !strings.EqualFold(filepath.Clean(parentPath), filepath.Clean(l.parentPath)) {
		return o, false, errWinController
	}
	if err := winControllerSystemUser(l.process); err != nil {
		return o, false, err
	}
	var bi, di, si windows.ByHandleFileInformation
	for _, pair := range []struct {
		handle windows.Handle
		out    *windows.ByHandleFileInformation
	}{{l.binary, &bi}, {l.directory, &di}, {l.service, &si}} {
		if err := windows.GetFileInformationByHandle(pair.handle, pair.out); err != nil {
			return o, false, err
		}
	}
	if !winControllerFileStable(bi, l.binaryInfo, false) || !winControllerFileStable(di, l.directoryInfo, true) || !winControllerFileStable(si, l.serviceInfo, false) {
		return o, false, errWinController
	}
	last, dead, err := winControllerProcessTime(l.process)
	if err != nil || dead {
		return o, dead, err
	}
	again, err := winControllerBasic(l.process)
	if err != nil || created != last || basic.UniqueProcessId != again.UniqueProcessId || basic.InheritedFromUniqueProcessId != again.InheritedFromUniqueProcessId || basic.PebBaseAddress != again.PebBaseAddress {
		return o, false, errWinController
	}
	id := func(info windows.ByHandleFileInformation) uint64 {
		return uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow)
	}
	o = winControllerObserved{Stamp: winControllerStamp{created, uint64(basic.InheritedFromUniqueProcessId), parentCreated, uint64(bi.VolumeSerialNumber), id(bi), uint64(di.VolumeSerialNumber), id(di), uint64(si.VolumeSerialNumber), id(si)}, PID: uint32(basic.UniqueProcessId), Image: actual, Hash: l.hash, Arguments: args, Trusted: true}
	if err := ctx.Err(); err != nil {
		return o, false, err
	}
	return o, false, nil
}
func winControllerSystemTuples(ctx context.Context, ipv4 bool) ([]winControllerTuple, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	api := winNativeIPHelper.NewProc("GetExtendedTcpTable")
	if err := api.Find(); err != nil {
		return nil, err
	}
	family := uintptr(windows.AF_INET6)
	if ipv4 {
		family = windows.AF_INET
	}
	size := uint32(16384)
	for tries := 0; tries < 4; tries++ {
		if size < 4 || size > 4<<20 {
			return nil, errWinController
		}
		buf := make([]byte, size)
		r, _, _ := api.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, family, 4, 0)
		if r == 122 {
			continue
		}
		if r != 0 {
			return nil, syscall.Errno(r)
		}
		if int(size) > len(buf) {
			return nil, errWinController
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return winControllerParseTuples(buf[:size], ipv4)
	}
	return nil, errWinController
}

func winControllerFileStable(a, b windows.ByHandleFileInformation, directory bool) bool {
	if a.VolumeSerialNumber != b.VolumeSerialNumber || a.FileIndexHigh != b.FileIndexHigh || a.FileIndexLow != b.FileIndexLow || a.CreationTime != b.CreationTime || a.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false
	}
	if directory {
		return a.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	}
	return a.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 && a.FileSizeHigh == b.FileSizeHigh && a.FileSizeLow == b.FileSizeLow && a.LastWriteTime == b.LastWriteTime
}
