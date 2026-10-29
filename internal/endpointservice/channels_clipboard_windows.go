//go:build windows

package endpointservice

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	ec "github.com/opensoha/soha-contracts/endpointcontrol"
	"golang.org/x/sys/windows"
)

var clipboardUser32 = windows.NewLazySystemDLL("user32.dll")
var openGuardClipboard = clipboardUser32.NewProc("OpenClipboard")
var closeGuardClipboard = clipboardUser32.NewProc("CloseClipboard")

type clipboardHello struct {
	SID     string `json:"sid"`
	Session uint32 `json:"session"`
	Nonce   string `json:"nonce"`
}
type clipboardAck struct {
	Session uint32 `json:"session"`
	Nonce   string `json:"nonce"`
	Held    bool   `json:"held"`
}
type clipboardGuard struct {
	job     windows.Handle
	process windows.Handle
	input   *os.File
	output  *os.File
	binary  windows.Handle
	session uint32
	nonce   string
	acks    <-chan clipboardAck
}

// RunClipboardGuard holds access before clipboard operations. It never reads,
// empties or uploads clipboard data; Session 0 is explicitly rejected.
func RunClipboardGuard(input io.Reader, output io.Writer) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	scan := bufio.NewScanner(input)
	scan.Buffer(make([]byte, 1024), 2048)
	if !scan.Scan() {
		return errors.New("clipboard guard request missing")
	}
	var hello clipboardHello
	if ec.Decode(scan.Bytes(), &hello) != nil || len(hello.Nonce) != 43 {
		return errors.New("invalid clipboard guard binding")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) || !clipboardConsoleMatches(hello.SID, hello.Session) {
		return errors.New("clipboard guard requires the bound SYSTEM desktop")
	}
	var session uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session); err != nil || session == 0 || session != hello.Session {
		return errors.New("clipboard guard is on the wrong desktop session")
	}
	ok, _, err := openGuardClipboard.Call(0)
	if ok == 0 {
		return err
	}
	defer closeGuardClipboard.Call()
	ack := clipboardAck{Session: session, Nonce: hello.Nonce, Held: true}
	encode := json.NewEncoder(output)
	if err := encode.Encode(ack); err != nil {
		return err
	}
	for scan.Scan() {
		if scan.Text() != "ping" || !clipboardConsoleMatches(hello.SID, session) {
			return errors.New("clipboard guard session changed")
		}
		if err := encode.Encode(ack); err != nil {
			return err
		}
	}
	return scan.Err()
}
func (g *clipboardGuard) close() error {
	if g == nil {
		return nil
	}
	_ = g.input.Close()
	if g.job != 0 {
		if windows.CloseHandle(g.job) == nil {
			g.job = 0
		}
	}
	event, err := windows.WaitForSingleObject(g.process, 500)
	if err != nil || event != windows.WAIT_OBJECT_0 {
		_ = windows.TerminateProcess(g.process, 1)
		event, err = windows.WaitForSingleObject(g.process, 1000)
		if err != nil || event != windows.WAIT_OBJECT_0 {
			return errors.Join(err, errors.New("clipboard guard termination unconfirmed"))
		}
	}
	_ = g.output.Close()
	_ = windows.CloseHandle(g.process)
	_ = windows.CloseHandle(g.binary)
	return nil
}

func (g *clipboardGuard) heartbeat(ctx context.Context) error {
	if windows.WTSGetActiveConsoleSessionId() != g.session {
		return errors.New("console session changed")
	}
	event, err := windows.WaitForSingleObject(g.process, 0)
	if err != nil || event == windows.WAIT_OBJECT_0 {
		return errors.New("clipboard guard exited")
	}
	written := make(chan error, 1)
	go func() { _, err := io.WriteString(g.input, "ping\n"); written <- err }()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case err := <-written:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errors.New("clipboard heartbeat write timed out")
	}
	select {
	case ack, ok := <-g.acks:
		if !ok || !ack.Held || ack.Session != g.session || ack.Nonce != g.nonce {
			return errors.New("clipboard acknowledgement invalid")
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errors.New("clipboard heartbeat timed out")
	}
}
func (s *windowsChannels) reconcileClipboard(ctx context.Context, enabled bool) ec.Channel {
	result := channelResult("clipboard", "enrolled_console_win32", enabled)
	if !enabled {
		if s.clipboard != nil {
			if s.clipboard.close() != nil {
				result.State = "failed"
				result.ReasonCode = "clipboard_cleanup_failed"
				return result
			}
			s.clipboard = nil
		}
		return result
	}
	result.Targets = 1
	if s.clipboard != nil {
		if s.clipboard.heartbeat(ctx) == nil {
			result.Controlled = 1
			return result
		}
		if s.clipboard.close() != nil {
			result.State = "failed"
			result.ReasonCode = "clipboard_cleanup_failed"
			return result
		}
		s.clipboard = nil
	}
	guard, err := startClipboardGuard(s.config.AllowedUserSID)
	if guard != nil {
		s.clipboard = guard
	}
	if err != nil {
		result.State = "failed"
		result.ReasonCode = "clipboard_guard_unavailable"
		return result
	}
	s.clipboard = guard
	result.Controlled = 1
	return result
}

func startClipboardGuard(expectedSID string) (*clipboardGuard, error) {
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0xffffffff || session == 0 {
		return nil, errors.New("no enrolled console session")
	}
	if !clipboardConsoleMatches(expectedSID, session) {
		return nil, errors.New("console user is not enrolled")
	}
	var token windows.Token
	if err := windows.DuplicateTokenEx(windows.GetCurrentProcessToken(), windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenPrimary, &token); err != nil {
		return nil, err
	}
	defer token.Close()
	if err := windows.SetTokenInformation(token, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), uint32(unsafe.Sizeof(session))); err != nil {
		return nil, err
	}
	executable, binary, err := trustedEAPHelperExecutable()
	if err != nil {
		return nil, err
	}
	guard, err := launchClipboardProcess(executable, token, session, binary)
	if err != nil {
		_ = windows.CloseHandle(binary)
		return nil, err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		_ = guard.close()
		return nil, err
	}
	guard.nonce = base64.RawURLEncoding.EncodeToString(nonce[:])
	hello := clipboardHello{SID: expectedSID, Session: session, Nonce: guard.nonce}
	encoded, _ := json.Marshal(hello)
	encoded = append(encoded, '\n')
	if _, err := guard.input.Write(encoded); err != nil {
		_ = guard.close()
		return nil, err
	}
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()
	select {
	case ack, ok := <-guard.acks:
		if ok && ack.Held && ack.Nonce == guard.nonce && ack.Session == session && windows.WTSGetActiveConsoleSessionId() == session {
			return guard, nil
		}
	case <-timeout.C:
	}
	if cleanup := guard.close(); cleanup != nil {
		return guard, cleanup
	}
	return nil, errors.New("clipboard guard did not acquire access")
}
func launchClipboardProcess(executable string, token windows.Token, session uint32, binary windows.Handle) (*clipboardGuard, error) {
	childInput, input, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer childInput.Close()
	output, childOutput, err := os.Pipe()
	if err != nil {
		_ = input.Close()
		return nil, err
	}
	defer childOutput.Close()
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		_ = input.Close()
		_ = output.Close()
		return nil, err
	}
	defer null.Close()
	guard := &clipboardGuard{input: input, output: output, binary: binary, session: session}
	success := false
	defer func() {
		if !success {
			_ = input.Close()
			_ = output.Close()
		}
	}()
	handles := [3]windows.Handle{}
	defer func() {
		for _, h := range handles {
			if h != 0 {
				_ = windows.CloseHandle(h)
			}
		}
	}()
	for i, file := range []*os.File{childInput, childOutput, null} {
		if err := windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(file.Fd()), windows.CurrentProcess(), &handles[i], 0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
			return nil, err
		}
	}
	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return nil, err
	}
	defer attrs.Delete()
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), unsafe.Sizeof(handles)); err != nil {
		return nil, err
	}
	environment, err := token.Environ(false)
	if err != nil {
		return nil, err
	}
	for _, value := range environment {
		if strings.ContainsRune(value, 0) {
			return nil, errors.New("invalid console environment")
		}
	}
	env := utf16.Encode([]rune(strings.Join(environment, "\x00") + "\x00\x00"))
	application, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return nil, err
	}
	command := windows.StringToUTF16Ptr(windows.ComposeCommandLine([]string{executable, "clipboard-guard"}))
	startup := windows.StartupInfoEx{StartupInfo: windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{})), Desktop: windows.StringToUTF16Ptr(`winsta0\default`), Flags: windows.STARTF_USESTDHANDLES, StdInput: handles[0], StdOutput: handles[1], StdErr: handles[2]}, ProcThreadAttributeList: attrs.List()}
	var process windows.ProcessInformation
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NO_WINDOW | windows.EXTENDED_STARTUPINFO_PRESENT)
	if err := windows.CreateProcessAsUser(token, application, command, nil, nil, true, flags, &env[0], windows.StringToUTF16Ptr(filepath.Dir(executable)), &startup.StartupInfo, &process); err != nil {
		return nil, err
	}
	job, jobErr := windows.CreateJobObject(nil, nil)
	if jobErr == nil {
		limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
		limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		_, jobErr = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)))
		if jobErr == nil {
			jobErr = windows.AssignProcessToJobObject(job, process.Process)
		}
	}
	if jobErr != nil {
		_ = windows.TerminateProcess(process.Process, 1)
		_ = windows.CloseHandle(process.Process)
		_ = windows.CloseHandle(process.Thread)
		if job != 0 {
			_ = windows.CloseHandle(job)
		}
		return nil, jobErr
	}
	guard.job = job
	_ = windows.CloseHandle(process.Thread)
	guard.process = process.Process
	acks := make(chan clipboardAck, 1)
	guard.acks = acks
	go func() {
		defer close(acks)
		scan := bufio.NewScanner(output)
		scan.Buffer(make([]byte, 1024), 2048)
		for scan.Scan() {
			var ack clipboardAck
			if ec.Decode(scan.Bytes(), &ack) != nil {
				return
			}
			select {
			case acks <- ack:
			default:
				return
			}
		}
	}()
	success = true
	return guard, nil
}

func clipboardConsoleMatches(sid string, session uint32) bool {
	if session == 0 || windows.WTSGetActiveConsoleSessionId() != session {
		return false
	}
	var token windows.Token
	if windows.WTSQueryUserToken(session, &token) != nil {
		return false
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	return err == nil && user.User.Sid.String() == sid
}
