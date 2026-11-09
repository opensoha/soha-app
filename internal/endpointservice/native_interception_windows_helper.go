//go:build windows

package endpointservice

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"runtime"
	"time"
	"unsafe"
)

type winNativeHelperRequest struct {
	SID            string
	Session        uint32
	Field          string
	Write, Restore bool
	Before, After  nativeValue
}
type winNativeHelperResponse struct{ Value nativeValue }

func winNativeCallHelper(ctx context.Context, session nativeSession, request winNativeHelperRequest) (winNativeHelperResponse, error) {
	s, ok := session.(*winNativeSession)
	if !ok {
		return winNativeHelperResponse{}, errors.New("untrusted native session")
	}
	if err := s.Validate(ctx, request.Restore || !request.Write); err != nil {
		return winNativeHelperResponse{}, err
	}
	s.mu.Lock()
	var token windows.Token
	err := windows.DuplicateTokenEx(s.token, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &token)
	s.mu.Unlock()
	if err != nil {
		return winNativeHelperResponse{}, err
	}
	defer token.Close()
	request.SID = s.owner.UserID
	request.Session = s.session
	executable, lock, err := trustedEAPHelperExecutable()
	if err != nil {
		return winNativeHelperResponse{}, err
	}
	defer windows.CloseHandle(lock)
	environment, err := token.Environ(false)
	if err != nil {
		return winNativeHelperResponse{}, err
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return winNativeHelperResponse{}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	output, err := runNativeUserProcess(callCtx, executable, token, environment, raw)
	if err != nil {
		return winNativeHelperResponse{}, errors.New("native user helper result unknown")
	}
	var result winNativeHelperResponse
	if err := decodeStrict(output, &result); err != nil {
		return result, errors.New("invalid native user helper receipt")
	}
	if err := s.Validate(ctx, request.Restore || !request.Write); err != nil {
		return result, err
	}
	return result, nil
}

// RunNativeInterceptionUserHelper must run before service dispatch with os.Args[1:].
// Only inherited stdin/stdout pipes carry the bounded typed protocol; argv contains no values.
func RunNativeInterceptionUserHelper(args []string) (bool, error) {
	if len(args) != 1 || args[0] != "native-user-helper" {
		return false, nil
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 256<<10+1))
	if err != nil || len(raw) > 256<<10 {
		return true, errors.New("native helper request exceeds bound")
	}
	var request winNativeHelperRequest
	if err := decodeStrict(raw, &request); err != nil {
		return true, errors.New("invalid native helper request")
	}
	validate := func() error {
		token := windows.GetCurrentProcessToken()
		u, err := token.GetTokenUser()
		if err != nil || u.User.Sid.IsWellKnown(windows.WinLocalSystemSid) || u.User.Sid.String() != request.SID {
			return errors.New("native helper user differs")
		}
		var session uint32
		var size uint32
		if err := windows.GetTokenInformation(token, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), 4, &size); err != nil || session != request.Session {
			return errors.New("native helper session differs")
		}
		if request.Write && !request.Restore && session != windows.WTSGetActiveConsoleSessionId() {
			return errors.New("native helper desktop changed")
		}
		return nil
	}
	if err := validate(); err != nil {
		return true, err
	}
	current, err := winNativeProxyGet(request.Field)
	if err != nil {
		return true, err
	}
	if request.Write {
		c := nativeChange{ID: "helper", Kind: "proxy", Field: request.Field, Before: request.Before, After: request.After}
		if err := winNativeValidate(c); err != nil {
			return true, err
		}
		if !winNativeEqual(current, request.Before) {
			return true, errors.New("proxy setting changed externally")
		}
		if !request.After.Present && !request.Restore {
			return true, errors.New("WinINet property cannot be absent")
		}
		if err := validate(); err != nil {
			return true, err
		}
		if err := winNativeProxySet(request.Field, request.After); err != nil {
			return true, err
		}
		if err := validate(); err != nil {
			return true, err
		}
		current, err = winNativeProxyGet(request.Field)
		if err != nil {
			return true, err
		}
		if !winNativeEqual(current, request.After) {
			return true, errors.New("proxy write readback differs")
		}
	}
	return true, json.NewEncoder(os.Stdout).Encode(winNativeHelperResponse{Value: current})
}

var winNativeWininet = windows.NewLazySystemDLL("wininet.dll")

type winNativeOption struct {
	Option uint32
	Value  uint64
}
type winNativeOptionList struct {
	Size         uint32
	Connection   *uint16
	Count, Error uint32
	Options      *winNativeOption
}

func winNativeOptionID(field string) uint32 {
	switch field {
	case "flags":
		return 1
	case "server":
		return 2
	case "bypass":
		return 3
	case "pac":
		return 4
	}
	return 0
}
func winNativeProxyGet(field string) (nativeValue, error) {
	id := winNativeOptionID(field)
	if id == 0 {
		return nativeValue{}, errors.New("unknown proxy field")
	}
	option := winNativeOption{Option: id}
	if field == "flags" {
		option.Option = 10
	}
	list := winNativeOptionList{Count: 1, Options: &option}
	list.Size = uint32(unsafe.Sizeof(list))
	size := list.Size
	r, _, err := winNativeWininet.NewProc("InternetQueryOptionW").Call(0, 75, uintptr(unsafe.Pointer(&list)), uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return nativeValue{}, err
	}
	if id != 1 && option.Value == 0 {
		return nativeValue{}, nil
	}
	value := &nativeProxyValue{}
	if id == 1 {
		value.Number = uint32(option.Value)
	} else if option.Value != 0 {
		ptr := (*uint16)(unsafe.Pointer(uintptr(option.Value)))
		defer windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalFree").Call(uintptr(option.Value))
		text, err := winNativeBoundedUTF16(ptr)
		if err != nil {
			return nativeValue{}, err
		}
		value.Text = text
	}
	return nativeValue{Present: true, Proxy: value}, nil
}
func winNativeProxySet(field string, value nativeValue) error {
	id := winNativeOptionID(field)
	if id == 0 || value.Present && value.Proxy == nil {
		return errors.New("unknown proxy property")
	}
	option := winNativeOption{Option: id}
	var text *uint16
	if !value.Present {
		option.Value = 0
	} else if id == 1 {
		option.Value = uint64(value.Proxy.Number)
	} else {
		var err error
		text, err = windows.UTF16PtrFromString(value.Proxy.Text)
		if err != nil {
			return err
		}
		option.Value = uint64(uintptr(unsafe.Pointer(text)))
	}
	list := winNativeOptionList{Count: 1, Options: &option}
	list.Size = uint32(unsafe.Sizeof(list))
	r, _, err := winNativeWininet.NewProc("InternetSetOptionW").Call(0, 75, uintptr(unsafe.Pointer(&list)), uintptr(list.Size))
	if r == 0 {
		return err
	}
	for _, o := range []uintptr{39, 37} {
		r, _, err = winNativeWininet.NewProc("InternetSetOptionW").Call(0, o, 0, 0)
		if r == 0 {
			return err
		}
	}
	// Keep the UTF16 allocation alive through the synchronous native call.
	runtime.KeepAlive(text)
	return nil
}
func winNativeBoundedUTF16(p *uint16) (string, error) {
	if p == nil {
		return "", nil
	}
	v := unsafe.Slice(p, 32769)
	for i, c := range v {
		if c == 0 {
			return windows.UTF16ToString(v[:i]), nil
		}
	}
	return "", errors.New("native string exceeds bound")
}
