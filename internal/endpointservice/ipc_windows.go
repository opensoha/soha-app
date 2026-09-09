//go:build windows

package endpointservice

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func ListenIPC(allowedUserSID string) (net.Listener, error) {
	sid, err := windows.StringToSid(allowedUserSID)
	if err != nil || sid.String() != allowedUserSID {
		return nil, errors.New("allowed Windows user SID is invalid")
	}
	securityDescriptor := fmt.Sprintf("O:SYG:SYD:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;%s)", allowedUserSID)
	return winio.ListenPipe(PipeName, &winio.PipeConfig{SecurityDescriptor: securityDescriptor, MessageMode: true, InputBufferSize: maxIPCMessageBytes, OutputBufferSize: maxIPCMessageBytes})
}

func dialIPC(ctx context.Context) (net.Conn, error) {
	return winio.DialPipeContext(ctx, PipeName)
}
