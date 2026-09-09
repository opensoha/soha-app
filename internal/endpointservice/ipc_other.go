//go:build !windows

package endpointservice

import (
	"context"
	"net"
)

func ListenIPC(string) (net.Listener, error) { return nil, ErrIPCUnsupported }

func dialIPC(context.Context) (net.Conn, error) { return nil, ErrIPCUnsupported }
