//go:build darwin

package endpointservice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

const DarwinStateDirectory = "/var/db/opensoha/network-service"
const DarwinSocketPath = "/var/run/opensoha/network-service.sock"

type darwinIPCListener struct {
	*net.UnixListener
	uid  uint32
	lock *os.File
	once sync.Once
}

func ListenIPC(identity string) (net.Listener, error) {
	uid, err := strconv.ParseUint(identity, 10, 32)
	if err != nil || uid == 0 || os.Geteuid() != 0 {
		return nil, errors.New("macOS network service requires root and an explicit user UID")
	}
	return listenDarwinIPC(DarwinSocketPath, uint32(uid))
}

func listenDarwinIPC(path string, uid uint32) (net.Listener, error) {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return nil, err
	}
	if err := ownedDarwinPath(directory, os.Geteuid(), false); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, errors.New("network service is already running")
	}
	fail := func(err error) (net.Listener, error) { _ = lock.Close(); return nil, err }
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fail(errors.New("refuse to replace a non-socket IPC path"))
		}
		if err := ownedDarwinPath(path, os.Geteuid(), true); err != nil {
			return fail(err)
		}
		if err := os.Remove(path); err != nil {
			return fail(err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fail(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return fail(err)
	}
	listener.SetUnlinkOnClose(true)
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return fail(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(path, int(uid), -1); err != nil {
			_ = listener.Close()
			return fail(err)
		}
	}
	return &darwinIPCListener{UnixListener: listener, uid: uid, lock: lock}, nil
}

func (l *darwinIPCListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		uid, err := darwinPeerUID(connection)
		if err == nil && (uid == 0 || uid == l.uid) {
			return connection, nil
		}
		_ = connection.Close()
	}
}

func (l *darwinIPCListener) Close() error {
	var result error
	l.once.Do(func() { result = errors.Join(l.UnixListener.Close(), l.lock.Close()) })
	return result
}

func dialIPC(ctx context.Context) (net.Conn, error) {
	if err := ownedDarwinPath(filepath.Dir(DarwinSocketPath), 0, false); err != nil {
		return nil, err
	}
	info, err := os.Lstat(DarwinSocketPath)
	if err != nil {
		return nil, fmt.Errorf("macOS network service is not installed or running: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("unsafe network service socket")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", DarwinSocketPath)
	if err != nil {
		return nil, err
	}
	peer, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return nil, errors.New("invalid network service transport")
	}
	uid, err := darwinPeerUID(peer)
	if err != nil || uid != 0 {
		_ = connection.Close()
		return nil, errors.New("network service is not root-owned")
	}
	return connection, nil
}

func darwinPeerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credentials *unix.Xucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, socketErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if socketErr != nil {
		return 0, socketErr
	}
	if credentials == nil {
		return 0, errors.New("missing IPC peer credentials")
	}
	return credentials.Uid, nil
}

func ownedDarwinPath(path string, uid int, socket bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("network service path is writable by another user")
	}
	// Socket ownership is assigned to the allowed desktop user; its parent and
	// the authenticated server process, not the socket inode UID, establish trust.
	if !socket && (int(stat.Uid) != uid || !info.IsDir()) {
		return errors.New("network service directory has an unexpected owner")
	}
	return nil
}
