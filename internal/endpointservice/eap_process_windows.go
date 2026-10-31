//go:build windows

package endpointservice

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

func runEAPUserProcess(ctx context.Context, executable string, token windows.Token, environment []string, request []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	input, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer input.Close()
	defer writer.Close()
	reader, output, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	defer output.Close()
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return nil, err
	}
	defer null.Close()
	var handles [3]windows.Handle
	defer func() {
		for _, handle := range handles {
			if handle != 0 {
				_ = windows.CloseHandle(handle)
			}
		}
	}()
	for index, file := range []*os.File{input, output, null} {
		if err := windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(file.Fd()), windows.CurrentProcess(), &handles[index], 0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
			return nil, err
		}
	}
	attributes, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return nil, err
	}
	defer attributes.Delete()
	if err := attributes.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), unsafe.Sizeof(handles)); err != nil {
		return nil, err
	}
	for _, entry := range environment {
		if strings.ContainsRune(entry, 0) {
			return nil, errors.New("EAP user environment contains a null character")
		}
	}
	env := utf16.Encode([]rune(strings.Join(environment, "\x00") + "\x00\x00"))
	application, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return nil, err
	}
	commandLine := windows.StringToUTF16Ptr(windows.ComposeCommandLine([]string{executable, "eap-user-helper"}))
	directory := windows.StringToUTF16Ptr(filepath.Dir(executable))
	// Protected root trust consent must appear on the enrolled user's interactive desktop.
	startup := windows.StartupInfoEx{StartupInfo: windows.StartupInfo{
		Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{})), Desktop: windows.StringToUTF16Ptr(`winsta0\default`),
		Flags: windows.STARTF_USESTDHANDLES, StdInput: handles[0], StdOutput: handles[1], StdErr: handles[2],
	}, ProcThreadAttributeList: attributes.List()}
	var process windows.ProcessInformation
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NO_WINDOW | windows.EXTENDED_STARTUPINFO_PRESENT)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := windows.CreateProcessAsUser(token, application, commandLine, nil, nil, true, flags, &env[0], directory, &startup.StartupInfo, &process); err != nil {
		return nil, err
	}
	defer windows.CloseHandle(process.Process)
	_ = windows.CloseHandle(process.Thread)
	for index, handle := range handles {
		_ = windows.CloseHandle(handle)
		handles[index] = 0
	}
	_ = input.Close()
	_ = output.Close()
	writeDone, readDone := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := io.Copy(writer, bytes.NewReader(request))
		writeDone <- errors.Join(err, writer.Close())
	}()
	result := &eapLimitedOutput{limit: 256 << 10}
	go func() {
		_, err := io.Copy(result, reader)
		if err != nil {
			_ = windows.TerminateProcess(process.Process, 1)
		}
		readDone <- err
	}()
	for {
		var event uint32
		event, err = windows.WaitForSingleObject(process.Process, 100)
		if err != nil || event == windows.WAIT_OBJECT_0 {
			break
		}
		if ctx.Err() != nil {
			terminateErr := windows.TerminateProcess(process.Process, 1)
			event, waitErr := windows.WaitForSingleObject(process.Process, 2000)
			err = errors.Join(ctx.Err(), terminateErr, waitErr)
			if event != windows.WAIT_OBJECT_0 {
				err = errors.Join(err, errors.New("EAP helper termination was not confirmed"))
			}
			break
		}
	}
	if err == nil {
		var code uint32
		err = windows.GetExitCodeProcess(process.Process, &code)
		if err == nil && code != 0 {
			err = errors.New("EAP user helper failed")
		}
	}
	if err != nil {
		_ = reader.Close()
		_ = writer.Close()
	}
	select {
	case writeErr := <-writeDone:
		err = errors.Join(err, writeErr)
	case <-ctx.Done():
		_ = writer.Close()
		err = errors.Join(err, ctx.Err(), <-writeDone)
	}
	select {
	case readErr := <-readDone:
		err = errors.Join(err, readErr)
	case <-ctx.Done():
		_ = reader.Close()
		err = errors.Join(err, ctx.Err(), <-readDone)
	}
	return result.Bytes(), err
}
