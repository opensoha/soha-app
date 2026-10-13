//go:build windows

package main

import (
	"crypto/rand"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Delete-on-close also removes the archive after a process crash on Windows.
func privatePersonalExportFile() (*os.File, error) {
	path := filepath.Join(os.TempDir(), "soha-app-personal-export-"+rand.Text())
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_TEMPORARY|windows.FILE_FLAG_DELETE_ON_CLOSE, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}
