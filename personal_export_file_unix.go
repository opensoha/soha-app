//go:build !windows

package main

import "os"

func privatePersonalExportFile() (*os.File, error) {
	file, err := os.CreateTemp("", "soha-app-personal-export-*")
	if err != nil {
		return nil, err
	}
	if err := os.Remove(file.Name()); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return nil, err
	}
	return file, nil
}
