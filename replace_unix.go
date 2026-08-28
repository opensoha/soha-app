//go:build !windows

package main

import "os"

func replaceFile(source string, target string) error {
	return os.Rename(source, target)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
