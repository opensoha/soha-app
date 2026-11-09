//go:build !windows

package endpointservice

import "os"

func syncNativeJournalDirectory(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
