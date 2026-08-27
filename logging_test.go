package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotatingLogWriterUsesSecureFilesAndOneBackup(t *testing.T) {
	logDirectory := filepath.Join(t.TempDir(), "logs")
	logPath := filepath.Join(logDirectory, appLogFileName)
	writer, err := openRotatingLogWriter(logPath, 24)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("first log entry\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("second log entry\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	current, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := os.ReadFile(logPath + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(current), "second log entry") || !strings.Contains(string(backup), "first log entry") {
		t.Fatalf("rotated logs current=%q backup=%q", current, backup)
	}
	for _, path := range []string{logDirectory, logPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("permissions for %s = %o, want no group/world access", path, info.Mode().Perm())
		}
	}
}
