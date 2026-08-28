package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigureAppLoggingWritesCanonicalJSON(t *testing.T) {
	previousLogger := appLog
	defer func() { appLog = previousLogger }()

	logDirectory := t.TempDir()
	closer, err := configureAppLogging(logDirectory, "test-version")
	if err != nil {
		t.Fatal(err)
	}
	appLog.Info("application started", "component", "startup", "event", "app.started")
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := os.ReadFile(filepath.Join(logDirectory, appLogFileName))
	if err != nil {
		t.Fatal(err)
	}

	var entry map[string]any
	if err := json.Unmarshal(output, &entry); err != nil {
		t.Fatalf("decode log entry: %v", err)
	}
	if entry["level"] != "info" || entry["service"] != "soha-app" || entry["app_version"] != "test-version" || entry["component"] != "startup" || entry["event"] != "app.started" || entry["message"] != "application started" {
		t.Fatalf("unexpected log entry: %#v", entry)
	}
	timestamp, ok := entry["timestamp"].(string)
	if !ok {
		t.Fatalf("timestamp = %#v", entry["timestamp"])
	}
	if parsed, err := time.Parse(time.RFC3339Nano, timestamp); err != nil || parsed.Location() != time.UTC {
		t.Fatalf("timestamp = %q, error = %v", timestamp, err)
	}
	if entry["caller"] == "" {
		t.Fatalf("caller = %#v", entry["caller"])
	}
}

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
