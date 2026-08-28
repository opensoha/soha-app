package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestAppLoggerWritesCanonicalJSON(t *testing.T) {
	var output bytes.Buffer
	newAppLogger(&output).Info("application started", "component", "startup", "event", "app.started")

	var entry map[string]any
	if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
		t.Fatalf("decode log entry: %v", err)
	}
	if entry["level"] != "info" || entry["service"] != "soha-app" || entry["component"] != "startup" || entry["event"] != "app.started" || entry["message"] != "application started" {
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
