package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	appLogFileName = "soha.log"
	appLogMaxBytes = 5 << 20
)

var appLog = newAppLogger(os.Stderr)

func newAppLogger(writer io.Writer) *slog.Logger {
	handler := slog.NewJSONHandler(writer, &slog.HandlerOptions{
		AddSource: true,
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			switch attr.Key {
			case slog.TimeKey:
				attr.Key = "timestamp"
				attr.Value = slog.TimeValue(attr.Value.Time().UTC())
			case slog.LevelKey:
				attr.Value = slog.StringValue(strings.ToLower(attr.Value.String()))
			case slog.SourceKey:
				if source, ok := attr.Value.Any().(*slog.Source); ok {
					attr.Key = "caller"
					attr.Value = slog.StringValue(fmt.Sprintf("%s:%d", filepath.Base(source.File), source.Line))
				}
			case slog.MessageKey:
				attr.Key = "message"
			}
			return attr
		},
	})
	return slog.New(handler).With("service", "soha-app")
}

func configureAppLogging(logDirectory, version string) (io.Closer, error) {
	writer, err := openRotatingLogWriter(filepath.Join(logDirectory, appLogFileName), appLogMaxBytes)
	if err != nil {
		return nil, err
	}
	appLog = newAppLogger(io.MultiWriter(writer, os.Stderr)).With("app_version", version)
	return writer, nil
}

func logErrorType(err error) string {
	return fmt.Sprintf("%T", err)
}

type rotatingLogWriter struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	file     *os.File
	size     int64
}

func openRotatingLogWriter(path string, maxBytes int64) (*rotatingLogWriter, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("log size limit must be positive")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create app log directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("secure app log directory: %w", err)
	}
	if info, err := os.Stat(path); err == nil && info.Size() >= maxBytes {
		if err := replaceFile(path, path+".1"); err != nil {
			return nil, fmt.Errorf("rotate app log: %w", err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect app log: %w", err)
	}

	file, size, err := openLogFile(path)
	if err != nil {
		return nil, err
	}
	return &rotatingLogWriter{path: path, maxBytes: maxBytes, file: file, size: size}, nil
}

func openLogFile(path string) (*os.File, int64, error) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, 0, fmt.Errorf("open app log: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, 0, fmt.Errorf("secure app log: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, 0, fmt.Errorf("inspect app log: %w", err)
	}
	return file, info.Size(), nil
}

func (writer *rotatingLogWriter) Write(data []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.file == nil {
		return 0, os.ErrClosed
	}
	if writer.size > 0 && writer.size+int64(len(data)) > writer.maxBytes {
		if err := writer.rotate(); err != nil {
			return 0, err
		}
	}
	written, err := writer.file.Write(data)
	writer.size += int64(written)
	return written, err
}

func (writer *rotatingLogWriter) rotate() error {
	if err := writer.file.Close(); err != nil {
		return err
	}
	writer.file = nil
	if err := replaceFile(writer.path, writer.path+".1"); err != nil {
		return err
	}
	file, size, err := openLogFile(writer.path)
	if err != nil {
		return err
	}
	writer.file = file
	writer.size = size
	return nil
}

func (writer *rotatingLogWriter) Close() error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.file == nil {
		return nil
	}
	err := writer.file.Close()
	writer.file = nil
	return err
}
