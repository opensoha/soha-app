package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

var appLog = newAppLogger(os.Stdout)

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

func logErrorType(err error) string {
	return fmt.Sprintf("%T", err)
}
