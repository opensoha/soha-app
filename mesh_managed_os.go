package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const (
	managedOSVersionTimeout  = 3 * time.Second
	managedOSVersionMaxBytes = 128
	managedOSVersionMaxLen   = 64
)

var (
	managedOSProductVersionPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)
	managedOSBuildVersionPattern   = regexp.MustCompile(`^[A-Za-z0-9]+$`)
)

func managedOSVersionArg(field string) (string, error) {
	switch field {
	case "productVersion":
		return "-productVersion", nil
	case "buildVersion":
		return "-buildVersion", nil
	default:
		return "", fmt.Errorf("unsupported os version field %q", field)
	}
}

func managedOSVersionValue(field, value string) (string, error) {
	if value == "" || len(value) > managedOSVersionMaxLen {
		return "", fmt.Errorf("unexpected os version output for %q", field)
	}
	switch field {
	case "productVersion":
		if !managedOSProductVersionPattern.MatchString(value) {
			return "", fmt.Errorf("unexpected product version output")
		}
	case "buildVersion":
		if !managedOSBuildVersionPattern.MatchString(value) {
			return "", fmt.Errorf("unexpected build version output")
		}
	default:
		return "", fmt.Errorf("unsupported os version field %q", field)
	}
	return value, nil
}

func runManagedOSVersion(ctx context.Context, field string) (string, error) {
	if runtime.GOOS != "darwin" {
		return "", errors.New("os version readback is only supported on macOS")
	}
	arg, err := managedOSVersionArg(field)
	if err != nil {
		return "", err
	}
	runCtx, cancel := context.WithTimeout(ctx, managedOSVersionTimeout)
	defer cancel()
	command := exec.CommandContext(runCtx, "/usr/bin/sw_vers", arg)
	command.Dir = "/"
	command.Env = []string{"LANG=C", "LC_ALL=C"}
	stdout := &managedOSLimitWriter{limit: managedOSVersionMaxBytes}
	stderr := &managedOSLimitWriter{limit: managedOSVersionMaxBytes}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return "", err
	}
	return managedOSVersionValue(field, strings.TrimSpace(string(stdout.buf)))
}

type managedOSLimitWriter struct {
	limit int
	buf   []byte
}

func (writer *managedOSLimitWriter) Write(data []byte) (int, error) {
	if len(writer.buf)+len(data) > writer.limit {
		return 0, fmt.Errorf("os version output exceeds %d bytes", writer.limit)
	}
	writer.buf = append(writer.buf, data...)
	return len(data), nil
}
