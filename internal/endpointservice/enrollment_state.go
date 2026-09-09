package endpointservice

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func EnrollmentCompleted(path, enrollmentID string) (bool, error) {
	raw, err := readFileBounded(path, 256, false)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read endpoint enrollment marker: %w", err)
	}
	stored := strings.TrimSpace(string(raw))
	if !identifierPattern.MatchString(stored) {
		return false, errors.New("endpoint enrollment marker is invalid")
	}
	return stored == enrollmentID, nil
}

func RecordEnrollment(path, enrollmentID string) error {
	if !filepath.IsAbs(path) || !identifierPattern.MatchString(enrollmentID) {
		return errors.New("endpoint enrollment marker parameters are invalid")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err := secureStateDirectory(directory); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".enrollment-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.WriteString(enrollmentID + "\n"); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(temporaryPath, path)
}
