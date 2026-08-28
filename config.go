package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const (
	configVersion    = 1
	defaultServerURL = "http://127.0.0.1:8080"
)

type storedConfig struct {
	Version            int    `json:"version"`
	ServerURL          string `json:"serverUrl"`
	CredentialsBlocked bool   `json:"credentialsBlocked,omitempty"`
}

type configStore struct {
	path string
	mu   sync.Mutex
}

func appPaths() (configPath string, logDir string, err error) {
	configHome, err := os.UserConfigDir()
	if err != nil {
		return "", "", fmt.Errorf("resolve config directory: %w", err)
	}
	cacheHome, err := os.UserCacheDir()
	if err != nil {
		return "", "", fmt.Errorf("resolve cache directory: %w", err)
	}

	return filepath.Join(configHome, "OpenSoha", "Soha", "config.json"),
		filepath.Join(cacheHome, "OpenSoha", "Soha", "logs"), nil
}

func newConfigStore(path string) *configStore {
	return &configStore{path: path}
}

func (s *configStore) Load() (storedConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := os.Open(s.path)
	if err != nil {
		return storedConfig{}, err
	}
	defer file.Close()

	decoder := json.NewDecoder(io.LimitReader(file, 4097))
	decoder.DisallowUnknownFields()
	var config storedConfig
	if err := decoder.Decode(&config); err != nil {
		return storedConfig{}, fmt.Errorf("decode app config: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return storedConfig{}, err
	}
	if config.Version != configVersion {
		return storedConfig{}, fmt.Errorf("unsupported app config version %d", config.Version)
	}
	normalized, err := normalizeServerURL(config.ServerURL)
	if err != nil {
		return storedConfig{}, err
	}
	config.ServerURL = normalized
	return config, nil
}

func (s *configStore) Save(serverURL string, credentialsBlocked bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	normalized, err := normalizeServerURL(serverURL)
	if err != nil {
		return err
	}
	payload, err := json.MarshalIndent(storedConfig{
		Version:            configVersion,
		ServerURL:          normalized,
		CredentialsBlocked: credentialsBlocked,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode app config: %w", err)
	}
	payload = append(payload, '\n')

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create app config directory: %w", err)
	}
	temporary, err := os.CreateTemp(dir, ".config-*")
	if err != nil {
		return fmt.Errorf("create temporary app config: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure temporary app config: %w", err)
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary app config: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary app config: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary app config: %w", err)
	}
	if err := replaceFile(temporaryPath, s.path); err != nil {
		return fmt.Errorf("replace app config: %w", err)
	}

	return syncDirectory(dir)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("decode trailing app config data: %w", err)
	}
	return errors.New("app config contains multiple JSON values")
}

func normalizeServerURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", errors.New("server URL is invalid")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("server URL must use HTTP or HTTPS")
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return "", errors.New("server URL must include a host")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", errors.New("server URL must not contain credentials, query, or fragment")
	}
	if parsed.EscapedPath() != "" && parsed.EscapedPath() != "/" {
		return "", errors.New("server URL must not contain a path")
	}
	if parsed.Port() != "" {
		port, err := strconv.Atoi(parsed.Port())
		if err != nil || port < 1 || port > 65535 {
			return "", errors.New("server URL contains an invalid port")
		}
	}
	if parsed.Scheme == "http" {
		ip := net.ParseIP(parsed.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return "", errors.New("remote server URLs must use HTTPS")
		}
	}

	parsed.Path = ""
	parsed.RawPath = ""
	return parsed.String(), nil
}
