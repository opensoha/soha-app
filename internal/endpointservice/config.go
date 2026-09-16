package endpointservice

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	serviceConfigVersion  = 1
	maxServiceConfigBytes = 64 << 10
	maxPEMBytes           = 1 << 20
	requestTimeout        = 10 * time.Second
)

type Config struct {
	Version                    int     `json:"version"`
	RuntimeID                  string  `json:"runtimeId"`
	DeviceID                   string  `json:"deviceId"`
	AllowedUserSID             string  `json:"allowedUserSid,omitempty"`
	AllowedUserUID             *uint32 `json:"allowedUserUid,omitempty"`
	ControlURL                 string  `json:"controlUrl"`
	ControlCAFile              string  `json:"controlCaFile"`
	ControlCertFile            string  `json:"controlCertFile"`
	ControlKeyFile             string  `json:"controlKeyFile"`
	ControlServerName          string  `json:"controlServerName,omitempty"`
	IngestURL                  string  `json:"ingestUrl,omitempty"`
	IngestCAFile               string  `json:"ingestCaFile,omitempty"`
	IngestCertFile             string  `json:"ingestCertFile,omitempty"`
	IngestKeyFile              string  `json:"ingestKeyFile,omitempty"`
	IngestServerName           string  `json:"ingestServerName,omitempty"`
	StateDirectory             string  `json:"stateDirectory"`
	WireGuardExecutable        string  `json:"wireGuardExecutable"`
	MihomoControllerURL        string  `json:"mihomoControllerUrl,omitempty"`
	MihomoControllerSecretFile string  `json:"mihomoControllerSecretFile,omitempty"`
	EnrollmentID               string  `json:"enrollmentId,omitempty"`
	EnrollmentChallengeID      string  `json:"enrollmentChallengeId,omitempty"`
	EnrollmentTokenFile        string  `json:"enrollmentTokenFile,omitempty"`
}

func LoadConfig(path string) (Config, error) {
	if !filepath.IsAbs(path) {
		return Config{}, errors.New("endpoint service config path must be absolute")
	}
	raw, err := readFileBounded(path, maxServiceConfigBytes, false)
	if err != nil {
		return Config{}, fmt.Errorf("read endpoint service config: %w", err)
	}
	var config Config
	if err := decodeStrict(raw, &config); err != nil {
		return Config{}, fmt.Errorf("decode endpoint service config: %w", err)
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (config Config) Validate() error {
	if config.Version != serviceConfigVersion || !identifierPattern.MatchString(config.RuntimeID) || !identifierPattern.MatchString(config.DeviceID) || !validServiceIdentity(config) {
		return errors.New("endpoint service version or identity is invalid")
	}
	if _, err := runtimeOrigin(config.ControlURL); err != nil {
		return err
	}
	for name, path := range map[string]string{"control CA": config.ControlCAFile, "control certificate": config.ControlCertFile, "control key": config.ControlKeyFile} {
		if err := regularFile(path); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if config.AllowedUserUID == nil {
		if err := regularFile(config.WireGuardExecutable); err != nil {
			return fmt.Errorf("WireGuard executable: %w", err)
		}
	} else if config.WireGuardExecutable != "" {
		return errors.New("macOS service uses the bundled WireGuard runtime")
	}
	if !filepath.IsAbs(config.StateDirectory) {
		return errors.New("endpoint state directory must be absolute")
	}
	if (config.MihomoControllerURL == "") != (config.MihomoControllerSecretFile == "") {
		return errors.New("mihomo controller URL and secret file must be configured together")
	}
	if config.MihomoControllerURL != "" {
		if _, _, err := mihomoOrigin(config.MihomoControllerURL); err != nil {
			return err
		}
		if !filepath.IsAbs(config.MihomoControllerSecretFile) || filepath.Clean(filepath.Dir(config.MihomoControllerSecretFile)) != filepath.Clean(config.StateDirectory) {
			return errors.New("mihomo controller secret must be a file in the protected state directory")
		}
		if _, err := config.MihomoControllerSecret(); err != nil {
			return err
		}
	}
	ingestFiles := []string{config.IngestURL, config.IngestCAFile, config.IngestCertFile, config.IngestKeyFile}
	configured := 0
	for _, value := range ingestFiles {
		if value != "" {
			configured++
		}
	}
	if configured != 0 && configured != len(ingestFiles) || configured == 0 && config.IngestServerName != "" {
		return errors.New("network ingest URL and separately scoped TLS files must be configured together")
	}
	if configured != 0 {
		if _, err := runtimeOrigin(config.IngestURL); err != nil {
			return err
		}
		for name, path := range map[string]string{"ingest CA": config.IngestCAFile, "ingest certificate": config.IngestCertFile, "ingest key": config.IngestKeyFile} {
			if err := regularFile(path); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	enrollment := []string{config.EnrollmentID, config.EnrollmentChallengeID, config.EnrollmentTokenFile}
	configured = 0
	for _, value := range enrollment {
		if value != "" {
			configured++
		}
	}
	if configured != 0 && configured != len(enrollment) {
		return errors.New("endpoint enrollment ID, challenge ID, and token file must be configured together")
	}
	if configured != 0 {
		if !identifierPattern.MatchString(config.EnrollmentID) || !identifierPattern.MatchString(config.EnrollmentChallengeID) {
			return errors.New("endpoint enrollment identifiers are invalid")
		}
		if !filepath.IsAbs(config.EnrollmentTokenFile) || filepath.Clean(filepath.Dir(config.EnrollmentTokenFile)) != filepath.Clean(config.StateDirectory) {
			return errors.New("endpoint enrollment token must be a file in the protected state directory")
		}
	}
	return nil
}

func validSID(value string) bool {
	if len(value) < 7 || len(value) > 184 || !strings.HasPrefix(value, "S-") {
		return false
	}
	for _, character := range value[2:] {
		if (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return !strings.HasSuffix(value, "-") && !strings.Contains(value, "--")
}

func (config Config) PrivateKeyPath() string {
	if config.AllowedUserUID != nil {
		return filepath.Join(config.StateDirectory, "wireguard.key")
	}
	return filepath.Join(config.StateDirectory, "wireguard.key.dpapi")
}

func (config Config) TunnelConfigPath() string {
	return filepath.Join(config.StateDirectory, endpointInterfaceName+".conf.dpapi")
}

func (config Config) EnrollmentMarkerPath() string {
	return filepath.Join(config.StateDirectory, "enrollment")
}

func (config Config) MihomoAppStatePath() string {
	if config.AllowedUserUID != nil {
		return filepath.Join(config.StateDirectory, "mihomo-app.json")
	}
	return filepath.Join(config.StateDirectory, "mihomo-app.dpapi")
}

func (config Config) MihomoConfigured() bool {
	return config.MihomoControllerURL != "" && config.MihomoControllerSecretFile != ""
}

func (config Config) MihomoControllerSecret() (string, error) {
	if !config.MihomoConfigured() {
		return "", errors.New("mihomo controller is not configured")
	}
	raw, err := readFileBounded(config.MihomoControllerSecretFile, 4096, true)
	if err != nil {
		return "", fmt.Errorf("read mihomo controller secret: %w", err)
	}
	defer clear(raw)
	secret := strings.TrimSpace(string(raw))
	if len(secret) < 32 || len(secret) > 4096 || strings.ContainsAny(secret, "\r\n\t ") {
		return "", errors.New("mihomo controller secret is invalid")
	}
	return secret, nil
}

func mihomoOrigin(raw string) (string, int, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", 0, errors.New("mihomo controller must be a loopback HTTP origin")
	}
	address, err := netip.ParseAddr(parsed.Hostname())
	if err != nil || !address.IsLoopback() {
		return "", 0, errors.New("mihomo controller must use a loopback IP address")
	}
	_, rawPort, err := net.SplitHostPort(parsed.Host)
	port, portErr := strconv.Atoi(rawPort)
	if err != nil || portErr != nil || port < 1 || port > 65535 {
		return "", 0, errors.New("mihomo controller must include a valid port")
	}
	return strings.TrimRight(parsed.String(), "/"), port, nil
}

func (config Config) ControlHTTPClient() (*http.Client, string, error) {
	client, certificate, err := newMTLSClient(config.ControlCertFile, config.ControlKeyFile, config.ControlCAFile, config.ControlServerName, "network-control", config.RuntimeID)
	if err != nil {
		return nil, "", err
	}
	publicKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("marshal endpoint certificate public key: %w", err)
	}
	return client, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKey})), nil
}

func (config Config) IngestHTTPClient() (*http.Client, error) {
	if config.IngestURL == "" {
		return nil, nil
	}
	client, _, err := newMTLSClient(config.IngestCertFile, config.IngestKeyFile, config.IngestCAFile, config.IngestServerName, "network-ingest", config.RuntimeID)
	return client, err
}

func (config Config) Enrollment(wireGuardPublicKey, devicePublicKey, clientVersion string) (EnrollmentInput, error) {
	if config.EnrollmentID == "" {
		return EnrollmentInput{}, errors.New("endpoint enrollment is not configured")
	}
	if _, err := wgtypes.ParseKey(wireGuardPublicKey); err != nil {
		return EnrollmentInput{}, errors.New("endpoint WireGuard public key is invalid")
	}
	raw, err := readFileBounded(config.EnrollmentTokenFile, 4096, true)
	if err != nil {
		return EnrollmentInput{}, fmt.Errorf("read endpoint enrollment token: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if len(token) < 32 || len(token) > 4096 || strings.ContainsAny(token, "\r\n\t ") {
		return EnrollmentInput{}, errors.New("endpoint enrollment token is invalid")
	}
	return EnrollmentInput{EnrollmentID: config.EnrollmentID, ChallengeID: config.EnrollmentChallengeID, DeviceID: config.DeviceID, DevicePublicKey: devicePublicKey, WireGuardPublicKey: wireGuardPublicKey, ClientVersion: clientVersion, Token: token}, nil
}

func newMTLSClient(certFile, keyFile, caFile, serverName, scope, runtimeID string) (*http.Client, *x509.Certificate, error) {
	certificatePEM, err := readFileBounded(certFile, maxPEMBytes, false)
	if err != nil {
		return nil, nil, fmt.Errorf("read client certificate: %w", err)
	}
	keyPEM, err := readFileBounded(keyFile, maxPEMBytes, true)
	if err != nil {
		return nil, nil, fmt.Errorf("read client key: %w", err)
	}
	defer clear(keyPEM)
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, nil, errors.New("load endpoint client certificate and key")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("parse endpoint client certificate: %w", err)
	}
	if err := validateClientIdentity(leaf.URIs, scope, runtimeID); err != nil {
		return nil, nil, err
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, nil, errors.New("endpoint client certificate is not currently valid")
	}
	caPEM, err := readFileBounded(caFile, maxPEMBytes, false)
	if err != nil {
		return nil, nil, fmt.Errorf("read server CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, nil, errors.New("server CA file contains no certificates")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{certificate}, ServerName: strings.TrimSpace(serverName)}
	return &http.Client{Transport: transport, Timeout: requestTimeout, CheckRedirect: rejectRedirect}, leaf, nil
}

func validateClientIdentity(uris []*url.URL, scope, runtimeID string) error {
	var path []string
	matches := 0
	for _, identity := range uris {
		if identity == nil || identity.Scheme != "spiffe" || identity.Host != "opensoha.local" {
			continue
		}
		matches++
		path = strings.Split(strings.Trim(identity.EscapedPath(), "/"), "/")
	}
	if matches != 1 || len(path) != 3 || path[0] != scope || path[1] != "endpoint" || path[2] != runtimeID {
		return fmt.Errorf("client certificate identity must be spiffe://opensoha.local/%s/endpoint/%s", scope, runtimeID)
	}
	return nil
}

func readFileBounded(path string, limit int64, secret bool) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("file path must be absolute")
	}
	entry, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if entry.Mode()&os.ModeSymlink != 0 || !entry.Mode().IsRegular() || entry.Size() > limit {
		return nil, errors.New("path must be a bounded regular file")
	}
	if secret {
		if err := secureSecretFile(path, entry); err != nil {
			return nil, err
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(entry, opened) {
		return nil, errors.New("file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("file exceeded the safe limit")
	}
	return raw, nil
}

func regularFile(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("file path must be absolute")
	}
	entry, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if entry.Mode()&os.ModeSymlink != 0 || !entry.Mode().IsRegular() {
		return errors.New("path must be a regular file and not a symlink")
	}
	return nil
}

func validServiceIdentity(config Config) bool {
	if config.AllowedUserUID != nil {
		return *config.AllowedUserUID > 0 && *config.AllowedUserUID <= 2147483647 && config.AllowedUserSID == ""
	}
	return validSID(config.AllowedUserSID)
}

func (config Config) IPCIdentity() string {
	if config.AllowedUserUID != nil {
		return strconv.FormatUint(uint64(*config.AllowedUserUID), 10)
	}
	return config.AllowedUserSID
}
