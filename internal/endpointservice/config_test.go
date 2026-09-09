package endpointservice

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "service.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("LoadConfig() error = nil")
	}
}

func TestConfigRequiresSeparateIngestIdentity(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	controlCA := testRegularFile(t, directory, "control-ca.pem")
	controlCert := testRegularFile(t, directory, "control-cert.pem")
	controlKey := testRegularFile(t, directory, "control-key.pem")
	wireguard := testRegularFile(t, directory, "wireguard.exe")
	config := Config{Version: 1, RuntimeID: "endpoint-1", DeviceID: "device-1", AllowedUserSID: "S-1-5-21-1000", ControlURL: "https://control.example.com", ControlCAFile: controlCA, ControlCertFile: controlCert, ControlKeyFile: controlKey, IngestURL: "https://ingest.example.com", StateDirectory: directory, WireGuardExecutable: wireguard}
	if err := config.Validate(); err == nil {
		t.Fatal("Validate() error = nil")
	}
	config.IngestCAFile = testRegularFile(t, directory, "ingest-ca.pem")
	config.IngestCertFile = testRegularFile(t, directory, "ingest-cert.pem")
	config.IngestKeyFile = testRegularFile(t, directory, "ingest-key.pem")
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigAllowsOnlyLoopbackMihomoControllerWithProtectedSecret(t *testing.T) {
	directory := t.TempDir()
	config := Config{
		Version: 1, RuntimeID: "endpoint-1", DeviceID: "device-1", AllowedUserSID: "S-1-5-21-1000",
		ControlURL: "https://control.example.com", ControlCAFile: testRegularFile(t, directory, "control-ca.pem"),
		ControlCertFile: testRegularFile(t, directory, "control-cert.pem"), ControlKeyFile: testRegularFile(t, directory, "control-key.pem"),
		StateDirectory: directory, WireGuardExecutable: testRegularFile(t, directory, "wireguard.exe"),
		MihomoControllerURL: "http://127.0.0.1:9090", MihomoControllerSecretFile: testRegularFile(t, directory, "mihomo.secret"),
	}
	if err := os.WriteFile(config.MihomoControllerSecretFile, []byte("test-mihomo-controller-secret-123456"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	if secret, err := config.MihomoControllerSecret(); err != nil || secret != "test-mihomo-controller-secret-123456" {
		t.Fatalf("MihomoControllerSecret() = %q, %v", secret, err)
	}
	config.MihomoControllerURL = "http://192.0.2.10:9090"
	if err := config.Validate(); err == nil {
		t.Fatal("non-loopback mihomo controller was accepted")
	}
}

func TestValidateClientIdentity(t *testing.T) {
	t.Parallel()
	identity, _ := url.Parse("spiffe://opensoha.local/network-control/endpoint/endpoint-1")
	if err := validateClientIdentity([]*url.URL{identity}, "network-control", "endpoint-1"); err != nil {
		t.Fatal(err)
	}
	wrong, _ := url.Parse("spiffe://opensoha.local/network-ingest/endpoint/endpoint-1")
	if err := validateClientIdentity([]*url.URL{wrong}, "network-control", "endpoint-1"); err == nil {
		t.Fatal("validateClientIdentity() error = nil")
	}
}

func TestEnrollmentMarkerTracksEnrollmentID(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "enrollment")
	if completed, err := EnrollmentCompleted(path, "enrollment-1"); err != nil || completed {
		t.Fatalf("EnrollmentCompleted() = %v, %v", completed, err)
	}
	if err := RecordEnrollment(path, "enrollment-1"); err != nil {
		t.Fatal(err)
	}
	if completed, err := EnrollmentCompleted(path, "enrollment-1"); err != nil || !completed {
		t.Fatalf("EnrollmentCompleted() = %v, %v", completed, err)
	}
	if completed, err := EnrollmentCompleted(path, "enrollment-2"); err != nil || completed {
		t.Fatalf("EnrollmentCompleted(new ID) = %v, %v", completed, err)
	}
}

func testRegularFile(t *testing.T, directory, name string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
