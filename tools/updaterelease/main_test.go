package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRepositoryVersionMetadata(t *testing.T) {
	if err := checkVersionFiles(filepath.Join("..", ".."), "0.2.0"); err != nil {
		t.Fatal(err)
	}
}

func TestBuildAndVerifyRelease(t *testing.T) {
	directory := t.TempDir()
	writeTestArtifact(t, directory, "soha-app-v0.2.0-windows-amd64.exe", bytes.Repeat([]byte("new executable"), 512))
	writeTestArtifact(t, directory, "soha-app-v0.2.0-windows-amd64-installer.exe", []byte("installer"))
	writeTestArtifact(t, directory, "soha-app-service-v0.2.0-windows-amd64.exe", []byte("service"))
	writeTestArtifact(t, directory, "soha-app-v0.2.0-linux-amd64.deb", []byte("deb"))
	writeTestArtifact(t, directory, "soha-app-v0.2.0-darwin-arm64.dmg", []byte("dmg"))
	writeTestAppZIP(t, filepath.Join(directory, "soha-app-v0.2.0-darwin-arm64.zip"))

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	publishedAt := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	if err := buildRelease(directory, "0.2.0", "stable", "Release notes", publishedAt, privateKey, nil); err != nil {
		t.Fatal(err)
	}
	if err := verifyRelease(directory, publicKey, ""); err != nil {
		t.Fatal(err)
	}

	manifestBytes, err := os.ReadFile(filepath.Join(directory, manifestName))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := decodeManifest(manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Targets["windows-amd64"].InstallMode != "external" || manifest.Targets["linux-amd64"].InstallMode != "external" {
		t.Fatalf("unexpected install modes: %#v", manifest.Targets)
	}
	signatureText, err := os.ReadFile(filepath.Join(directory, signatureName))
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(signatureText)))
	if err != nil || !ed25519.Verify(publicKey, manifestBytes, signature) {
		t.Fatal("manifest signature does not verify exact bytes")
	}

	if err := os.WriteFile(filepath.Join(directory, manifest.Targets["linux-amd64"].Full.Name), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyRelease(directory, publicKey, ""); err == nil {
		t.Fatal("verifyRelease accepted a tampered asset")
	}
}

func TestBuildReleaseKeepsMachineInstalledWindowsExternal(t *testing.T) {
	previousDirectory := t.TempDir()
	previousEXE := filepath.Join(previousDirectory, "soha-app-v0.2.0-test.1-windows-amd64.exe")
	oldBinary := bytes.Repeat([]byte("signed executable baseline\n"), 4096)
	writeTestArtifact(t, previousDirectory, filepath.Base(previousEXE), oldBinary)

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	previousArtifact, err := artifactForFile(previousEXE)
	if err != nil {
		t.Fatal(err)
	}
	previousManifest := manifest{
		SchemaVersion: 1,
		Channel:       "test",
		Version:       "0.2.0-test.1",
		PublishedAt:   time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC),
		Notes:         "Previous",
		Targets: map[string]target{
			"windows-amd64": {InstallMode: "self", Full: previousArtifact},
		},
	}
	previousBytes, err := marshalManifest(previousManifest)
	if err != nil {
		t.Fatal(err)
	}
	previousManifestPath := filepath.Join(previousDirectory, manifestName)
	previousSignaturePath := filepath.Join(previousDirectory, signatureName)
	writeTestArtifact(t, previousDirectory, manifestName, previousBytes)
	writeTestArtifact(t, previousDirectory, signatureName, []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, previousBytes))))

	directory := t.TempDir()
	newBinary := append([]byte(nil), oldBinary...)
	copy(newBinary[len(newBinary)/2:], []byte("signed executable target"))
	currentEXE := filepath.Join(directory, "soha-app-v0.2.0-test.2-windows-amd64.exe")
	writeTestArtifact(t, directory, filepath.Base(currentEXE), newBinary)
	writeTestArtifact(t, directory, "soha-app-v0.2.0-test.2-windows-amd64-installer.exe", []byte("installer"))
	writeTestArtifact(t, directory, "soha-app-service-v0.2.0-test.2-windows-amd64.exe", []byte("service"))
	writeTestArtifact(t, directory, "soha-app-v0.2.0-test.2-linux-amd64.deb", []byte("deb"))
	writeTestArtifact(t, directory, "soha-app-v0.2.0-test.2-darwin-arm64.dmg", []byte("dmg"))
	writeTestAppZIP(t, filepath.Join(directory, "soha-app-v0.2.0-test.2-darwin-arm64.zip"))

	previous := &previousRelease{
		ManifestPath:   previousManifestPath,
		SignaturePath:  previousSignaturePath,
		ExecutablePath: previousEXE,
		PublicKey:      publicKey,
	}
	if err := buildRelease(directory, "0.2.0-test.2", "test", "Target", time.Now().UTC(), privateKey, previous); err != nil {
		t.Fatal(err)
	}
	if err := verifyRelease(directory, publicKey, previousEXE); err != nil {
		t.Fatal(err)
	}

	manifestBytes, err := os.ReadFile(filepath.Join(directory, manifestName))
	if err != nil {
		t.Fatal(err)
	}
	built, err := decodeManifest(manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	if built.Targets["windows-amd64"].InstallMode != "external" || len(built.Targets["windows-amd64"].Deltas) != 0 {
		t.Fatalf("machine-installed Windows target must use the installer: %#v", built.Targets["windows-amd64"])
	}
}

func writeTestArtifact(t *testing.T, directory, name string, payload []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), payload, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeTestAppZIP(t *testing.T, destination string) {
	t.Helper()
	file, err := os.Create(destination)
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(file)
	for name, payload := range map[string]string{
		"soha-app.app/Contents/Info.plist":          "plist",
		"soha-app.app/Contents/MacOS/soha-app":      "binary",
		"soha-app.app/Contents/Resources/icon.icns": "icon",
	} {
		entry, createErr := archive.Create(name)
		if createErr != nil {
			t.Fatal(createErr)
		}
		if _, writeErr := entry.Write([]byte(payload)); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
