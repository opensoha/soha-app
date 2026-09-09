package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/totallygamerjet/bsdiff"
	"golang.org/x/mod/semver"
)

const (
	manifestName       = "update-manifest-v1.json"
	signatureName      = manifestName + ".sig"
	checksumsName      = "checksums.txt"
	maxManifestSize    = 1 << 20
	maxArtifactSize    = 128 << 20
	maxReleaseNoteSize = 64 << 10
)

type manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	Channel       string            `json:"channel"`
	Version       string            `json:"version"`
	PublishedAt   time.Time         `json:"publishedAt"`
	Notes         string            `json:"notes"`
	Targets       map[string]target `json:"targets"`
}

type target struct {
	InstallMode string          `json:"installMode"`
	Full        artifact        `json:"full"`
	Deltas      []deltaArtifact `json:"deltas,omitempty"`
}

type artifact struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type deltaArtifact struct {
	FromVersion string `json:"fromVersion"`
	FromSHA256  string `json:"fromSha256"`
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
}

type previousRelease struct {
	ManifestPath   string
	SignaturePath  string
	ExecutablePath string
	PublicKey      ed25519.PublicKey
}

type previousWindows struct {
	Version string
	Channel string
	SHA256  string
}

func main() {
	if len(os.Args) < 2 {
		fatal(errors.New("expected check-version, build, or verify subcommand"))
	}
	var err error
	switch os.Args[1] {
	case "check-version":
		err = runCheckVersion(os.Args[2:])
	case "build":
		err = runBuild(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	default:
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "updaterelease:", err)
	os.Exit(1)
}

func runCheckVersion(arguments []string) error {
	flags := flag.NewFlagSet("check-version", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	version := flags.String("version", "", "release version without v prefix")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	return checkVersionFiles(*root, *version)
}

func runBuild(arguments []string) error {
	flags := flag.NewFlagSet("build", flag.ContinueOnError)
	directory := flags.String("dir", "", "release artifact directory")
	version := flags.String("version", "", "release version without v prefix")
	channel := flags.String("channel", "", "stable or test")
	notesPath := flags.String("notes-file", "", "UTF-8 release notes")
	publishedAtValue := flags.String("published-at", "", "RFC3339 publication time")
	privateKeyPath := flags.String("private-key", "", "raw Ed25519 seed or private key file")
	previousManifest := flags.String("previous-manifest", "", "previous signed manifest")
	previousSignature := flags.String("previous-signature", "", "previous manifest signature")
	previousEXE := flags.String("previous-exe", "", "previous signed Windows executable")
	previousPublicKey := flags.String("previous-public-key", "", "raw previous Ed25519 public key")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *directory == "" || *version == "" || *channel == "" || *notesPath == "" || *publishedAtValue == "" || *privateKeyPath == "" {
		return errors.New("dir, version, channel, notes-file, published-at, and private-key are required")
	}
	publishedAt, err := time.Parse(time.RFC3339, *publishedAtValue)
	if err != nil {
		return fmt.Errorf("parse published-at: %w", err)
	}
	notes, err := readLimited(*notesPath, maxReleaseNoteSize)
	if err != nil {
		return fmt.Errorf("read release notes: %w", err)
	}
	privateKey, err := readPrivateKey(*privateKeyPath)
	if err != nil {
		return err
	}
	previousValues := []string{*previousManifest, *previousSignature, *previousEXE, *previousPublicKey}
	provided := 0
	for _, value := range previousValues {
		if value != "" {
			provided++
		}
	}
	var previous *previousRelease
	if provided != 0 {
		if provided != len(previousValues) {
			return errors.New("all previous release inputs must be provided together")
		}
		publicKey, readErr := readPublicKey(*previousPublicKey)
		if readErr != nil {
			return readErr
		}
		previous = &previousRelease{
			ManifestPath:   *previousManifest,
			SignaturePath:  *previousSignature,
			ExecutablePath: *previousEXE,
			PublicKey:      publicKey,
		}
	}
	return buildRelease(*directory, *version, *channel, strings.TrimSpace(string(notes)), publishedAt, privateKey, previous)
}

func runVerify(arguments []string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	directory := flags.String("dir", "", "downloaded release directory")
	publicKeyPath := flags.String("public-key", "", "raw Ed25519 public key")
	previousEXE := flags.String("previous-exe", "", "previous signed Windows executable when a delta is present")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *directory == "" || *publicKeyPath == "" {
		return errors.New("dir and public-key are required")
	}
	publicKey, err := readPublicKey(*publicKeyPath)
	if err != nil {
		return err
	}
	return verifyRelease(*directory, publicKey, *previousEXE)
}

func buildRelease(directory, version, channel, notes string, publishedAt time.Time, privateKey ed25519.PrivateKey, previous *previousRelease) error {
	if err := validateVersionChannel(version, channel); err != nil {
		return err
	}
	if publishedAt.IsZero() {
		return errors.New("publishedAt is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return errors.New("Ed25519 private key has invalid length")
	}
	for _, name := range []string{manifestName, signatureName, checksumsName} {
		if err := os.Remove(filepath.Join(directory, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	targets := make(map[string]target, 3)
	for _, platform := range []struct {
		key, mode string
	}{
		{key: "windows-amd64", mode: "external"},
		{key: "darwin-arm64", mode: "self"},
		{key: "linux-amd64", mode: "external"},
	} {
		name, err := fullAssetName(version, platform.key)
		if err != nil {
			return err
		}
		full, err := artifactForFile(filepath.Join(directory, name))
		if err != nil {
			return fmt.Errorf("inspect %s: %w", name, err)
		}
		targets[platform.key] = target{InstallMode: platform.mode, Full: full}
	}

	for _, name := range []string{
		fmt.Sprintf("soha-app-v%s-windows-amd64-installer.exe", version),
		fmt.Sprintf("soha-app-service-v%s-windows-amd64.exe", version),
		fmt.Sprintf("soha-app-v%s-darwin-arm64.dmg", version),
	} {
		if _, err := artifactForFile(filepath.Join(directory, name)); err != nil {
			return fmt.Errorf("inspect %s: %w", name, err)
		}
	}
	if err := verifyAppZIP(filepath.Join(directory, fmt.Sprintf("soha-app-v%s-darwin-arm64.zip", version))); err != nil {
		return err
	}

	previousExecutable := ""
	if previous != nil && targets["windows-amd64"].InstallMode == "self" {
		verified, err := verifyPreviousWindowsRelease(*previous)
		if err != nil {
			return err
		}
		if verified.Channel != channel {
			return errors.New("previous release channel does not match")
		}
		if semver.Compare("v"+verified.Version, "v"+version) >= 0 {
			return errors.New("previous release must be older than the target")
		}
		patchName := fmt.Sprintf("soha-app-v%s-to-v%s-windows-amd64.bsdiff", verified.Version, version)
		created, err := createWindowsDelta(
			previous.ExecutablePath,
			filepath.Join(directory, fmt.Sprintf("soha-app-v%s-windows-amd64.exe", version)),
			filepath.Join(directory, patchName),
		)
		if err != nil {
			return err
		}
		if created {
			patch, err := artifactForFile(filepath.Join(directory, patchName))
			if err != nil {
				return err
			}
			windows := targets["windows-amd64"]
			windows.Deltas = []deltaArtifact{{
				FromVersion: verified.Version,
				FromSHA256:  verified.SHA256,
				Name:        patch.Name,
				Size:        patch.Size,
				SHA256:      patch.SHA256,
			}}
			targets["windows-amd64"] = windows
			previousExecutable = previous.ExecutablePath
		}
	}

	payload, err := marshalManifest(manifest{
		SchemaVersion: 1,
		Channel:       channel,
		Version:       version,
		PublishedAt:   publishedAt.UTC(),
		Notes:         notes,
		Targets:       targets,
	})
	if err != nil {
		return err
	}
	if len(payload) > maxManifestSize {
		return errors.New("manifest exceeds 1 MiB")
	}
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)) + "\n"
	if err := os.WriteFile(filepath.Join(directory, manifestName), payload, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(directory, signatureName), []byte(signature), 0o644); err != nil {
		return err
	}
	if err := writeChecksums(directory); err != nil {
		return err
	}
	return verifyRelease(directory, privateKey.Public().(ed25519.PublicKey), previousExecutable)
}

func verifyRelease(directory string, publicKey ed25519.PublicKey, previousExecutable string) error {
	if err := verifyChecksums(directory); err != nil {
		return err
	}
	payload, err := readLimited(filepath.Join(directory, manifestName), maxManifestSize)
	if err != nil {
		return err
	}
	if err := verifyManifestSignature(payload, filepath.Join(directory, signatureName), publicKey); err != nil {
		return err
	}
	release, err := decodeManifest(payload)
	if err != nil {
		return err
	}
	if err := validateManifest(release); err != nil {
		return err
	}
	allowed := map[string]bool{manifestName: true, signatureName: true, checksumsName: true}
	for key, target := range release.Targets {
		if err := verifyArtifact(directory, target.Full); err != nil {
			return fmt.Errorf("verify %s full asset: %w", key, err)
		}
		allowed[target.Full.Name] = true
		for _, delta := range target.Deltas {
			if err := verifyArtifact(directory, artifact{Name: delta.Name, Size: delta.Size, SHA256: delta.SHA256}); err != nil {
				return fmt.Errorf("verify delta: %w", err)
			}
			allowed[delta.Name] = true
		}
	}
	installer := fmt.Sprintf("soha-app-v%s-windows-amd64-installer.exe", release.Version)
	service := fmt.Sprintf("soha-app-service-v%s-windows-amd64.exe", release.Version)
	dmg := fmt.Sprintf("soha-app-v%s-darwin-arm64.dmg", release.Version)
	for _, name := range []string{installer, service, dmg} {
		if _, err := artifactForFile(filepath.Join(directory, name)); err != nil {
			return fmt.Errorf("verify %s: %w", name, err)
		}
		allowed[name] = true
	}
	zipName := fmt.Sprintf("soha-app-v%s-darwin-arm64.zip", release.Version)
	if err := verifyAppZIP(filepath.Join(directory, zipName)); err != nil {
		return err
	}

	windows := release.Targets["windows-amd64"]
	if len(windows.Deltas) > 0 {
		if previousExecutable == "" {
			return errors.New("previous executable is required to verify the delta")
		}
		if len(windows.Deltas) != 1 {
			return errors.New("only one Windows delta is allowed")
		}
		delta := windows.Deltas[0]
		previous, err := artifactForFile(previousExecutable)
		if err != nil {
			return err
		}
		if previous.SHA256 != delta.FromSHA256 {
			return errors.New("previous executable SHA-256 does not match the delta")
		}
		oldBytes, err := readLimited(previousExecutable, maxArtifactSize)
		if err != nil {
			return err
		}
		patchBytes, err := readLimited(filepath.Join(directory, delta.Name), maxArtifactSize)
		if err != nil {
			return err
		}
		newBytes, err := bsdiff.Patch(oldBytes, patchBytes)
		if err != nil {
			return fmt.Errorf("apply Windows delta: %w", err)
		}
		if int64(len(newBytes)) != windows.Full.Size || hexDigest(newBytes) != windows.Full.SHA256 {
			return errors.New("Windows delta reconstruction does not match the full executable")
		}
		if delta.Size*100 >= windows.Full.Size*80 {
			return errors.New("Windows delta is not smaller than 80% of the full executable")
		}
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return fmt.Errorf("unexpected directory in release: %s", entry.Name())
		}
		if !allowed[entry.Name()] {
			return fmt.Errorf("unexpected release asset: %s", entry.Name())
		}
	}
	return nil
}

func validateManifest(release manifest) error {
	if release.SchemaVersion != 1 || release.PublishedAt.IsZero() {
		return errors.New("manifest schemaVersion or publishedAt is invalid")
	}
	if err := validateVersionChannel(release.Version, release.Channel); err != nil {
		return err
	}
	if len(release.Targets) != 3 {
		return errors.New("manifest must contain exactly three supported targets")
	}
	expectedModes := map[string]string{"windows-amd64": "external", "darwin-arm64": "self", "linux-amd64": "external"}
	for key, mode := range expectedModes {
		target, ok := release.Targets[key]
		if !ok || target.InstallMode != mode {
			return fmt.Errorf("target %s has invalid install mode", key)
		}
		expected, err := fullAssetName(release.Version, key)
		if err != nil || target.Full.Name != expected {
			return fmt.Errorf("target %s has invalid full asset name", key)
		}
		if target.Full.Size <= 0 || target.Full.Size > maxArtifactSize || !validSHA256(target.Full.SHA256) {
			return fmt.Errorf("target %s has invalid full asset metadata", key)
		}
		if key != "windows-amd64" && len(target.Deltas) != 0 {
			return fmt.Errorf("target %s must not contain deltas", key)
		}
	}
	for _, delta := range release.Targets["windows-amd64"].Deltas {
		if !semver.IsValid("v"+delta.FromVersion) || semver.Compare("v"+delta.FromVersion, "v"+release.Version) >= 0 {
			return errors.New("delta fromVersion is invalid")
		}
		expected := fmt.Sprintf("soha-app-v%s-to-v%s-windows-amd64.bsdiff", delta.FromVersion, release.Version)
		if delta.Name != expected || delta.Size <= 0 || delta.Size > maxArtifactSize || !validSHA256(delta.SHA256) || !validSHA256(delta.FromSHA256) {
			return errors.New("delta metadata is invalid")
		}
	}
	return nil
}

func validateVersionChannel(version, channel string) error {
	if !semver.IsValid("v"+version) || strings.HasPrefix(version, "v") {
		return errors.New("version must be valid SemVer without a v prefix")
	}
	if channel != "stable" && channel != "test" {
		return errors.New("channel must be stable or test")
	}
	if channel == "stable" && semver.Prerelease("v"+version) != "" {
		return errors.New("stable releases must not use prerelease versions")
	}
	return nil
}

func verifyPreviousWindowsRelease(previous previousRelease) (previousWindows, error) {
	payload, err := readLimited(previous.ManifestPath, maxManifestSize)
	if err != nil {
		return previousWindows{}, err
	}
	if err := verifyManifestSignature(payload, previous.SignaturePath, previous.PublicKey); err != nil {
		return previousWindows{}, fmt.Errorf("verify previous manifest: %w", err)
	}
	release, err := decodeManifest(payload)
	if err != nil {
		return previousWindows{}, err
	}
	if release.SchemaVersion != 1 || release.PublishedAt.IsZero() {
		return previousWindows{}, errors.New("previous manifest metadata is invalid")
	}
	if err := validateVersionChannel(release.Version, release.Channel); err != nil {
		return previousWindows{}, err
	}
	windows, ok := release.Targets["windows-amd64"]
	if !ok || windows.InstallMode != "self" {
		return previousWindows{}, errors.New("previous manifest has no self-updating Windows target")
	}
	expected := fmt.Sprintf("soha-app-v%s-windows-amd64.exe", release.Version)
	if windows.Full.Name != expected {
		return previousWindows{}, errors.New("previous Windows asset name is invalid")
	}
	actual, err := artifactForFile(previous.ExecutablePath)
	if err != nil {
		return previousWindows{}, err
	}
	if filepath.Base(previous.ExecutablePath) != expected || actual.Size != windows.Full.Size || actual.SHA256 != windows.Full.SHA256 {
		return previousWindows{}, errors.New("previous Windows executable does not match its signed manifest")
	}
	return previousWindows{Version: release.Version, Channel: release.Channel, SHA256: actual.SHA256}, nil
}

func createWindowsDelta(oldPath, newPath, outputPath string) (bool, error) {
	oldBytes, err := readLimited(oldPath, maxArtifactSize)
	if err != nil {
		return false, err
	}
	newBytes, err := readLimited(newPath, maxArtifactSize)
	if err != nil {
		return false, err
	}
	patch, err := bsdiff.Diff(oldBytes, newBytes)
	if err != nil {
		return false, fmt.Errorf("create BSDIFF40 patch: %w", err)
	}
	rebuilt, err := bsdiff.Patch(oldBytes, patch)
	if err != nil || !bytes.Equal(rebuilt, newBytes) {
		return false, errors.New("generated Windows delta failed reconstruction")
	}
	if len(patch)*100 >= len(newBytes)*80 {
		if err := os.Remove(outputPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
		return false, nil
	}
	if err := os.WriteFile(outputPath, patch, 0o644); err != nil {
		return false, err
	}
	return true, nil
}

func marshalManifest(release manifest) ([]byte, error) {
	payload, err := json.MarshalIndent(release, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

func decodeManifest(payload []byte) (manifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var release manifest
	if err := decoder.Decode(&release); err != nil {
		return manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return manifest{}, errors.New("manifest contains trailing data")
	}
	return release, nil
}

func verifyManifestSignature(payload []byte, signaturePath string, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("Ed25519 public key has invalid length")
	}
	signatureText, err := readLimited(signaturePath, 4096)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signatureText)))
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("manifest signature is invalid")
	}
	return nil
}

func artifactForFile(filePath string) (artifact, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return artifact{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxArtifactSize {
		return artifact{}, errors.New("asset is empty, non-regular, or exceeds 128 MiB")
	}
	digest, err := digestFile(filePath)
	if err != nil {
		return artifact{}, err
	}
	return artifact{Name: filepath.Base(filePath), Size: info.Size(), SHA256: digest}, nil
}

func verifyArtifact(directory string, expected artifact) error {
	if !safeName(expected.Name) {
		return errors.New("unsafe asset name")
	}
	actual, err := artifactForFile(filepath.Join(directory, expected.Name))
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("asset size or SHA-256 does not match manifest")
	}
	return nil
}

func fullAssetName(version, targetKey string) (string, error) {
	switch targetKey {
	case "windows-amd64":
		return fmt.Sprintf("soha-app-v%s-windows-amd64.exe", version), nil
	case "darwin-arm64":
		return fmt.Sprintf("soha-app-v%s-darwin-arm64.zip", version), nil
	case "linux-amd64":
		return fmt.Sprintf("soha-app-v%s-linux-amd64.deb", version), nil
	default:
		return "", fmt.Errorf("unsupported target %q", targetKey)
	}
}

func writeChecksums(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == checksumsName {
			continue
		}
		if !safeName(entry.Name()) {
			return fmt.Errorf("unsafe release asset name %q", entry.Name())
		}
		digest, err := digestFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return err
		}
		lines = append(lines, digest+"  "+entry.Name())
	}
	sort.Strings(lines)
	return os.WriteFile(filepath.Join(directory, checksumsName), []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func verifyChecksums(directory string) error {
	file, err := os.Open(filepath.Join(directory, checksumsName))
	if err != nil {
		return err
	}
	defer file.Close()
	expected := map[string]string{}
	scanner := bufio.NewScanner(io.LimitReader(file, maxManifestSize+1))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 || !validSHA256(parts[0]) || !safeName(parts[1]) || expected[parts[1]] != "" {
			return errors.New("checksums.txt contains an invalid entry")
		}
		expected[parts[1]] = parts[0]
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	actualCount := 0
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == checksumsName {
			continue
		}
		actualCount++
		digest, ok := expected[entry.Name()]
		if !ok {
			return fmt.Errorf("checksum missing for %s", entry.Name())
		}
		actual, err := digestFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return err
		}
		if actual != digest {
			return fmt.Errorf("checksum mismatch for %s", entry.Name())
		}
	}
	if actualCount != len(expected) {
		return errors.New("checksums.txt references a missing asset")
	}
	return nil
}

func verifyAppZIP(filePath string) error {
	archive, err := zip.OpenReader(filePath)
	if err != nil {
		return fmt.Errorf("open macOS update zip: %w", err)
	}
	defer archive.Close()
	if len(archive.File) == 0 {
		return errors.New("macOS update zip is empty")
	}
	foundInfo, foundExecutable := false, false
	for _, entry := range archive.File {
		name := entry.Name
		if strings.Contains(name, "\\") || strings.HasPrefix(name, "/") || path.Clean(name) != strings.TrimSuffix(name, "/") && path.Clean(name)+"/" != name {
			return errors.New("macOS update zip contains an unsafe path")
		}
		if name != "soha-app.app/" && !strings.HasPrefix(name, "soha-app.app/") {
			return errors.New("macOS update zip must contain only soha-app.app")
		}
		if entry.Mode()&os.ModeSymlink != 0 {
			return errors.New("macOS update zip must not contain symlinks")
		}
		foundInfo = foundInfo || name == "soha-app.app/Contents/Info.plist"
		foundExecutable = foundExecutable || name == "soha-app.app/Contents/MacOS/soha-app"
	}
	if !foundInfo || !foundExecutable {
		return errors.New("macOS update zip is missing the app metadata or executable")
	}
	return nil
}

func checkVersionFiles(root, expected string) error {
	if !semver.IsValid("v"+expected) || semver.Prerelease("v"+expected) != "" {
		return errors.New("expected version must be stable SemVer without a v prefix")
	}
	checks := []struct {
		path    string
		pattern string
		count   int
	}{
		{"build/config.yml", `(?m)^[ \t]+version: "([^"]+)"[ \t]*$`, 2},
		{"build/linux/nfpm/nfpm.yaml", `(?m)^version: "([^"]+)"[ \t]*$`, 1},
		{"build/windows/wails.exe.manifest", `assemblyIdentity[^>]+name="com\.opensoha\.app"[^>]+version="([^"]+)"`, 1},
		{"build/windows/nsis/wails_tools.nsh", `(?m)^[ \t]+!define INFO_PRODUCTVERSION "([^"]+)"[ \t]*$`, 1},
	}
	for _, check := range checks {
		payload, err := os.ReadFile(filepath.Join(root, check.path))
		if err != nil {
			return err
		}
		matches := regexp.MustCompile(check.pattern).FindAllStringSubmatch(string(payload), -1)
		if len(matches) != check.count {
			return fmt.Errorf("%s has an unexpected version layout", check.path)
		}
		for _, match := range matches {
			if match[1] != expected {
				return fmt.Errorf("%s version %s does not match %s", check.path, match[1], expected)
			}
		}
	}
	if err := checkPlistVersion(filepath.Join(root, "build/darwin/Info.plist"), expected); err != nil {
		return err
	}
	if err := checkJSONVersions(filepath.Join(root, "build/windows/info.json"), expected, []string{"fixed.file_version", "info.0000.ProductVersion"}); err != nil {
		return err
	}
	if err := checkJSONVersions(filepath.Join(root, "frontend/package.json"), expected, []string{"version"}); err != nil {
		return err
	}
	return checkJSONVersions(filepath.Join(root, "frontend/package-lock.json"), expected, []string{"version", "packages..version"})
}

func checkPlistVersion(filePath, expected string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := xml.NewDecoder(file)
	wanted := map[string]bool{"CFBundleShortVersionString": false, "CFBundleVersion": false}
	currentKey := ""
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if start.Name.Local == "key" {
			if err := decoder.DecodeElement(&currentKey, &start); err != nil {
				return err
			}
			continue
		}
		if start.Name.Local == "string" && currentKey != "" {
			var value string
			if err := decoder.DecodeElement(&value, &start); err != nil {
				return err
			}
			if _, ok := wanted[currentKey]; ok {
				if value != expected {
					return fmt.Errorf("%s %s does not match %s", filePath, currentKey, expected)
				}
				wanted[currentKey] = true
			}
			currentKey = ""
		}
	}
	for key, found := range wanted {
		if !found {
			return fmt.Errorf("%s is missing %s", filePath, key)
		}
	}
	return nil
}

func checkJSONVersions(filePath, expected string, paths []string) error {
	payload, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	var value map[string]any
	if err := json.Unmarshal(payload, &value); err != nil {
		return err
	}
	for _, keyPath := range paths {
		current := any(value)
		for _, key := range strings.Split(keyPath, ".") {
			object, ok := current.(map[string]any)
			if !ok {
				return fmt.Errorf("%s is missing %s", filePath, keyPath)
			}
			current, ok = object[key]
			if !ok {
				return fmt.Errorf("%s is missing %s", filePath, keyPath)
			}
		}
		if current != expected {
			return fmt.Errorf("%s %s does not match %s", filePath, keyPath, expected)
		}
	}
	return nil
}

func readPrivateKey(filePath string) (ed25519.PrivateKey, error) {
	payload, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	switch len(payload) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(payload), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(payload), nil
	default:
		return nil, errors.New("Ed25519 private key file must contain 32 or 64 raw bytes")
	}
}

func readPublicKey(filePath string) (ed25519.PublicKey, error) {
	payload, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	if len(payload) != ed25519.PublicKeySize {
		return nil, errors.New("Ed25519 public key file must contain 32 raw bytes")
	}
	return ed25519.PublicKey(payload), nil
}

func digestFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func readLimited(filePath string, limit int64) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > limit {
		return nil, errors.New("file exceeds size limit")
	}
	return payload, nil
}

func hexDigest(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func safeName(name string) bool {
	return name != "" && name == filepath.Base(name) && !strings.ContainsAny(name, `/\\`)
}
