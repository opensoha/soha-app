package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/totallygamerjet/bsdiff"
	"github.com/wailsapp/wails/v3/pkg/updater"
	"golang.org/x/mod/semver"
)

const (
	maxUpdateManifestSize       = 1 << 20
	maxUpdateSignatureSize      = 4 << 10
	maxUpdateAssetSize          = 128 << 20
	updateMetadataInstallMode   = "installMode"
	updateMetadataDownloadMode  = "downloadMode"
	updateMetadataReleaseURL    = "releaseURL"
	updateMetadataCandidate     = "sohaUpdateCandidate"
	productionUpdateManifestURL = "https://github.com/opensoha/soha-app/releases/latest/download/update-manifest-v1.json"
)

type updateBuildMode string

const (
	updateModeDisabled   updateBuildMode = "disabled"
	updateModeTest       updateBuildMode = "test"
	updateModeProduction updateBuildMode = "production"
)

type signedManifestProviderConfig struct {
	Mode           updateBuildMode
	ManifestURL    string
	PublicKey      ed25519.PublicKey
	HTTPClient     *http.Client
	ExecutablePath string
}

type signedManifestProvider struct {
	mode           updateBuildMode
	manifestURL    *url.URL
	publicKey      ed25519.PublicKey
	client         *http.Client
	executablePath string
}

type updateManifest struct {
	SchemaVersion int                             `json:"schemaVersion"`
	Channel       string                          `json:"channel"`
	Version       string                          `json:"version"`
	PublishedAt   time.Time                       `json:"publishedAt"`
	Notes         string                          `json:"notes"`
	Targets       map[string]updateManifestTarget `json:"targets"`
}

type updateManifestTarget struct {
	InstallMode string                `json:"installMode"`
	Full        updateManifestAsset   `json:"full"`
	Deltas      []updateManifestDelta `json:"deltas"`
}

type updateManifestAsset struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type updateManifestDelta struct {
	FromVersion string `json:"fromVersion"`
	FromSHA256  string `json:"fromSha256"`
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
}

type verifiedUpdateAsset struct {
	name   string
	size   int64
	digest []byte
	url    *url.URL
}

type updateDownloadCandidate struct {
	full           verifiedUpdateAsset
	delta          *verifiedUpdateAsset
	executablePath string
}

func newSignedManifestProvider(config signedManifestProviderConfig) (*signedManifestProvider, error) {
	if config.Mode != updateModeTest && config.Mode != updateModeProduction {
		return nil, fmt.Errorf("unsupported update mode %q", config.Mode)
	}
	if len(config.PublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("update public key must be Ed25519")
	}
	manifestURL, err := url.Parse(config.ManifestURL)
	if err != nil || !manifestURL.IsAbs() {
		return nil, errors.New("update manifest URL is invalid")
	}
	client := config.HTTPClient
	if client == nil {
		client = newUpdateHTTPClient()
	}
	return &signedManifestProvider{
		mode:           config.Mode,
		manifestURL:    manifestURL,
		publicKey:      append(ed25519.PublicKey(nil), config.PublicKey...),
		client:         client,
		executablePath: config.ExecutablePath,
	}, nil
}

func (provider *signedManifestProvider) Name() string {
	return "soha-signed-manifest"
}

func (provider *signedManifestProvider) Check(ctx context.Context, request updater.CheckRequest) (release *updater.Release, resultErr error) {
	defer sanitizeUpdateProviderError("update check failed", &resultErr)
	manifestBytes, err := provider.fetch(ctx, provider.manifestURL, maxUpdateManifestSize)
	if err != nil {
		return nil, fmt.Errorf("download update manifest: %w", err)
	}
	signatureURL := *provider.manifestURL
	signatureURL.Path += ".sig"
	signatureBytes, err := provider.fetch(ctx, &signatureURL, maxUpdateSignatureSize)
	if err != nil {
		return nil, fmt.Errorf("download update manifest signature: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signatureBytes)))
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(provider.publicKey, manifestBytes, signature) {
		return nil, errors.New("update manifest signature is invalid")
	}

	manifest, err := decodeUpdateManifest(manifestBytes)
	if err != nil {
		return nil, err
	}
	if err := provider.validateManifest(manifest, request); err != nil {
		return nil, err
	}
	if semver.Compare("v"+manifest.Version, "v"+strings.TrimPrefix(request.CurrentVersion, "v")) == 0 {
		return nil, nil
	}
	target, ok := manifest.Targets[request.Platform+"-"+request.Arch]
	if !ok {
		return nil, errors.New("update manifest does not contain this platform")
	}
	full, err := provider.verifiedAsset(manifest.Version, request.Platform, request.Arch, target.Full, "")
	if err != nil {
		return nil, fmt.Errorf("invalid full update asset: %w", err)
	}

	installMode := target.InstallMode
	if installMode != "self" && installMode != "external" {
		return nil, errors.New("update install mode is invalid")
	}
	if request.Platform == "linux" {
		installMode = "external"
	} else if installMode == "self" && !canReplaceExecutable(request.Platform, provider.executablePath) {
		installMode = "external"
	}

	downloadMode := "full"
	candidate := &updateDownloadCandidate{full: full, executablePath: provider.executablePath}
	if installMode == "self" && request.Platform == "windows" && request.Arch == "amd64" {
		for _, delta := range target.Deltas {
			if delta.FromVersion != request.CurrentVersion || delta.Size*100 >= full.size*80 {
				continue
			}
			fromDigest, decodeErr := decodeSHA256(delta.FromSHA256)
			if decodeErr != nil {
				return nil, fmt.Errorf("invalid delta base digest: %w", decodeErr)
			}
			currentDigest, digestErr := fileSHA256(provider.executablePath, maxUpdateAssetSize)
			if digestErr != nil || subtle.ConstantTimeCompare(currentDigest, fromDigest) != 1 {
				continue
			}
			verifiedDelta, verifyErr := provider.verifiedAsset(manifest.Version, request.Platform, request.Arch, updateManifestAsset{
				Name:   delta.Name,
				Size:   delta.Size,
				SHA256: delta.SHA256,
			}, delta.FromVersion)
			if verifyErr != nil {
				return nil, fmt.Errorf("invalid delta update asset: %w", verifyErr)
			}
			candidate.delta = &verifiedDelta
			downloadMode = "delta"
			break
		}
	}

	releaseURL := provider.releaseURL(manifest.Version)
	return &updater.Release{
		Version:     manifest.Version,
		Channel:     manifest.Channel,
		Name:        "Soha " + manifest.Version,
		Notes:       manifest.Notes,
		PublishedAt: manifest.PublishedAt,
		Artifact: updater.Artifact{
			Filename: full.name,
			Filetype: filepath.Ext(full.name),
			Size:     full.size,
			Platform: request.Platform,
			Arch:     request.Arch,
		},
		Verification: &updater.Verification{DigestAlgo: "sha256", Digest: append([]byte(nil), full.digest...)},
		Metadata: map[string]any{
			updateMetadataInstallMode:  installMode,
			updateMetadataDownloadMode: downloadMode,
			updateMetadataReleaseURL:   releaseURL,
			updateMetadataCandidate:    candidate,
		},
	}, nil
}

func (provider *signedManifestProvider) Download(ctx context.Context, release *updater.Release, destination io.Writer, progress func(int64, int64)) (resultErr error) {
	defer sanitizeUpdateProviderError("update download failed", &resultErr)
	candidate, ok := release.Metadata[updateMetadataCandidate].(*updateDownloadCandidate)
	if !ok || candidate == nil {
		return errors.New("update release is missing download metadata")
	}
	if candidate.delta != nil {
		if target, err := provider.applyDelta(ctx, candidate, progress); err == nil {
			_, writeErr := io.Copy(destination, bytes.NewReader(target))
			return writeErr
		}
	}
	full, err := provider.downloadVerifiedAsset(ctx, candidate.full, progress)
	if err != nil {
		return fmt.Errorf("download full update: %w", err)
	}
	_, err = io.Copy(destination, bytes.NewReader(full))
	return err
}

func sanitizeUpdateProviderError(message string, target *error) {
	if *target != nil {
		*target = errors.New(message)
	}
}

func (provider *signedManifestProvider) applyDelta(ctx context.Context, candidate *updateDownloadCandidate, progress func(int64, int64)) ([]byte, error) {
	patch, err := provider.downloadVerifiedAsset(ctx, *candidate.delta, progress)
	if err != nil {
		return nil, err
	}
	if err := validateBSDiffTargetSize(patch, candidate.full.size); err != nil {
		return nil, err
	}
	oldBinary, err := readFileLimited(candidate.executablePath, maxUpdateAssetSize)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	target, err := bsdiff.Patch(oldBinary, patch)
	if err != nil {
		return nil, err
	}
	if err := verifyAssetBytes(candidate.full, target); err != nil {
		return nil, err
	}
	return target, nil
}

func (provider *signedManifestProvider) downloadVerifiedAsset(ctx context.Context, asset verifiedUpdateAsset, progress func(int64, int64)) ([]byte, error) {
	payload, err := provider.fetch(ctx, asset.url, maxUpdateAssetSize)
	if err != nil {
		return nil, err
	}
	if err := verifyAssetBytes(asset, payload); err != nil {
		return nil, err
	}
	progress(int64(len(payload)), asset.size)
	return payload, nil
}

func verifyAssetBytes(asset verifiedUpdateAsset, payload []byte) error {
	if int64(len(payload)) != asset.size {
		return fmt.Errorf("update asset size mismatch: got %d want %d", len(payload), asset.size)
	}
	digest := sha256.Sum256(payload)
	if subtle.ConstantTimeCompare(digest[:], asset.digest) != 1 {
		return errors.New("update asset digest mismatch")
	}
	return nil
}

func (provider *signedManifestProvider) fetch(ctx context.Context, target *url.URL, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/octet-stream")
	response, err := provider.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
	}
	if response.ContentLength > limit {
		return nil, errors.New("update response exceeds size limit")
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > limit {
		return nil, errors.New("update response exceeds size limit")
	}
	return payload, nil
}

func decodeUpdateManifest(payload []byte) (*updateManifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var manifest updateManifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode update manifest: %w", err)
	}
	if err := ensureUpdateManifestEOF(decoder); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func ensureUpdateManifestEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("update manifest contains trailing JSON")
		}
		return fmt.Errorf("decode update manifest: %w", err)
	}
	return nil
}

func (provider *signedManifestProvider) validateManifest(manifest *updateManifest, request updater.CheckRequest) error {
	if manifest.SchemaVersion != 1 {
		return errors.New("update manifest schema is unsupported")
	}
	expectedChannel := string(provider.mode)
	if provider.mode == updateModeProduction {
		expectedChannel = "stable"
	}
	if manifest.Channel != expectedChannel {
		return errors.New("update manifest channel does not match this build")
	}
	version := "v" + manifest.Version
	currentVersion := "v" + strings.TrimPrefix(request.CurrentVersion, "v")
	if strings.HasPrefix(manifest.Version, "v") || !semver.IsValid(version) || !semver.IsValid(currentVersion) {
		return errors.New("update manifest version is invalid")
	}
	if provider.mode == updateModeProduction && semver.Prerelease(version) != "" {
		return errors.New("stable update manifest contains a prerelease")
	}
	if semver.Compare(version, currentVersion) < 0 {
		return errors.New("update manifest attempts a downgrade")
	}
	if manifest.PublishedAt.IsZero() {
		return errors.New("update manifest publication time is invalid")
	}
	switch request.Platform + "-" + request.Arch {
	case "windows-amd64", "darwin-arm64", "linux-amd64":
	default:
		return errors.New("update target is invalid")
	}
	return nil
}

func (provider *signedManifestProvider) verifiedAsset(version, platform, arch string, asset updateManifestAsset, fromVersion string) (verifiedUpdateAsset, error) {
	if asset.Size <= 0 || asset.Size > maxUpdateAssetSize {
		return verifiedUpdateAsset{}, errors.New("asset size is invalid")
	}
	if !safeUpdateAssetName(asset.Name) {
		return verifiedUpdateAsset{}, errors.New("asset name is unsafe")
	}
	expectedName := expectedUpdateAssetName(version, platform, arch)
	if fromVersion != "" {
		expectedName = fmt.Sprintf("soha-app-v%s-to-v%s-%s-%s.bsdiff", fromVersion, version, platform, arch)
	}
	if asset.Name != expectedName {
		return verifiedUpdateAsset{}, errors.New("asset name does not match the release contract")
	}
	digest, err := decodeSHA256(asset.SHA256)
	if err != nil {
		return verifiedUpdateAsset{}, err
	}
	assetURL, err := provider.assetURL(version, asset.Name)
	if err != nil {
		return verifiedUpdateAsset{}, err
	}
	return verifiedUpdateAsset{name: asset.Name, size: asset.Size, digest: digest, url: assetURL}, nil
}

func (provider *signedManifestProvider) assetURL(version, name string) (*url.URL, error) {
	if provider.mode == updateModeProduction {
		return url.Parse(fmt.Sprintf("https://github.com/opensoha/soha-app/releases/download/v%s/%s", version, name))
	}
	return provider.manifestURL.ResolveReference(&url.URL{Path: name}), nil
}

func (provider *signedManifestProvider) releaseURL(version string) string {
	if provider.mode == updateModeProduction {
		return "https://github.com/opensoha/soha-app/releases/tag/v" + version
	}
	return provider.manifestURL.ResolveReference(&url.URL{Path: "."}).String()
}

func expectedUpdateAssetName(version, platform, arch string) string {
	extension := map[string]string{"windows": ".exe", "darwin": ".zip", "linux": ".deb"}[platform]
	return fmt.Sprintf("soha-app-v%s-%s-%s%s", version, platform, arch, extension)
}

func safeUpdateAssetName(name string) bool {
	return name != "" && len(name) <= 255 && filepath.Base(name) == name && !strings.ContainsAny(name, `/\\`) && name != "." && name != ".."
}

func decodeSHA256(encoded string) ([]byte, error) {
	if len(encoded) != sha256.Size*2 || strings.ToLower(encoded) != encoded {
		return nil, errors.New("SHA-256 digest must be lowercase hexadecimal")
	}
	digest, err := hex.DecodeString(encoded)
	if err != nil || len(digest) != sha256.Size {
		return nil, errors.New("SHA-256 digest is invalid")
	}
	return digest, nil
}

func fileSHA256(path string, limit int64) ([]byte, error) {
	payload, err := readFileLimited(path, limit)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	return digest[:], nil
}

func readFileLimited(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > limit {
		return nil, errors.New("file exceeds update size limit")
	}
	return payload, nil
}

func canReplaceExecutable(platform, executablePath string) bool {
	if executablePath == "" {
		return false
	}
	target := executablePath
	if platform == "darwin" {
		if marker := strings.Index(executablePath, ".app"+string(filepath.Separator)); marker >= 0 {
			target = executablePath[:marker+4]
		}
	}
	directory := filepath.Dir(target)
	probe, err := os.CreateTemp(directory, ".soha-update-write-*")
	if err != nil {
		return false
	}
	name := probe.Name()
	closeErr := probe.Close()
	removeErr := os.Remove(name)
	return closeErr == nil && removeErr == nil
}

func validateBSDiffTargetSize(patch []byte, expected int64) error {
	if len(patch) < 32 || !bytes.Equal(patch[:8], []byte("BSDIFF40")) {
		return errors.New("delta patch header is invalid")
	}
	newSize := decodeBSDiffInt64(patch[24:32])
	if newSize < 0 || newSize > maxUpdateAssetSize || newSize != expected {
		return errors.New("delta patch target size is invalid")
	}
	return nil
}

func decodeBSDiffInt64(encoded []byte) int64 {
	value := int64(encoded[7] & 0x7f)
	for index := 6; index >= 0; index-- {
		value = value*256 + int64(encoded[index])
	}
	if encoded[7]&0x80 != 0 {
		return -value
	}
	return value
}

func newUpdateHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 10 * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	return &http.Client{
		Transport: transport,
		Timeout:   2 * time.Minute,
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			if request.URL.Scheme != "https" || !trustedUpdateHost(request.URL.Hostname()) {
				return errors.New("update redirect is not trusted")
			}
			return nil
		},
	}
}

func trustedUpdateHost(host string) bool {
	switch strings.ToLower(host) {
	case "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com":
		return true
	default:
		return false
	}
}
