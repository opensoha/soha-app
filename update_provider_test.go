package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/totallygamerjet/bsdiff"
	"github.com/wailsapp/wails/v3/pkg/updater"
)

type updateTestFeed struct {
	manifest  []byte
	signature []byte
	assets    map[string][]byte
	requests  atomic.Int64
}

func (feed *updateTestFeed) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	feed.requests.Add(1)
	switch request.URL.Path {
	case "/update-manifest-v1.json":
		_, _ = writer.Write(feed.manifest)
	case "/update-manifest-v1.json.sig":
		_, _ = writer.Write(feed.signature)
	default:
		asset, ok := feed.assets[strings.TrimPrefix(request.URL.Path, "/")]
		if !ok {
			http.NotFound(writer, request)
			return
		}
		_, _ = writer.Write(asset)
	}
}

func TestSignedManifestProviderUsesDeltaAndVerifiesTarget(t *testing.T) {
	oldBinary := bytes.Repeat([]byte("old-soha-binary\n"), 4096)
	newBinary := append([]byte(nil), oldBinary...)
	copy(newBinary[2000:2020], []byte("new-signed-soha-bin!"))
	patch, err := bsdiff.Diff(oldBinary, newBinary)
	if err != nil {
		t.Fatal(err)
	}
	if len(patch)*100 >= len(newBinary)*80 {
		t.Fatalf("test patch is not small enough: patch=%d full=%d", len(patch), len(newBinary))
	}

	executable := filepath.Join(t.TempDir(), "soha-app.exe")
	if err := os.WriteFile(executable, oldBinary, 0o700); err != nil {
		t.Fatal(err)
	}
	feed, server, publicKey := newUpdateTestFeed(t, "test", "0.2.0-test.2", map[string]any{
		"installMode": "self",
		"full": map[string]any{
			"name":   "soha-app-v0.2.0-test.2-windows-amd64.exe",
			"size":   len(newBinary),
			"sha256": testSHA256(newBinary),
		},
		"deltas": []map[string]any{{
			"fromVersion": "0.2.0-test.1",
			"fromSha256":  testSHA256(oldBinary),
			"name":        "soha-app-v0.2.0-test.1-to-v0.2.0-test.2-windows-amd64.bsdiff",
			"size":        len(patch),
			"sha256":      testSHA256(patch),
		}},
	}, map[string][]byte{
		"soha-app-v0.2.0-test.2-windows-amd64.exe":                     newBinary,
		"soha-app-v0.2.0-test.1-to-v0.2.0-test.2-windows-amd64.bsdiff": patch,
	})
	defer server.Close()

	provider, err := newSignedManifestProvider(signedManifestProviderConfig{
		Mode:           updateModeTest,
		ManifestURL:    server.URL + "/update-manifest-v1.json",
		PublicKey:      publicKey,
		HTTPClient:     server.Client(),
		ExecutablePath: executable,
	})
	if err != nil {
		t.Fatal(err)
	}
	release, err := provider.Check(context.Background(), updater.CheckRequest{
		CurrentVersion: "0.2.0-test.1",
		Platform:       "windows",
		Arch:           "amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
	if release == nil || release.Metadata[updateMetadataDownloadMode] != "delta" {
		t.Fatalf("expected a delta release, got %#v", release)
	}
	var downloaded bytes.Buffer
	if err := provider.Download(context.Background(), release, &downloaded, func(int64, int64) {}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(downloaded.Bytes(), newBinary) {
		t.Fatal("delta output does not match the signed full artifact")
	}
	if feed.requests.Load() != 3 {
		t.Fatalf("expected manifest, signature and patch requests only; got %d", feed.requests.Load())
	}
}

func TestSignedManifestProviderFallsBackToFull(t *testing.T) {
	oldBinary := bytes.Repeat([]byte("old-soha-binary\n"), 4096)
	newBinary := append([]byte(nil), oldBinary...)
	copy(newBinary[3000:3020], []byte("new-signed-soha-bin!"))
	corruptPatch := bytes.Repeat([]byte("not-a-bsdiff"), 32)

	executable := filepath.Join(t.TempDir(), "soha-app.exe")
	if err := os.WriteFile(executable, oldBinary, 0o700); err != nil {
		t.Fatal(err)
	}
	feed, server, publicKey := newUpdateTestFeed(t, "test", "0.2.0-test.2", map[string]any{
		"installMode": "self",
		"full": map[string]any{
			"name":   "soha-app-v0.2.0-test.2-windows-amd64.exe",
			"size":   len(newBinary),
			"sha256": testSHA256(newBinary),
		},
		"deltas": []map[string]any{{
			"fromVersion": "0.2.0-test.1",
			"fromSha256":  testSHA256(oldBinary),
			"name":        "soha-app-v0.2.0-test.1-to-v0.2.0-test.2-windows-amd64.bsdiff",
			"size":        len(corruptPatch),
			"sha256":      testSHA256(corruptPatch),
		}},
	}, map[string][]byte{
		"soha-app-v0.2.0-test.2-windows-amd64.exe":                     newBinary,
		"soha-app-v0.2.0-test.1-to-v0.2.0-test.2-windows-amd64.bsdiff": corruptPatch,
	})
	defer server.Close()

	provider, err := newSignedManifestProvider(signedManifestProviderConfig{
		Mode:           updateModeTest,
		ManifestURL:    server.URL + "/update-manifest-v1.json",
		PublicKey:      publicKey,
		HTTPClient:     server.Client(),
		ExecutablePath: executable,
	})
	if err != nil {
		t.Fatal(err)
	}
	release, err := provider.Check(context.Background(), updater.CheckRequest{
		CurrentVersion: "0.2.0-test.1",
		Platform:       "windows",
		Arch:           "amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
	var downloaded bytes.Buffer
	if err := provider.Download(context.Background(), release, &downloaded, func(int64, int64) {}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(downloaded.Bytes(), newBinary) {
		t.Fatal("full fallback output does not match")
	}
	if feed.requests.Load() != 4 {
		t.Fatalf("expected manifest, signature, patch and full requests; got %d", feed.requests.Load())
	}
}

func TestSignedManifestProviderForcesLinuxToExternal(t *testing.T) {
	full := []byte("linux package")
	_, server, publicKey := newUpdateTestFeedWithTargets(t, "test", "0.2.0-test.2", map[string]any{
		"linux-amd64": map[string]any{
			"installMode": "self",
			"full": map[string]any{
				"name":   "soha-app-v0.2.0-test.2-linux-amd64.deb",
				"size":   len(full),
				"sha256": testSHA256(full),
			},
			"deltas": []any{},
		},
	}, map[string][]byte{"soha-app-v0.2.0-test.2-linux-amd64.deb": full})
	defer server.Close()
	provider, err := newSignedManifestProvider(signedManifestProviderConfig{
		Mode:           updateModeTest,
		ManifestURL:    server.URL + "/update-manifest-v1.json",
		PublicKey:      publicKey,
		HTTPClient:     server.Client(),
		ExecutablePath: os.Args[0],
	})
	if err != nil {
		t.Fatal(err)
	}
	release, err := provider.Check(context.Background(), updater.CheckRequest{CurrentVersion: "0.2.0-test.1", Platform: "linux", Arch: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if release.Metadata[updateMetadataInstallMode] != "external" {
		t.Fatalf("Linux must remain external even when the manifest says self: %#v", release.Metadata)
	}
}

func TestSignedManifestProviderRejectsUnsupportedPlatform(t *testing.T) {
	full := []byte("unsupported package")
	_, server, publicKey := newUpdateTestFeedWithTargets(t, "test", "0.2.0-test.2", map[string]any{
		"freebsd-amd64": map[string]any{
			"installMode": "self",
			"full": map[string]any{
				"name":   "soha-app-v0.2.0-test.2-freebsd-amd64",
				"size":   len(full),
				"sha256": testSHA256(full),
			},
			"deltas": []any{},
		},
	}, nil)
	defer server.Close()
	provider, err := newSignedManifestProvider(signedManifestProviderConfig{
		Mode:           updateModeTest,
		ManifestURL:    server.URL + "/update-manifest-v1.json",
		PublicKey:      publicKey,
		HTTPClient:     server.Client(),
		ExecutablePath: os.Args[0],
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Check(context.Background(), updater.CheckRequest{CurrentVersion: "0.2.0-test.1", Platform: "freebsd", Arch: "amd64"}); err == nil {
		t.Fatal("unsupported platform was accepted")
	}
}

func TestSignedManifestProviderSanitizesCheckErrors(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := newSignedManifestProvider(signedManifestProviderConfig{
		Mode:        updateModeTest,
		ManifestURL: "https://updates.example.invalid/private/manifest?token=secret",
		PublicKey:   publicKey,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("network failure for token=secret")
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.Check(context.Background(), updater.CheckRequest{CurrentVersion: "0.2.0-test.1", Platform: "windows", Arch: "amd64"})
	if err == nil || err.Error() != "update check failed" {
		t.Fatalf("unexpected public updater error: %v", err)
	}
}

func TestSignedManifestProviderRejectsOversizedManifest(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	feed := &updateTestFeed{manifest: bytes.Repeat([]byte("x"), maxUpdateManifestSize+1)}
	server := httptest.NewServer(http.HandlerFunc(feed.serveHTTP))
	defer server.Close()
	provider, err := newSignedManifestProvider(signedManifestProviderConfig{
		Mode:        updateModeTest,
		ManifestURL: server.URL + "/update-manifest-v1.json",
		PublicKey:   publicKey,
		HTTPClient:  server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Check(context.Background(), updater.CheckRequest{CurrentVersion: "0.2.0-test.1", Platform: "windows", Arch: "amd64"}); err == nil {
		t.Fatal("oversized manifest was accepted")
	}
}

func TestSignedManifestProviderRejectsUntrustedOrInvalidManifest(t *testing.T) {
	validTarget := map[string]any{
		"installMode": "self",
		"full": map[string]any{
			"name":   "soha-app-v0.2.0-windows-amd64.exe",
			"size":   4,
			"sha256": testSHA256([]byte("full")),
		},
		"deltas": []any{},
	}
	tests := []struct {
		name    string
		channel string
		version string
		target  any
		mutate  func(*updateTestFeed, ed25519.PublicKey)
	}{
		{name: "tampered signature", channel: "stable", version: "0.2.0", target: validTarget, mutate: func(feed *updateTestFeed, _ ed25519.PublicKey) { feed.manifest = append(feed.manifest, ' ') }},
		{name: "wrong key", channel: "stable", version: "0.2.0", target: validTarget, mutate: func(feed *updateTestFeed, _ ed25519.PublicKey) {
			_, wrongPrivate, _ := ed25519.GenerateKey(rand.Reader)
			feed.signature = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(wrongPrivate, feed.manifest)))
		}},
		{name: "unknown field", channel: "stable", version: "0.2.0", target: validTarget, mutate: func(feed *updateTestFeed, _ ed25519.PublicKey) {
			feed.manifest = bytes.Replace(feed.manifest, []byte(`"notes":"test"`), []byte(`"notes":"test","unknown":true`), 1)
		}},
		{name: "downgrade", channel: "stable", version: "0.1.8", target: validTarget},
		{name: "stable prerelease", channel: "stable", version: "0.2.0-rc.1", target: validTarget},
		{name: "missing target", channel: "stable", version: "0.2.0", target: nil},
		{name: "oversized asset", channel: "stable", version: "0.2.0", target: map[string]any{
			"installMode": "self",
			"full":        map[string]any{"name": "soha-app-v0.2.0-windows-amd64.exe", "size": maxUpdateAssetSize + 1, "sha256": testSHA256([]byte("full"))},
			"deltas":      []any{},
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			targets := map[string]any{}
			if test.target != nil {
				targets["windows-amd64"] = test.target
			}
			feed, server, publicKey := newUpdateTestFeedWithTargets(t, test.channel, test.version, targets, nil)
			defer server.Close()
			if test.mutate != nil {
				test.mutate(feed, publicKey)
				if test.name == "unknown field" {
					// Keep the manifest cryptographically valid so strict JSON decoding is the failing boundary.
					_, privateKey, err := ed25519.GenerateKey(rand.Reader)
					if err != nil {
						t.Fatal(err)
					}
					publicKey = privateKey.Public().(ed25519.PublicKey)
					feed.signature = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, feed.manifest)))
				}
			}
			provider, err := newSignedManifestProvider(signedManifestProviderConfig{
				Mode:           updateModeProduction,
				ManifestURL:    server.URL + "/update-manifest-v1.json",
				PublicKey:      publicKey,
				HTTPClient:     server.Client(),
				ExecutablePath: filepath.Join(t.TempDir(), "soha-app.exe"),
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := provider.Check(context.Background(), updater.CheckRequest{CurrentVersion: "0.1.9", Platform: "windows", Arch: "amd64"}); err == nil {
				t.Fatal("expected manifest to be rejected")
			}
		})
	}
}

func newUpdateTestFeed(t *testing.T, channel, version string, target map[string]any, assets map[string][]byte) (*updateTestFeed, *httptest.Server, ed25519.PublicKey) {
	t.Helper()
	return newUpdateTestFeedWithTargets(t, channel, version, map[string]any{"windows-amd64": target}, assets)
}

func newUpdateTestFeedWithTargets(t *testing.T, channel, version string, targets map[string]any, assets map[string][]byte) (*updateTestFeed, *httptest.Server, ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal(map[string]any{
		"schemaVersion": 1,
		"channel":       channel,
		"version":       version,
		"publishedAt":   time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
		"notes":         "test",
		"targets":       targets,
	})
	if err != nil {
		t.Fatal(err)
	}
	feed := &updateTestFeed{
		manifest:  manifest,
		signature: []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, manifest))),
		assets:    assets,
	}
	server := httptest.NewServer(http.HandlerFunc(feed.serveHTTP))
	return feed, server, publicKey
}

func testSHA256(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func TestUpdateTestFeedSanity(t *testing.T) {
	feed := &updateTestFeed{manifest: []byte("manifest"), signature: []byte("signature"), assets: map[string][]byte{"asset": []byte("value")}}
	server := httptest.NewServer(http.HandlerFunc(feed.serveHTTP))
	defer server.Close()
	for path, expected := range map[string]string{"/update-manifest-v1.json": "manifest", "/update-manifest-v1.json.sig": "signature", "/asset": "value"} {
		response, err := server.Client().Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != expected {
			t.Fatalf("%s: got %q", path, body)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
