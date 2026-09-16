package main

import (
	"bytes"
	"image/png"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/wailsapp/wails/v3/pkg/application"
)

type recordingWindow struct {
	calls []string
}

func (window *recordingWindow) Restore() { window.calls = append(window.calls, "restore") }
func (window *recordingWindow) Show() application.Window {
	window.calls = append(window.calls, "show")
	return nil
}
func (window *recordingWindow) Focus() { window.calls = append(window.calls, "focus") }

func TestInitialServerConfigurationRestoresBlockedEnvironmentSession(t *testing.T) {
	store := newConfigStore(filepath.Join(t.TempDir(), "config.json"))
	if err := store.Save("https://soha.example.com", true); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOHA_SERVER_URL", "https://soha.example.com")
	serverURL, locked, source, blocked := initialServerConfiguration(store)
	if serverURL != "https://soha.example.com" || !locked || source != "environment" || !blocked {
		t.Fatalf("environment session state = %q, %v, %q, %v", serverURL, locked, source, blocked)
	}

	t.Setenv("SOHA_SERVER_URL", "https://other.example.com")
	_, _, _, blocked = initialServerConfiguration(store)
	if blocked {
		t.Fatal("blocked state from another server was reused")
	}
}

func TestResolvedAppVersionUsesBuildInjection(t *testing.T) {
	previous := appBuildVersion
	appBuildVersion = "1.2.3"
	t.Cleanup(func() { appBuildVersion = previous })

	if got := resolvedAppVersion(); got != "1.2.3" {
		t.Fatalf("resolvedAppVersion() = %q, want build-injected version", got)
	}
}

func TestActivateMainWindowRestoresShowsAndFocuses(t *testing.T) {
	window := &recordingWindow{}
	activateMainWindow(window)

	if want := []string{"restore", "show", "focus"}; !reflect.DeepEqual(window.calls, want) {
		t.Fatalf("activation calls = %v, want %v", window.calls, want)
	}
}

func TestTrayIconHasTransparentBackground(t *testing.T) {
	icon, err := png.Decode(bytes.NewReader(trayIcon))
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, alpha := icon.At(icon.Bounds().Min.X, icon.Bounds().Min.Y).RGBA()
	if alpha != 0 {
		t.Fatalf("tray icon corner alpha = %d, want transparent", alpha)
	}
}

func TestMacTrayIconAddsCenteredPadding(t *testing.T) {
	data, err := macTrayIcon(trayIcon)
	if err != nil {
		t.Fatal(err)
	}
	got, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	source, err := png.Decode(bytes.NewReader(trayIcon))
	if err != nil {
		t.Fatal(err)
	}
	w, h := source.Bounds().Dx(), source.Bounds().Dy()
	px, py := w/10, h/10
	if got.Bounds().Dx() != w+2*px || got.Bounds().Dy() != h+2*py {
		t.Fatalf("padded icon bounds = %v", got.Bounds())
	}
	for y := 0; y < got.Bounds().Dy(); y++ {
		for x := 0; x < got.Bounds().Dx(); x++ {
			r, g, b, a := got.At(x, y).RGBA()
			if x < px || x >= px+w || y < py || y >= py+h {
				if a != 0 {
					t.Fatalf("padding at (%d, %d) is not transparent", x, y)
				}
				continue
			}
			sr, sg, sb, sa := source.At(x-px, y-py).RGBA()
			if r != sr || g != sg || b != sb || a != sa {
				t.Fatalf("artwork changed at (%d, %d)", x, y)
			}
		}
	}
	if _, err := macTrayIcon([]byte("invalid PNG")); err == nil {
		t.Fatal("invalid PNG accepted")
	}
}
