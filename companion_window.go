package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

const (
	companionWindowWidth  = 360
	companionWindowHeight = 430
)

type windowPosition struct {
	X int `json:"x"`
	Y int `json:"y"`
}

type windowPositionStore struct {
	mu   sync.Mutex
	path string
}

func defaultWindowPositionStore() (*windowPositionStore, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("resolve user config directory: %w", err)
	}
	return &windowPositionStore{path: filepath.Join(root, "OpenSoha", "companion-window.json")}, nil
}

func (s *windowPositionStore) load() (windowPosition, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		return windowPosition{}, false
	}
	var position windowPosition
	if json.Unmarshal(data, &position) != nil || position.X < -100_000 || position.X > 100_000 || position.Y < -100_000 || position.Y > 100_000 {
		return windowPosition{}, false
	}
	return position, true
}

func (s *windowPositionStore) save(position windowPosition) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create companion state directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".companion-window-*.tmp")
	if err != nil {
		return fmt.Errorf("create companion position file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect companion position file: %w", err)
	}
	if err := json.NewEncoder(temporary).Encode(position); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("encode companion position: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync companion position: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close companion position file: %w", err)
	}
	if err := os.Rename(temporaryPath, s.path); err != nil {
		return fmt.Errorf("commit companion position: %w", err)
	}
	return nil
}

func newCompanionWindow(app *application.App, positions *windowPositionStore) *application.WebviewWindow {
	options := application.WebviewWindowOptions{
		Name:             "soha-companion",
		Title:            "Soha Companion",
		Width:            companionWindowWidth,
		Height:           companionWindowHeight,
		MinWidth:         companionWindowWidth,
		MinHeight:        companionWindowHeight,
		MaxWidth:         companionWindowWidth,
		MaxHeight:        companionWindowHeight,
		DisableResize:    true,
		Frameless:        true,
		Hidden:           true,
		AlwaysOnTop:      true,
		BackgroundType:   application.BackgroundTypeTransparent,
		BackgroundColour: application.NewRGBA(0, 0, 0, 0),
		URL:              "/companion",
		Mac: application.MacWindow{
			Backdrop:      application.MacBackdropTransparent,
			DisableShadow: true,
			TitleBar:      application.MacTitleBarHidden,
			WindowLevel:   application.MacWindowLevelFloating,
			CollectionBehavior: application.MacWindowCollectionBehaviorCanJoinAllSpaces |
				application.MacWindowCollectionBehaviorFullScreenAuxiliary,
			TabbingMode: application.MacWindowTabbingModeDisallowed,
		},
		Windows: application.WindowsWindow{
			DisableFramelessWindowDecorations: true,
			HiddenOnTaskbar:                   true,
			NonClientRegionSupport:            true,
			WindowDidMoveDebounceMS:           120,
		},
		Linux: application.LinuxWindow{
			WindowIsTranslucent:     true,
			WindowDidMoveDebounceMS: 120,
		},
	}
	if position, ok := positions.load(); ok {
		options.InitialPosition = application.WindowXY
		options.X = position.X
		options.Y = position.Y
	} else {
		options.InitialPosition = application.WindowCentered
	}

	window := app.Window.NewWithOptions(options)
	window.RegisterHook(events.Common.WindowClosing, func(event *application.WindowEvent) {
		window.Hide()
		event.Cancel()
	})
	window.OnWindowEvent(events.Common.WindowDidMove, func(_ *application.WindowEvent) {
		x, y := window.Position()
		if err := positions.save(windowPosition{X: x, Y: y}); err != nil && !errors.Is(err, os.ErrClosed) {
			app.Logger.Error("persist companion window position", "error", err)
		}
	})
	return window
}

func configureSystemTray(app *application.App, mainWindow, companionWindow *application.WebviewWindow, icon []byte) {
	tray := app.SystemTray.New()
	tray.SetTooltip("Soha Companion")
	if runtime.GOOS == "darwin" {
		tray.SetTemplateIcon(icon)
	} else {
		tray.SetIcon(icon)
	}
	menu := app.NewMenu()
	menu.Add("Show Soha").OnClick(func(_ *application.Context) {
		mainWindow.Show().Focus()
	})
	menu.Add("Show Companion").OnClick(func(_ *application.Context) {
		companionWindow.Reload()
		companionWindow.Show().Focus()
	})
	menu.Add("Hide Companion").OnClick(func(_ *application.Context) {
		companionWindow.Hide()
	})
	menu.AddSeparator()
	menu.Add("Quit").OnClick(func(_ *application.Context) {
		app.Quit()
	})
	tray.SetMenu(menu)
	tray.OnClick(func() {
		if companionWindow.IsVisible() {
			companionWindow.Hide()
			return
		}
		companionWindow.Reload()
		companionWindow.Show().Focus()
	})
}
