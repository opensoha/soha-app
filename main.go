package main

import (
	"embed"
	"errors"
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

const fallbackAppVersion = "0.1.0"

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/appicon.png
var trayIcon []byte

func main() {
	configPath, logDirectory, err := appPaths()
	if err != nil {
		appLog.Error("application paths unavailable", "component", "startup", "event", "app.paths.unavailable", "error", err, "error_type", logErrorType(err))
		os.Exit(1)
	}
	appVersion := resolvedAppVersion()
	logCloser, err := configureAppLogging(logDirectory, appVersion)
	if err != nil {
		appLog.Warn("file logging unavailable", "component", "startup", "event", "app.logging.file_unavailable", "error", err, "error_type", logErrorType(err))
	} else {
		defer logCloser.Close()
	}
	appLog.Info("application started", "component", "startup", "event", "app.started", "platform", runtime.GOOS, "arch", runtime.GOARCH)
	config := newConfigStore(configPath)
	serverURL, locked, source, credentialsBlocked := initialServerConfiguration(config)

	host, err := newAppHost(
		application.AssetFileServerFS(assets),
		serverURL,
		config,
		locked,
		source,
		AppInfo{
			Name:            "Soha",
			Version:         appVersion,
			Platform:        runtime.GOOS,
			Arch:            runtime.GOARCH,
			LogDirectory:    logDirectory,
			UpdateSupported: false,
		},
		systemKeyring{},
	)
	if err != nil {
		appLog.Error("server configuration invalid", "component", "startup", "event", "app.server.configuration_invalid", "error", err, "error_type", logErrorType(err))
		os.Exit(1)
	}
	host.credentialsBlocked.Store(credentialsBlocked)

	catalogPath := strings.TrimSpace(os.Getenv("SOHA_APP_SOFTWARE_CATALOG"))
	var catalog softwareCatalog
	if catalogPath != "" {
		catalog = fileSoftwareCatalog{path: catalogPath}
	} else {
		catalog = activeServerSoftwareCatalog{host: host}
	}
	runtimeAPI := &appRuntime{
		version:  appVersion,
		software: newSoftwareLibrary(catalog),
	}
	host.setRuntimeAPI(runtimeAPI)

	var window *application.WebviewWindow
	app := application.New(application.Options{
		Name:        "Soha",
		Description: "Soha endpoint client",
		SingleInstance: &application.SingleInstanceOptions{
			UniqueID: "com.opensoha.app",
			OnSecondInstanceLaunch: func(application.SecondInstanceData) {
				appLog.Info("second application instance received", "component", "runtime", "event", "app.second_instance.received")
				if window == nil {
					return
				}
				window.Restore()
				window.Focus()
			},
		},
		Assets: application.AssetOptions{
			Handler: host,
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: false,
		},
	})
	runtimeAPI.software.openFile = app.Browser.OpenFile
	if err := configureAppUpdater(app.Context(), runtimeAPI, app.Updater); err != nil {
		appLog.Warn("application updates are unavailable", "component", "updater", "event", "app.updater.unavailable", "error", err, "error_type", logErrorType(err))
	}
	host.appInfo.UpdateSupported = runtimeAPI.updater != nil

	host.setOpenLogDirectory(func() error {
		if err := os.MkdirAll(logDirectory, 0o700); err != nil {
			return err
		}
		return app.Browser.OpenFile(logDirectory)
	})
	host.setOpenBrowserURL(app.Browser.OpenURL)

	window = app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:                      "Soha",
		Width:                      1100,
		Height:                     760,
		MinWidth:                   960,
		MinHeight:                  640,
		DefaultContextMenuDisabled: true,
		DevToolsEnabled:            false,
		Mac: application.MacWindow{
			InvisibleTitleBarHeight: 50,
			Backdrop:                application.MacBackdropTranslucent,
			TitleBar:                application.MacTitleBarHiddenInset,
		},
		BackgroundColour: application.NewRGB(247, 248, 250),
		URL:              "/",
	})
	window.RegisterHook(events.Common.WindowClosing, func(event *application.WindowEvent) {
		window.Hide()
		event.Cancel()
	})
	positions, err := defaultWindowPositionStore()
	if err != nil {
		appLog.Error("companion window state initialization failed", "component", "companion", "event", "app.companion.state_initialization_failed", "error", err, "error_type", logErrorType(err))
		os.Exit(1)
	}
	companionWindow := newCompanionWindow(app, positions)
	configureSystemTray(app, window, companionWindow, trayIcon)

	if err := app.Run(); err != nil {
		appLog.Error("application runtime stopped with an error", "component", "runtime", "event", "app.runtime.failed", "error", err, "error_type", logErrorType(err))
		os.Exit(1)
	}
}

func initialServerConfiguration(store *configStore) (serverURL string, locked bool, source string, credentialsBlocked bool) {
	if environmentURL := strings.TrimSpace(os.Getenv("SOHA_SERVER_URL")); environmentURL != "" {
		normalized, normalizeErr := normalizeServerURL(environmentURL)
		config, loadErr := store.Load()
		blocked := normalizeErr == nil && loadErr == nil && config.ServerURL == normalized && config.CredentialsBlocked
		return environmentURL, true, "environment", blocked
	}
	config, err := store.Load()
	if err == nil {
		return config.ServerURL, false, "saved", config.CredentialsBlocked
	}
	if !errors.Is(err, os.ErrNotExist) {
		appLog.Warn("saved configuration ignored", "component", "startup", "event", "app.configuration.saved_ignored", "error", err, "error_type", logErrorType(err))
	}
	return defaultServerURL, false, "default", false
}

func resolvedAppVersion() string {
	build, ok := debug.ReadBuildInfo()
	if ok && build.Main.Version != "" && build.Main.Version != "(devel)" {
		return build.Main.Version
	}
	return fallbackAppVersion
}
