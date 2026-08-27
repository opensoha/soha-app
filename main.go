package main

import (
	"embed"
	"errors"
	"log"
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
		log.Fatal("level=ERROR event=app_paths_unavailable")
	}
	appVersion := resolvedAppVersion()
	logCloser, err := configureAppLogging(logDirectory, appVersion)
	if err != nil {
		log.Print("level=WARN event=file_logging_unavailable")
	} else {
		defer logCloser.Close()
	}
	log.Printf("level=INFO event=app_start platform=%s arch=%s", runtime.GOOS, runtime.GOARCH)
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
		log.Fatal("level=ERROR event=server_configuration_invalid")
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
				log.Print("level=INFO event=second_instance_received")
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
		log.Printf("level=WARN event=app_updater_unavailable error=%q", err)
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
		log.Fatal(err)
	}
	companionWindow := newCompanionWindow(app, positions)
	configureSystemTray(app, window, companionWindow, trayIcon)

	if err := app.Run(); err != nil {
		log.Fatal("level=ERROR event=app_run_failed")
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
		log.Print("level=WARN event=saved_configuration_ignored")
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
