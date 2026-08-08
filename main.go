package main

import (
	"embed"
	"log"
	"os"
	"strings"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/appicon.png
var trayIcon []byte

func main() {
	serverURL := strings.TrimSpace(os.Getenv("SOHA_SERVER_URL"))
	if serverURL == "" {
		serverURL = "http://127.0.0.1:8080"
	}
	catalogPath := strings.TrimSpace(os.Getenv("SOHA_APP_SOFTWARE_CATALOG"))
	var catalog softwareCatalog
	if catalogPath != "" {
		catalog = fileSoftwareCatalog{path: catalogPath}
	} else {
		remoteCatalog, err := newServerSoftwareCatalog(serverURL)
		if err != nil {
			log.Fatal(err)
		}
		catalog = remoteCatalog
	}

	runtimeAPI := &appRuntime{
		version:  appVersion,
		software: newSoftwareLibrary(catalog),
	}
	handler, err := newAppHandler(application.AssetFileServerFS(assets), runtimeAPI, serverURL)
	if err != nil {
		log.Fatal(err)
	}

	app := application.New(application.Options{
		Name:        "Soha",
		Description: "Soha endpoint client",
		Assets: application.AssetOptions{
			Handler: handler,
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: false,
		},
	})
	runtimeAPI.software.openFile = app.Browser.OpenFile
	if err := configureAppUpdater(app.Context(), runtimeAPI, app.Updater); err != nil {
		log.Printf("Soha updates are unavailable: %v", err)
	}

	mainWindow := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:     "Soha",
		Width:     1100,
		Height:    760,
		MinWidth:  360,
		MinHeight: 640,
		Mac: application.MacWindow{
			InvisibleTitleBarHeight: 50,
			Backdrop:                application.MacBackdropTranslucent,
			TitleBar:                application.MacTitleBarHiddenInset,
		},
		BackgroundColour: application.NewRGB(248, 248, 248),
		URL:              "/",
	})
	mainWindow.RegisterHook(events.Common.WindowClosing, func(event *application.WindowEvent) {
		mainWindow.Hide()
		event.Cancel()
	})
	positions, err := defaultWindowPositionStore()
	if err != nil {
		log.Fatal(err)
	}
	companionWindow := newCompanionWindow(app, positions)
	configureSystemTray(app, mainWindow, companionWindow, trayIcon)

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
