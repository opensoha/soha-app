package main

import (
	"embed"
	"log"
	"os"
	"strings"

	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	serverURL := strings.TrimSpace(os.Getenv("SOHA_SERVER_URL"))
	if serverURL == "" {
		serverURL = "http://127.0.0.1:8080"
	}

	handler, err := newAppHandler(application.AssetFileServerFS(assets), serverURL)
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
			ApplicationShouldTerminateAfterLastWindowClosed: true,
		},
	})

	app.Window.NewWithOptions(application.WebviewWindowOptions{
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

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
