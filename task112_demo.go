//go:build task112_demo

package main

import (
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

const task112DemoServer = "http://127.0.0.1:18112"

func validateTask112Demo() error {
	if os.Getenv("SOHA_APP_PROFILE") != "task112-demo" || os.Getenv("SOHA_APP_NATIVE_NETWORK") != "disabled" || os.Getenv("SOHA_SERVER_URL") != task112DemoServer || len(os.Getenv("SOHA_TASK112_DEMO_KEY")) < 24 {
		return errors.New("task112 demo requires its isolated profile, disabled native network, fixed server and demo key")
	}
	return nil
}

func wrapTask112Demo(runtime http.Handler) http.Handler {
	target, _ := url.Parse(task112DemoServer)
	proxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			contentType := request.In.Header.Get("Content-Type")
			request.SetURL(target)
			request.Out.Header = make(http.Header)
			if contentType != "" {
				request.Out.Header.Set("Content-Type", contentType)
			}
			request.Out.Header.Set("X-Soha-Demo-Key", os.Getenv("SOHA_TASK112_DEMO_KEY"))
			request.Out.Header["User-Agent"] = nil
		},
		Transport: &http.Transport{Proxy: nil},
	}
	return &task112DemoHandler{runtime: runtime, proxy: proxy}
}

type task112DemoHandler struct {
	runtime http.Handler
	proxy   *httputil.ReverseProxy
}

func (handler *task112DemoHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if strings.HasPrefix(request.URL.Path, "/app/v1/network/") {
		handler.proxy.ServeHTTP(writer, request)
		return
	}
	handler.runtime.ServeHTTP(writer, request)
}
