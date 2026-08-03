package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const apiPrefix = "/api/v1"

func newAppHandler(static http.Handler, rawServerURL string) (http.Handler, error) {
	target, err := url.Parse(rawServerURL)
	if err != nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") {
		return nil, fmt.Errorf("invalid SOHA_SERVER_URL %q", rawServerURL)
	}
	if target.User != nil || target.RawQuery != "" || target.Fragment != "" {
		return nil, fmt.Errorf("SOHA_SERVER_URL must not contain credentials, query, or fragment")
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	director := proxy.Director
	proxy.Director = func(request *http.Request) {
		director(request)
		request.Header.Del("Origin")
	}
	proxy.ErrorHandler = func(writer http.ResponseWriter, _ *http.Request, proxyErr error) {
		log.Printf("Soha API is unavailable: %v", proxyErr)
		http.Error(writer, `{"error":{"code":"upstream_unavailable","message":"Soha server is unavailable"}}`, http.StatusBadGateway)
	}

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == apiPrefix || strings.HasPrefix(request.URL.Path, apiPrefix+"/") {
			proxy.ServeHTTP(writer, request)
			return
		}
		static.ServeHTTP(writer, request)
	}), nil
}
