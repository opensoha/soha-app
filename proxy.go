package main

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const apiPrefix = "/api/v1"
const appPrefix = "/app/v1"

func newAppHandler(static, runtimeAPI http.Handler, rawServerURL string) (http.Handler, error) {
	target, err := parseServerURL(rawServerURL)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	director := proxy.Director
	proxy.Director = func(request *http.Request) {
		director(request)
		request.Header.Del("Origin")
	}
	proxy.ModifyResponse = func(response *http.Response) error {
		response.Header.Set("X-Request-Id", response.Request.Header.Get("X-Request-Id"))
		return nil
	}
	proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, proxyErr error) {
		requestID := request.Header.Get("X-Request-Id")
		appLog.Error("Soha server is unavailable", "request_id", requestID, "component", "http_proxy", "event", "app.proxy.upstream_unavailable", "error_type", logErrorType(proxyErr))
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.Header().Set("X-Request-Id", requestID)
		writeJSON(writer, http.StatusBadGateway, map[string]any{"error": map[string]string{
			"code":       "upstream_unavailable",
			"message":    "Soha server is unavailable",
			"request_id": requestID,
		}})
	}

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestID := ensureRequestID(request)
		if request.URL.Path == appPrefix || strings.HasPrefix(request.URL.Path, appPrefix+"/") {
			writer.Header().Set("X-Request-Id", requestID)
			runtimeAPI.ServeHTTP(writer, request)
			return
		}
		if request.URL.Path == apiPrefix || strings.HasPrefix(request.URL.Path, apiPrefix+"/") {
			proxy.ServeHTTP(writer, request)
			return
		}
		writer.Header().Set("X-Request-Id", requestID)
		static.ServeHTTP(writer, request)
	}), nil
}

func ensureRequestID(request *http.Request) string {
	requestID := strings.TrimSpace(request.Header.Get("X-Request-Id"))
	if !validRequestID(requestID) {
		requestID = rand.Text()
	}
	request.Header.Set("X-Request-Id", requestID)
	return requestID
}

func validRequestID(requestID string) bool {
	if requestID == "" || len(requestID) > 128 {
		return false
	}
	for _, char := range requestID {
		if !((char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || strings.ContainsRune("._:-", char)) {
			return false
		}
	}
	return true
}

func parseServerURL(rawServerURL string) (*url.URL, error) {
	target, err := url.Parse(rawServerURL)
	if err != nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") {
		return nil, fmt.Errorf("invalid SOHA_SERVER_URL %q", rawServerURL)
	}
	if target.User != nil || target.RawQuery != "" || target.Fragment != "" {
		return nil, fmt.Errorf("SOHA_SERVER_URL must not contain credentials, query, or fragment")
	}
	return target, nil
}
