//go:build !task112_demo

package main

import "net/http"

func validateTask112Demo() error                        { return nil }
func wrapTask112Demo(runtime http.Handler) http.Handler { return runtime }
