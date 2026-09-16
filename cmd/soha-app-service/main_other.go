//go:build !windows && !darwin

package main

import (
	"fmt"
	"os"
)

func main() {
	_, _ = fmt.Fprintln(os.Stderr, "soha-app-service is supported on Windows and macOS only")
	os.Exit(1)
}
