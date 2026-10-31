package endpointservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"time"
)

type eapLimitedOutput struct {
	bytes.Buffer
	limit int
}

func (output *eapLimitedOutput) Write(raw []byte) (int, error) {
	if len(raw) > output.limit-output.Len() {
		return 0, errors.New("native EAP output exceeds the safe size")
	}
	return output.Buffer.Write(raw)
}

func eapCommandOutput(ctx context.Context, limit int, path string, args ...string) ([]byte, error) {
	operationCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	command := exec.CommandContext(operationCtx, path, args...)
	output := &eapLimitedOutput{limit: limit}
	command.Stdout, command.Stderr = output, io.Discard
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("native EAP command failed: %w", err)
	}
	return output.Bytes(), nil
}
