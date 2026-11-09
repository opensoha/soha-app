package endpointservice

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var ErrMihomoProcessUnsupported = errors.New("external mihomo process control is unsupported")

// MihomoProcessConfig is operator-owned local configuration, never remote desired state.
type MihomoProcessConfig struct {
	Ownership string `json:"ownership,omitempty"`
	Binary    string `json:"binary,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	Version   string `json:"version,omitempty"`
}

func (c MihomoProcessConfig) validate(configured bool) error {
	if c.Ownership == "" || c.Ownership == "external" {
		if c.Binary != "" || c.SHA256 != "" || c.Version != "" {
			return errors.New("external mihomo cannot configure an owned binary")
		}
		return nil
	}
	digest, err := hex.DecodeString(c.SHA256)
	if !configured || c.Ownership != "soha_owned" || !filepath.IsAbs(c.Binary) || err != nil || len(digest) != 32 || len(c.Version) == 0 || len(c.Version) > 256 || strings.ContainsAny(c.Version, "\r\n") {
		return errors.New("owned mihomo requires a local binary, SHA256 and exact version line")
	}
	return regularFile(c.Binary)
}

type MihomoProcessStatus struct {
	Ownership      string    `json:"ownership"`
	DesiredRunning bool      `json:"desiredRunning"`
	State          string    `json:"state"`
	PID            int       `json:"pid"`
	ProcessEpoch   string    `json:"processEpoch"`
	StartedAt      time.Time `json:"startedAt"`
	BinarySHA256   string    `json:"binarySha256"`
	Version        string    `json:"version"`
}

type mihomoProcess struct {
	mu        sync.Mutex
	config    MihomoProcessConfig
	directory string
	authority string
	cmd       *exec.Cmd
	kill      func() error
	done      chan struct{}
	status    MihomoProcessStatus
	stopped   bool
}

func NewConfiguredMihomoController(config Config, secret string) (*MihomoController, error) {
	if err := config.MihomoProcess.validate(config.MihomoConfigured()); err != nil {
		return nil, err
	}
	controller, err := NewMihomoController(config.MihomoControllerURL, secret)
	if err != nil {
		return nil, err
	}
	controller.probeProfiles = make(map[string]string)
	for id, rawURL := range config.MihomoProbeProfiles {
		if !identifierPattern.MatchString(id) || !validSubscriptionURL(rawURL) {
			return nil, errors.New("invalid operator probe profile")
		}
		controller.probeProfiles[id] = rawURL
	}
	if config.MihomoTransportCAFile != "" {
		raw, err := readFileBounded(config.MihomoTransportCAFile, maxPEMBytes, false)
		if err != nil {
			return nil, err
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(raw) {
			return nil, errors.New("invalid operator transport CA")
		}
		controller.transportTLS = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	}
	if config.MihomoProcess.Ownership == "soha_owned" {
		if !filepath.IsAbs(config.StateDirectory) {
			return nil, errors.New("owned mihomo requires protected state directory")
		}
		directory := filepath.Join(config.StateDirectory, "mihomo-process")
		if err := os.MkdirAll(directory, 0700); err != nil {
			return nil, err
		}
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("unsafe mihomo state directory")
		}
		if err := secureStateDirectory(directory); err != nil {
			return nil, err
		}
		_, err = os.Stat(filepath.Join(directory, "stopped"))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		controller.process = &mihomoProcess{config: config.MihomoProcess, directory: directory, authority: controller.authority, stopped: err == nil, status: MihomoProcessStatus{Ownership: "soha_owned", State: "stopped"}}
	}
	return controller, nil
}

func (c *MihomoController) ProcessStatus() MihomoProcessStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.process == nil {
		return MihomoProcessStatus{Ownership: "external", State: "unsupported"}
	}
	c.process.mu.Lock()
	defer c.process.mu.Unlock()
	status := c.process.status
	status.DesiredRunning = !c.process.stopped
	return status
}

// SetMihomoProcessRunning must be called through CoordinatedExecutor. Resume only
// removes the stop intent; the next authorized configuration performs the start.
func (c *MihomoController) setProcessRunning(ctx context.Context, running bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.process == nil {
		return ErrMihomoProcessUnsupported
	}
	p := c.process
	p.mu.Lock()
	path := filepath.Join(p.directory, "stopped")
	var err error
	if running {
		err = os.Remove(path)
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
	} else {
		err = os.WriteFile(path, []byte("stopped\n"), 0600)
	}
	// Even a failed persistence attempt must stop the current process.
	if !running {
		p.stopped = true
	} else if err == nil {
		p.stopped = false
	}
	p.mu.Unlock()
	if !running {
		gateErr := c.egress.close()
		c.egress = nil
		c.applied = MihomoReadback{}
		return errors.Join(err, gateErr, p.stop(ctx))
	}
	return err
}

func (e *CoordinatedExecutor) SetMihomoProcessRunning(ctx context.Context, running bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	c, ok := e.mihomo.(*MihomoController)
	if !ok {
		return ErrMihomoProcessUnsupported
	}
	if !running {
		if err := e.restoreNativeLocked(ctx, false); err != nil {
			return err
		}
	}
	err := c.setProcessRunning(ctx, running)
	if !running && c.process != nil {
		e.mihomoActive = false
		e.previousMihomo = nil
		e.appStatus = MihomoAppStatus{}
	}
	return err
}

func (c *MihomoController) startOwned(ctx context.Context) error {
	p := c.process
	payload := fmt.Sprintf("mixed-port: 0\nport: 0\nsocks-port: 0\nredir-port: 0\ntproxy-port: 0\nallow-lan: false\nbind-address: %s\nmode: rule\nexternal-controller: %s\nsecret: %s\ntun:\n  enable: false\ndns:\n  enable: false\nproxies: []\nproxy-groups: []\nrules:\n  - MATCH,REJECT\n", yamlString(c.address), yamlString(c.authority), yamlString(c.secret))
	health := func(ctx context.Context) error {
		var result struct {
			Version string `json:"version"`
		}
		return c.request(ctx, http.MethodGet, "/version", nil, http.StatusOK, &result)
	}
	return p.start(ctx, payload, health)
}

// The command output is deliberately discarded after a small cap; it can include secrets.
type cappedOutput struct{ bytes.Buffer }

func (b *cappedOutput) Write(data []byte) (int, error) {
	n := len(data)
	if b.Len() < 4096 {
		remaining := 4096 - b.Len()
		if len(data) > remaining {
			data = data[:remaining]
		}
		_, _ = b.Buffer.Write(data)
	}
	return n, nil
}
func (p *mihomoProcess) check(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	cmd := exec.Command(p.config.Binary, args...)
	cmd.WaitDelay = time.Second
	output := &cappedOutput{}
	cmd.Stdout, cmd.Stderr = output, output
	kill, release, err := startMihomoCommand(cmd)
	if err != nil {
		return "", errors.New("mihomo binary check failed")
	}
	defer release()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return "", errors.New("mihomo binary check failed")
		}
	case <-ctx.Done():
		_ = kill()
		<-done
		return "", errors.New("mihomo binary check timed out")
	}

	return strings.TrimSpace(output.String()), nil
}

func (p *mihomoProcess) start(ctx context.Context, payload string, health func(context.Context) error) (result error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.stopped {
		return errors.New("mihomo is explicitly stopped")
	}
	if p.cmd != nil {
		return nil
	}
	release, err := lockMihomoProcess(filepath.Join(p.directory, "owner.lock"))
	if err != nil {
		return err
	}
	transferred := false
	defer func() {
		if !transferred {
			release()
		}
	}()
	p.status.State = "failed"
	raw, err := readFileBounded(p.config.Binary, 256<<20, false)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), p.config.SHA256) {
		return errors.New("mihomo binary hash mismatch")
	}
	// Copy the verified bytes into the private launch directory so replacement of
	// the operator path cannot change the executable between check and start.
	directory, err := os.MkdirTemp(p.directory, "launch-")
	if err != nil {
		return err
	}
	defer func() {
		if !transferred {
			_ = os.RemoveAll(directory)
		}
	}()
	binary := filepath.Join(directory, "mihomo")
	if strings.EqualFold(filepath.Ext(p.config.Binary), ".exe") {
		binary += ".exe"
	}
	if err = os.WriteFile(binary, raw, 0700); err != nil {
		return err
	}
	original := p.config.Binary
	p.config.Binary = binary
	defer func() { p.config.Binary = original }()
	version, err := p.check(ctx, "-v")
	if err != nil || strings.Split(version, "\n")[0] != p.config.Version {
		return errors.New("mihomo binary version mismatch")
	}
	path := filepath.Join(directory, "config.yaml")
	if err = os.WriteFile(path, []byte(payload), 0600); err != nil {
		return err
	}
	if _, err = p.check(ctx, "-t", "-d", directory, "-f", path); err != nil {
		return err
	}
	probe, err := net.Listen("tcp", p.authority)
	if err != nil {
		return errors.New("mihomo controller port is occupied")
	}
	_ = probe.Close()
	if err = ctx.Err(); err != nil {
		return err
	}
	cmd := exec.Command(binary, "-d", directory, "-f", path)
	cmd.WaitDelay = time.Second
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	kill, releaseProcess, err := startMihomoCommand(cmd)
	if err != nil {
		return errors.New("mihomo process start failed")
	}
	epoch := make([]byte, 16)
	if _, err = rand.Read(epoch); err != nil {
		_ = kill()
		_ = cmd.Wait()
		releaseProcess()
		return err
	}
	done := make(chan struct{})
	p.cmd = cmd
	p.kill = kill
	p.done = done
	p.status = MihomoProcessStatus{Ownership: "soha_owned", State: "starting", PID: cmd.Process.Pid, ProcessEpoch: hex.EncodeToString(epoch), StartedAt: time.Now().UTC(), BinarySHA256: p.config.SHA256, Version: p.config.Version}
	transferred = true
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		releaseProcess()
		close(exited)
		p.mu.Lock()
		p.cmd = nil
		if p.status.State == "stopping" {
			p.status.State = "stopped"
		} else {
			p.status.State = "exited"
		}
		p.status.PID = 0
		_ = os.RemoveAll(directory)
		release()
		close(done)
		p.mu.Unlock()
	}()
	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		attempt, cancelAttempt := context.WithTimeout(healthCtx, 250*time.Millisecond)
		err = health(attempt)
		cancelAttempt()
		select {
		case <-exited:
			p.mu.Unlock()
			<-done
			p.mu.Lock()
			return errors.New("mihomo process exited during startup")
		default:
		}
		if err == nil {
			p.status.State = "running"
			return nil
		}
		select {
		case <-healthCtx.Done():
			_ = kill()
			// Wait outside the mutex so the reaper can publish exit and release the lock.
			p.mu.Unlock()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
			}
			p.mu.Lock()
			return errors.New("mihomo process health timed out")
		case <-ticker.C:
		}
	}
}

func (p *mihomoProcess) stop(ctx context.Context) error {
	p.mu.Lock()
	if p.cmd == nil {
		p.mu.Unlock()
		return nil
	}
	done := p.done
	p.status.State = "stopping"
	// Terminate only the process group/job created for this exact child.
	err := p.kill()
	p.mu.Unlock()
	if err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errors.New("mihomo stop timed out")
	}
}

// Restart keeps the saved stop intent until cleanup succeeds, then waits for a
// fresh authorized Apply to rebuild the gate and configuration.
func (e *CoordinatedExecutor) RestartMihomoProcess(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.restoreNativeLocked(ctx, false); err != nil {
		return err
	}
	c, ok := e.mihomo.(*MihomoController)
	if !ok {
		return ErrMihomoProcessUnsupported
	}
	if err := c.setProcessRunning(ctx, false); err != nil {
		return err
	}
	e.mihomoActive, e.previousMihomo, e.appStatus = false, nil, MihomoAppStatus{}
	return c.setProcessRunning(ctx, true)
}

// nativeOwnedProof reads the actual launch copy and fixed argv while its cmd and
// epoch are still owned. Configuration.Binary is the operator source, not cmd.Path.
func (c *MihomoController) nativeOwnedProof() (nativeOwnedProcessProof, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.process == nil {
		return nativeOwnedProcessProof{}, errors.New("owned native process unavailable")
	}
	p := c.process
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd == nil || p.cmd.Process == nil || p.status.State != "running" || p.status.ProcessEpoch == "" || p.cmd.Process.Pid != p.status.PID {
		return nativeOwnedProcessProof{}, errors.New("owned native process identity changed")
	}
	return nativeOwnedProcessProof{PID: uint32(p.status.PID), ProcessEpoch: p.status.ProcessEpoch, BinarySHA256: p.status.BinarySHA256, ExecutablePath: p.cmd.Path, LaunchDirectory: filepath.Dir(p.cmd.Path), Arguments: append([]string(nil), p.cmd.Args...)}, nil
}

func (c *MihomoController) nativeRecoveryLock(proof nativeOwnedProcessProof) (func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.process == nil {
		return nil, errors.New("owned process recovery lock unavailable")
	}
	p := c.process
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd != nil || filepath.Dir(filepath.Clean(proof.LaunchDirectory)) != filepath.Clean(p.directory) || !strings.HasPrefix(filepath.Base(proof.LaunchDirectory), "launch-") || filepath.Dir(proof.ExecutablePath) != proof.LaunchDirectory || !strings.EqualFold(proof.BinarySHA256, p.config.SHA256) {
		return nil, errors.New("native process launch identity does not match owned state")
	}
	release, err := lockMihomoProcess(filepath.Join(p.directory, "owner.lock"))
	if err != nil {
		return nil, errors.New("native process recovery owner lock is busy")
	}
	return release, nil
}
