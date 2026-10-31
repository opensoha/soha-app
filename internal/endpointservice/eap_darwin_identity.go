//go:build darwin

package endpointservice

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type DarwinEAPSystem struct {
	directory string
	uid       uint32
	home      string
	deviceID  string
}

func NewDarwinEAPSystem(directory, deviceID string, uid uint32) (*DarwinEAPSystem, error) {
	if os.Geteuid() != 0 || uid == 0 || !filepath.IsAbs(directory) || !identifierPattern.MatchString(deviceID) {
		return nil, errors.New("macOS EAP requires the privileged service and an explicit desktop user")
	}
	account, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil || !filepath.IsAbs(account.HomeDir) {
		return nil, errors.New("macOS EAP desktop user has no home directory")
	}
	directory = filepath.Join(directory, "eap")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	if err := secureStateDirectory(directory); err != nil {
		return nil, err
	}
	return &DarwinEAPSystem{directory: directory, uid: uid, home: account.HomeDir, deviceID: deviceID}, nil
}

func (system *DarwinEAPSystem) eapKeyPath(requestID string) string {
	return filepath.Join(system.directory, eapPayloadUUID(requestID)+".key")
}

func (system *DarwinEAPSystem) loadEAPKey(requestID string) (*ecdsa.PrivateKey, error) {
	if !identifierPattern.MatchString(requestID) {
		return nil, errors.New("EAP key identifier is invalid")
	}
	raw, err := readFileBounded(system.eapKeyPath(requestID), 4096, true)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("stored EAP key is invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("stored EAP key is not P-256")
	}
	return key, nil
}

func (system *DarwinEAPSystem) CreateCSR(ctx context.Context, requestID string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !identifierPattern.MatchString(requestID) {
		return "", errors.New("EAP request identifier is invalid")
	}
	key, err := system.loadEAPKey(requestID)
	if errors.Is(err, os.ErrNotExist) {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return "", err
		}
		defer clear(der)
		plain := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		defer clear(plain)
		file, err := os.OpenFile(system.eapKeyPath(requestID), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return "", err
		}
		_, writeErr := file.Write(plain)
		err = errors.Join(writeErr, file.Sync(), file.Close())
		if err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	csrPath := filepath.Join(system.directory, eapPayloadUUID(requestID)+".csr")
	if raw, err := readFileBounded(csrPath, 4096, false); err == nil {
		csr, parseErr := parseEAPCSR(string(raw))
		if parseErr != nil || !key.PublicKey.Equal(csr.PublicKey) {
			return "", errors.New("stored EAP CSR does not match its protected key")
		}
		return string(raw), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "Soha EAP request"}}, key)
	if err != nil {
		return "", err
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	file, err := os.OpenFile(csrPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	_, writeErr := file.Write(raw)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return "", err
	}
	return string(raw), nil
}

func (system *DarwinEAPSystem) ExportProfile(ctx context.Context, requestID string, profile AdmissionProfile, certificate EAPCertificateResult, ethernetPosition int) (EAPStagedProfile, error) {
	key, err := system.loadEAPKey(requestID)
	if err != nil {
		return EAPStagedProfile{}, err
	}
	leaf, err := parseEAPCertificate(certificate.CertificatePEM)
	if err != nil {
		return EAPStagedProfile{}, err
	}
	public, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !key.PublicKey.Equal(public) {
		return EAPStagedProfile{}, errors.New("EAP certificate does not match the protected EAP key")
	}
	csr, err := system.CreateCSR(ctx, requestID)
	if err != nil {
		return EAPStagedProfile{}, err
	}
	if err := validateEAPCertificate(certificate, csr, system.deviceID, profile.Identity, time.Now()); err != nil {
		return EAPStagedProfile{}, err
	}
	passwordBytes := make([]byte, 32)
	if _, err := rand.Read(passwordBytes); err != nil {
		return EAPStagedProfile{}, err
	}
	password := base64.RawURLEncoding.EncodeToString(passwordBytes)
	clear(passwordBytes)
	pkcs12, err := system.eapPKCS12(ctx, requestID, certificate, password)
	if err != nil {
		return EAPStagedProfile{}, err
	}
	defer clear(pkcs12)
	raw, err := renderEAPMobileconfig(profile, system.deviceID, certificate, pkcs12, password, ethernetPosition, time.Now())
	if err != nil {
		return EAPStagedProfile{}, err
	}
	defer clear(raw)
	identityHash, err := eapIdentityPayloadHash(map[string]any{"PayloadContent": pkcs12, "Password": password, "KeyIsExtractable": false, "AllowAllAppsAccess": false})
	if err != nil {
		return EAPStagedProfile{}, err
	}
	path, err := system.exportEAPFile(raw)
	if err != nil {
		return EAPStagedProfile{}, err
	}
	return EAPStagedProfile{EAPArtifact: EAPArtifact{Path: path, SHA256: fmt.Sprintf("%x", sha256.Sum256(raw))}, IdentitySHA256: identityHash}, nil
}

func (system *DarwinEAPSystem) eapPKCS12(ctx context.Context, requestID string, certificate EAPCertificateResult, password string) ([]byte, error) {
	directory, err := os.MkdirTemp(system.directory, ".eap-p12-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(directory)
	if err := os.WriteFile(filepath.Join(directory, "certificate.pem"), []byte(certificate.CertificatePEM), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(directory, "issuer.pem"), []byte(certificate.CACertificatePEM), 0o600); err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, "/usr/bin/openssl", "pkcs12", "-export", "-inkey", system.eapKeyPath(requestID), "-in", filepath.Join(directory, "certificate.pem"), "-certfile", filepath.Join(directory, "issuer.pem"), "-name", "Soha EAP identity", "-passout", "stdin")
	command.Stdin = strings.NewReader(password + "\n")
	command.Stderr = io.Discard
	result, err := command.Output()
	if err != nil {
		clear(result)
		return nil, fmt.Errorf("package dedicated EAP identity: %w", err)
	}
	if len(result) == 0 || len(result) > 65536 {
		clear(result)
		return nil, errors.New("EAP PKCS12 exceeds the safe size")
	}
	return result, nil
}

func (system *DarwinEAPSystem) exportEAPFile(raw []byte) (string, error) {
	root, err := os.OpenRoot(system.home)
	if err != nil {
		return "", err
	}
	defer root.Close()
	relative := filepath.Join("Library", "Application Support", "Soha", "EAP")
	for _, path := range []string{"Library", filepath.Join("Library", "Application Support"), filepath.Join("Library", "Application Support", "Soha"), relative} {
		err := root.Mkdir(path, 0o700)
		created := err == nil
		if err != nil && !errors.Is(err, os.ErrExist) {
			return "", err
		}
		directory, err := root.Open(path)
		if err != nil {
			return "", err
		}
		if created {
			err = directory.Chown(int(system.uid), -1)
		}
		entry, statErr := directory.Stat()
		closeErr := directory.Close()
		if err := errors.Join(err, statErr, closeErr); err != nil {
			return "", err
		}
		stat, ok := entry.Sys().(*syscall.Stat_t)
		if !entry.IsDir() || !ok || stat.Uid != system.uid {
			return "", errors.New("EAP export directory belongs to another user")
		}
	}
	name := filepath.Join(relative, "Soha-EAP-"+randomID()+".mobileconfig")
	receipt := eapExportReceipt{Artifact: EAPArtifact{Path: filepath.Join(system.home, name), SHA256: fmt.Sprintf("%x", sha256.Sum256(raw))}}
	// Journal ownership before exposing any identity bytes in the desktop user's home.
	if err := system.saveExportReceipt(receipt); err != nil {
		return "", err
	}
	complete := false
	defer func() {
		if !complete {
			_ = system.removeEAPArtifact(receipt.Artifact)
		}
	}()
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	created, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return "", err
	}
	identity, ok := created.Sys().(*syscall.Stat_t)
	if !ok {
		_ = file.Close()
		return "", errors.New("EAP export file has no native identity")
	}
	receipt.Device, receipt.Inode = uint64(identity.Dev), identity.Ino
	if err := system.saveExportReceipt(receipt); err != nil {
		_ = file.Close()
		if current, statErr := root.Lstat(name); statErr == nil && current.Mode().IsRegular() && os.SameFile(created, current) {
			_ = root.Remove(name)
		}
		return "", err
	}
	_, writeErr := file.Write(raw)
	err = errors.Join(writeErr, file.Chown(int(system.uid), -1), file.Sync(), file.Close())
	if err != nil {
		if current, statErr := root.Lstat(name); statErr == nil && current.Mode().IsRegular() && os.SameFile(created, current) {
			_ = root.Remove(name)
		}
		return "", err
	}
	receipt.Complete = true
	if err := system.saveExportReceipt(receipt); err != nil {
		return "", err
	}
	complete = true
	return filepath.Join(system.home, name), nil
}
