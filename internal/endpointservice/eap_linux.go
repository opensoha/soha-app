//go:build linux

package endpointservice

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type LinuxEAPSystem struct{ directory, deviceID string }
type linuxEAPRecord struct {
	RequestID, ProfileHash string
	Receipt                nmEAPReceipt
}

func newLinuxEAPSystem(directory, deviceID string) (*LinuxEAPSystem, error) {
	if os.Geteuid() != 0 || !filepath.IsAbs(directory) || !identifierPattern.MatchString(deviceID) {
		return nil, errors.New("Linux EAP requires the root-owned enrolled service")
	}
	directory = filepath.Join(directory, "eap-linux")
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	if err := linuxEAPProtected(directory, true); err != nil {
		return nil, err
	}
	return &LinuxEAPSystem{directory, deviceID}, nil
}
func linuxEAPProtected(path string, private bool) error {
	for current := path; current != "/"; current = filepath.Dir(current) {
		entry, err := os.Lstat(current)
		if err != nil {
			return err
		}
		st, ok := entry.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || entry.Mode()&os.ModeSymlink != 0 || entry.Mode().Perm()&0022 != 0 {
			return errors.New("EAP material path is not root protected")
		}
		if current == path {
			if private && entry.Mode().Perm()&0077 != 0 {
				return os.ErrPermission
			}
			if !entry.IsDir() && !entry.Mode().IsRegular() {
				return os.ErrPermission
			}
		}
	}
	return nil
}
func (s *LinuxEAPSystem) keyPath(id string) string {
	return filepath.Join(s.directory, eapPayloadUUID(id)+".key")
}
func (s *LinuxEAPSystem) CreateCSR(ctx context.Context, id string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !identifierPattern.MatchString(id) {
		return "", errors.New("invalid EAP key identifier")
	}
	path := s.keyPath(id)
	raw, err := readFileBounded(path, 4096, true)
	var key *ecdsa.PrivateKey
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
		raw = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return "", err
		}
		_, werr := file.Write(raw)
		err = errors.Join(werr, file.Sync(), file.Close())
		if err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	defer clear(raw)
	if err := linuxEAPProtected(path, true); err != nil {
		return "", err
	}
	if key == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return "", errors.New("invalid EAP key")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return "", err
		}
		var ok bool
		key, ok = parsed.(*ecdsa.PrivateKey)
		if !ok || key.Curve != elliptic.P256() {
			return "", errors.New("invalid EAP key type")
		}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "Soha EAP request"}}, key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}
func (s *LinuxEAPSystem) Adapters(ctx context.Context) ([]EAPAdapter, error) {
	o, err := newNMDBusOps(ctx)
	if err != nil {
		return nil, err
	}
	defer o.Close()
	devices, err := o.devices(ctx)
	if err != nil {
		return nil, err
	}
	result := []EAPAdapter{}
	for _, d := range devices {
		result = append(result, EAPAdapter{ID: d.Path, Name: d.Interface, Medium: d.Medium, MACAddress: d.MAC, Enabled: d.Managed, LinkUp: d.Managed})
	}
	return result, nil
}
func (s *LinuxEAPSystem) PasswordSupport(ctx context.Context, p AdmissionProfile) (bool, string) {
	o, err := newNMDBusOps(ctx)
	if err != nil {
		return false, "networkmanager_unavailable"
	}
	defer o.Close()
	c, err := o.Capability(ctx)
	if err != nil || !c.TTLSPAP {
		return false, "networkmanager_ttls_pap_unavailable"
	}
	if p.WifiSecurity == "wpa3-enterprise" {
		return false, "networkmanager_wpa3_evidence_required"
	}
	return true, ""
}
func (s *LinuxEAPSystem) recordPath(p AdmissionProfile) string {
	return filepath.Join(s.directory, eapPayloadUUID(s.deviceID+"/"+p.ID)+".json")
}
func (s *LinuxEAPSystem) save(p AdmissionProfile, r linuxEAPRecord) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(s.directory, ".nm-intent-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, werr := file.Write(raw)
	if err := errors.Join(werr, file.Sync(), file.Close()); err != nil {
		return err
	}
	return os.Rename(file.Name(), s.recordPath(p))
}
func (s *LinuxEAPSystem) load(p AdmissionProfile, a EAPAdapter) (linuxEAPRecord, error) {
	var r linuxEAPRecord
	raw, err := readFileBounded(s.recordPath(p), 128<<10, true)
	if err != nil {
		return r, err
	}
	if decodeStrict(raw, &r) != nil || r.ProfileHash != eapProfileHash(p) || r.Receipt.Device.Path != a.ID || r.Receipt.Device.Interface != a.Name || !strings.EqualFold(r.Receipt.Device.MAC, a.MACAddress) || r.Receipt.Device.Medium != a.Medium || r.Receipt.SettingsHash == "" || r.Receipt.SettingsHash != nmEAPSettingsHash(r.Receipt.Settings) || !identifierPattern.MatchString(r.RequestID) || r.Receipt.Incarnation != r.RequestID || r.Receipt.UUID != eapPayloadUUID(s.deviceID+"/"+p.ID+"/"+r.RequestID) || !strings.HasPrefix(r.Receipt.Owner, ":") {
		return r, errors.New("Linux EAP ownership record changed")
	}
	return r, nil
}
func (s *LinuxEAPSystem) input(ctx context.Context, o *nmDBusOps, id string, p AdmissionProfile, a EAPAdapter, cert EAPCertificateResult, password []byte) (nmEAPInput, error) {
	d, err := o.device(ctx, dbusPath(a.ID))
	if err != nil || d.Interface != a.Name || !strings.EqualFold(d.MAC, a.MACAddress) || d.Medium != p.AccessMedium || !d.Managed {
		return nmEAPInput{}, errors.New("Linux EAP adapter changed")
	}
	base := filepath.Join(s.directory, eapPayloadUUID(id))
	ca := filepath.Join(s.directory, eapPayloadUUID(id+"/"+p.ID)+".ca.pem")
	if err := os.WriteFile(ca, []byte(strings.Join(p.CACertificates, "\n")), 0600); err != nil {
		return nmEAPInput{}, err
	}
	m := nmEAPMaterial{Method: admissionMethod(p), InnerMethod: p.InnerMethod, CAFile: ca, Password: password}
	if admissionMethod(p) == "tls" {
		csr, err := s.CreateCSR(ctx, id)
		if err != nil {
			return nmEAPInput{}, err
		}
		if err := validateEAPCertificate(cert, csr, s.deviceID, p.Identity, time.Now()); err != nil {
			return nmEAPInput{}, err
		}
		m.PrivateKeyFile = s.keyPath(id)
		m.ClientCertificateFile = base + ".cert.pem"
		if err := os.WriteFile(m.ClientCertificateFile, []byte(cert.CertificatePEM), 0600); err != nil {
			return nmEAPInput{}, err
		}
	}
	return nmEAPInput{DeviceID: s.deviceID, Incarnation: id, Profile: p, Device: d, Material: m}, nil
}
func (s *LinuxEAPSystem) stage(ctx context.Context, id string, p AdmissionProfile, c EAPCertificateResult, a EAPAdapter) (EAPStagedProfile, error) {
	o, err := newNMDBusOps(ctx)
	if err != nil {
		return EAPStagedProfile{}, err
	}
	defer o.Close()
	if old, err := s.load(p, a); err == nil {
		actual, reused, err := reconcileNMEAPStage(ctx, o, old.Receipt, old.RequestID == id)
		if err != nil {
			return EAPStagedProfile{}, err
		}
		if reused {
			old.Receipt = actual
			return EAPStagedProfile{}, s.save(p, old)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return EAPStagedProfile{}, err
	}
	password := []byte(nil)
	if admissionMethod(p) == "ttls" {
		password = []byte("not-sent")
	}
	input, err := s.input(ctx, o, id, p, a, c, password)
	if err != nil {
		return EAPStagedProfile{}, err
	}
	cap, err := o.Capability(ctx)
	if err != nil {
		return EAPStagedProfile{}, err
	}
	settings, err := buildNMEAPSettings(input, cap, linuxEAPProtected, time.Now())
	if err != nil {
		return EAPStagedProfile{}, err
	}
	delete(settings["802-1x"], "password")
	r := linuxEAPRecord{RequestID: id, ProfileHash: eapProfileHash(p), Receipt: nmEAPReceipt{Settings: settings, Owner: o.owner, UUID: settings["connection"]["uuid"].(string), Incarnation: id, Device: input.Device, SettingsHash: nmEAPSettingsHash(settings)}}
	if err := s.save(p, r); err != nil {
		return EAPStagedProfile{}, err
	}
	r.Receipt.ConnectionPath, err = o.Add(ctx, settings, 0x22)
	if err != nil {
		return EAPStagedProfile{}, errors.New("NetworkManager staging failed; cleanup pending")
	}
	if err := s.save(p, r); err != nil {
		return EAPStagedProfile{}, err
	}
	_, err = o.Inspect(ctx, r.Receipt)
	return EAPStagedProfile{}, err
}
func (s *LinuxEAPSystem) Stage(ctx context.Context, id string, p AdmissionProfile, c EAPCertificateResult, a EAPAdapter) (EAPStagedProfile, error) {
	return s.stage(ctx, id, p, c, a)
}
func (s *LinuxEAPSystem) StagePassword(ctx context.Context, id string, p AdmissionProfile, a EAPAdapter) (EAPStagedProfile, error) {
	return s.stage(ctx, id, p, EAPCertificateResult{}, a)
}
func (s *LinuxEAPSystem) ReadbackPassword(ctx context.Context, id string, p AdmissionProfile, a EAPAdapter) error {
	raw, readErr := readFileBounded(filepath.Join(s.directory, eapPayloadUUID(id+"/"+p.ID)+".ca.pem"), 128<<10, false)
	if readErr != nil || string(raw) != strings.Join(p.CACertificates, "\n") {
		return errors.New("Linux EAP CA material changed")
	}
	r, err := s.load(p, a)
	if err != nil || r.RequestID != id {
		return errors.New("Linux EAP installation is unavailable")
	}
	o, err := newNMDBusOps(ctx)
	if err != nil {
		return err
	}
	defer o.Close()
	actual, inspectErr := o.Inspect(ctx, r.Receipt)
	if inspectErr != nil {
		return inspectErr
	}
	if r.Receipt.ConnectionPath == "" {
		r.Receipt = actual
		return s.save(p, r)
	}
	return nil
}
func (s *LinuxEAPSystem) Readback(ctx context.Context, id string, p AdmissionProfile, c EAPCertificateResult, a EAPAdapter) error {
	raw, err := readFileBounded(filepath.Join(s.directory, eapPayloadUUID(id)+".cert.pem"), 16384, false)
	if err != nil || string(raw) != c.CertificatePEM {
		return errors.New("Linux EAP certificate changed")
	}
	return s.ReadbackPassword(ctx, id, p, a)
}
func (s *LinuxEAPSystem) Connect(ctx context.Context, id string, p AdmissionProfile, c EAPCertificateResult, a EAPAdapter) error {
	if err := s.Readback(ctx, id, p, c, a); err != nil {
		return err
	}
	r, err := s.load(p, a)
	if err != nil {
		return err
	}
	o, err := newNMDBusOps(ctx)
	if err != nil {
		return err
	}
	defer o.Close()
	if err := o.Activate(ctx, r.Receipt); err != nil {
		return err
	}
	if err := o.WaitActivated(ctx, r.Receipt); err != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		return errors.Join(err, o.RemoveOwned(cleanup, r.Receipt))
	}
	return nil
}
func (s *LinuxEAPSystem) ConnectPassword(ctx context.Context, id string, p AdmissionProfile, a EAPAdapter, password []byte) error {
	r, err := s.load(p, a)
	if err != nil {
		return err
	}
	o, err := newNMDBusOps(ctx)
	if err != nil {
		return err
	}
	defer o.Close()
	if err := o.RemoveOwned(ctx, r.Receipt); err != nil {
		return err
	}
	input, err := s.input(ctx, o, id, p, a, EAPCertificateResult{}, password)
	if err != nil {
		return err
	}
	_, err = connectNMEAP(ctx, o, input, linuxEAPProtected, time.Now(), func(receipt nmEAPReceipt) error { r.Receipt = receipt; return s.save(p, r) })
	return err
}
func (s *LinuxEAPSystem) Remove(ctx context.Context, p AdmissionProfile, a EAPAdapter, _ []EAPProfileIdentity) error {
	r, err := s.load(p, a)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	o, err := newNMDBusOps(ctx)
	if err != nil {
		return err
	}
	defer o.Close()
	if err := o.RemoveOwned(ctx, r.Receipt); err != nil {
		return err
	}
	ca := filepath.Join(s.directory, eapPayloadUUID(r.RequestID+"/"+p.ID)+".ca.pem")
	if err := linuxEAPProtected(ca, false); err == nil {
		if err := os.Remove(ca); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Remove(s.recordPath(p))
}
func (s *LinuxEAPSystem) Cleanup(ctx context.Context, c EAPCleanup) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.RequestID == "" {
		return nil
	}
	if !identifierPattern.MatchString(c.RequestID) {
		return errors.New("invalid EAP cleanup request")
	}
	for _, suffix := range []string{".key", ".ca.pem", ".cert.pem"} {
		path := filepath.Join(s.directory, eapPayloadUUID(c.RequestID)+suffix)
		if err := linuxEAPProtected(path, suffix == ".key"); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	return nil
}
func (s *LinuxEAPSystem) RecoverArtifacts(context.Context, []EAPArtifact) error { return nil }

func (s *LinuxEAPSystem) TLSSupport(ctx context.Context, p AdmissionProfile) (bool, string) {
	o, err := newNMDBusOps(ctx)
	if err != nil {
		return false, "networkmanager_unavailable"
	}
	defer o.Close()
	c, err := o.Capability(ctx)
	if err != nil || !c.TLS {
		return false, "networkmanager_tls_unavailable"
	}
	if p.WifiSecurity == "wpa3-enterprise" {
		return false, "networkmanager_wpa3_evidence_required"
	}
	return true, ""
}
