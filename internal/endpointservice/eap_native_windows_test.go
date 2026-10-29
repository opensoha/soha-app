//go:build windows && eap_native_lab

package endpointservice

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This tagged test binary is installed only in the explicitly authorized lab VM.
func TestMain(tests *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "eap-user-helper" {
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, (256<<10)+1))
		var request eapUserRequest
		if err == nil && len(raw) <= 256<<10 {
			err = decodeStrict(raw, &request)
		}
		if err == nil {
			if strings.HasPrefix(request.Action, "lab_") {
				err = runWindowsEAPLabAssertion(request)
				if err == nil {
					err = json.NewEncoder(os.Stdout).Encode(eapUserResponse{OK: true})
				}
			} else {
				ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
				defer cancel()
				err = RunEAPUserHelper(ctx, bytes.NewReader(raw), os.Stdout)
			}
		}
		if err != nil {
			if file, openErr := os.OpenFile(filepath.Join(os.TempDir(), "soha-task53-eap-lab-errors.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); openErr == nil {
				_, _ = fmt.Fprintln(file, request.Action, err)
				_ = file.Close()
			}
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(tests.Run())
}

func windowsEAPLabSystem(t *testing.T) (*WindowsEAPSystem, EAPAdapter) {
	t.Helper()
	var marker struct {
		Task       string `json:"task"`
		VMID       int    `json:"vmid"`
		UserSID    string `json:"userSid"`
		AdapterMAC string `json:"adapterMac"`
	}
	raw, err := readFileBounded(`C:\ProgramData\OpenSoha\Task53-Lab\marker.json`, 4096, true)
	if err != nil || decodeStrict(raw, &marker) != nil || marker.Task != "task53" || marker.VMID != 1532 || !validSID(marker.UserSID) || marker.AdapterMAC == "" {
		t.Fatal("native tests require the protected Task53 VM 1532 lab marker")
	}
	if _, lease, err := trustedEAPHelperExecutable(); err != nil {
		t.Fatal(err)
	} else {
		_ = windows.CloseHandle(lease)
	}
	system, err := NewWindowsEAPSystem(t.TempDir(), "task53-native-"+randomID(), marker.UserSID)
	if err != nil {
		t.Fatal(err)
	}
	adapters, err := system.Adapters(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, adapter := range adapters {
		if adapter.Medium == "wired" && strings.EqualFold(adapter.MACAddress, marker.AdapterMAC) {
			return system, adapter
		}
	}
	t.Fatal("authorized lab adapter was not found")
	return nil, EAPAdapter{}
}

func windowsEAPLabCA(t *testing.T, name string) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func windowsEAPLabCertificate(t *testing.T, deviceID, csrPEM string) (EAPCertificateResult, AdmissionProfile, string) {
	t.Helper()
	csr, err := parseEAPCSR(csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	ca, key, encoded := windowsEAPLabCA(t, "Task53 native EAP issuer")
	_, _, server := windowsEAPLabCA(t, "Task53 owned server root")
	_, _, preexisting := windowsEAPLabCA(t, "Task53 preexisting server root")
	uri, _ := url.Parse("spiffe://opensoha.local/network-eap/endpoint/" + deviceID)
	now := time.Now().UTC().Truncate(time.Second)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "subject-1"}, URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute)}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	result := EAPCertificateResult{CredentialID: randomID(), CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), CACertificatePEM: encoded, Fingerprint: fmt.Sprintf("sha256:%x", sha256.Sum256(der)), ExpiresAt: leaf.NotAfter, Status: "pending"}
	profile := AdmissionProfile{ID: randomID(), SiteID: "site-1", AccessMedium: "wired", Identity: "subject-1", ServerNames: []string{"radius.example.test"}, CACertificates: []string{server, preexisting}}
	return result, profile, preexisting
}

func TestWindowsNativeEAPIdentityLifecycle(t *testing.T) {
	system, _ := windowsEAPLabSystem(t)
	ctx := context.Background()
	requestID := randomID()
	job := EAPCleanup{RequestID: requestID}
	preexisting := ""
	recovery := saveWindowsEAPLabRecovery(t, system, job, preexisting)
	t.Cleanup(func() {
		err := system.Cleanup(ctx, job)
		if preexisting != "" {
			_, removeErr := callEAPUserHelper(ctx, system.userSID, eapUserRequest{Action: "lab_remove_preexisting", DeviceID: system.deviceID, RequestID: requestID, Profile: &AdmissionProfile{CACertificates: []string{preexisting}}})
			err = errors.Join(err, removeErr)
		}
		if err != nil {
			t.Error(err)
		} else if err := os.Remove(recovery); err != nil {
			t.Error(err)
		}
	})
	csr, err := system.CreateCSR(ctx, requestID)
	if err != nil {
		t.Fatal(err)
	}
	certificate, profile, existingRoot := windowsEAPLabCertificate(t, system.deviceID, csr)
	preexisting = existingRoot
	job.Certificate = &certificate
	job.CACertificates = append([]string{certificate.CACertificatePEM}, profile.CACertificates...)
	saveWindowsEAPLabRecovery(t, system, job, preexisting)
	publicRoots := &AdmissionProfile{CACertificates: []string{preexisting}}
	call := func(action string, cleanup *EAPCleanup) error {
		_, err := callEAPUserHelper(ctx, system.userSID, eapUserRequest{Action: action, DeviceID: system.deviceID, RequestID: requestID, Profile: publicRoots, Cleanup: cleanup})
		return err
	}
	if err := call("lab_seed_preexisting", nil); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"install", "readback"} {
		result, err := callEAPUserHelper(ctx, system.userSID, eapUserRequest{Action: action, DeviceID: system.deviceID, RequestID: requestID, Profile: &profile, Certificate: &certificate})
		if err != nil || result.Fingerprint != certificate.Fingerprint {
			t.Fatalf("%s: %v", action, err)
		}
	}
	if err := call("lab_assert_nonexportable", nil); err != nil {
		t.Fatal(err)
	}
	if err := system.Cleanup(ctx, job); err != nil {
		t.Fatal(err)
	}
	if err := call("lab_assert_retired", &job); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsNativeUserHelperIsolation(t *testing.T) {
	system, _ := windowsEAPLabSystem(t)
	request := eapUserRequest{Action: "lab_assert_desktop", DeviceID: system.deviceID, RequestID: randomID(), Profile: &AdmissionProfile{}}
	if _, err := callEAPUserHelper(context.Background(), system.userSID, request); err != nil {
		t.Fatal("user desktop startup parameters:", err)
	}
	request.Action = "lab_process_oversize"
	if _, err := callEAPUserHelper(context.Background(), system.userSID, request); err == nil {
		t.Fatal("oversized helper output was accepted")
	}
	request.Action = "lab_process_wait"
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := callEAPUserHelper(ctx, system.userSID, request); err == nil || time.Since(started) > 5*time.Second {
		t.Fatalf("helper cancellation did not terminate promptly: %v", err)
	}
}

func TestWindowsNativeEAPWiredProfileRecovery(t *testing.T) {
	system, adapter := windowsEAPLabSystem(t)
	ctx := context.Background()
	baseline, err := system.lanProfile(ctx, adapter)
	if err != nil || !eapWindowsLANBaselineAllowed(baseline) {
		t.Fatalf("lab wired baseline is unavailable or already uses 802.1X: %v", err)
	}
	requestID := randomID()
	job := EAPCleanup{RequestID: requestID}
	recovery := saveWindowsEAPLabRecovery(t, system, job, "")
	t.Cleanup(func() {
		if err := system.Cleanup(ctx, job); err != nil {
			t.Error(err)
		} else if err := os.Remove(recovery); err != nil {
			t.Error(err)
		}
	})
	csr, err := system.CreateCSR(ctx, requestID)
	if err != nil {
		t.Fatal(err)
	}
	certificate, profile, _ := windowsEAPLabCertificate(t, system.deviceID, csr)
	job.Certificate = &certificate
	job.CACertificates = append([]string{certificate.CACertificatePEM}, profile.CACertificates...)
	saveWindowsEAPLabRecovery(t, system, job, "")
	t.Cleanup(func() {
		if err := system.Remove(ctx, profile, adapter, []EAPProfileIdentity{{Fingerprint: certificate.Fingerprint}}); err != nil {
			t.Error("native remove failed:", err)
			if restoreErr := system.setLANProfile(ctx, adapter, baseline); restoreErr != nil {
				t.Error("lab recovery failed:", restoreErr)
			}
		}
	})
	if _, err := system.Stage(ctx, requestID, profile, certificate, adapter); err != nil {
		t.Fatal(err)
	}
	if err := system.Readback(ctx, requestID, profile, certificate, adapter); err != nil {
		t.Fatal(err)
	}
	if err := system.Remove(ctx, profile, adapter, []EAPProfileIdentity{{Fingerprint: certificate.Fingerprint}}); err != nil {
		t.Fatal(err)
	}
	actual, err := system.lanProfile(ctx, adapter)
	if err != nil || matchEAPWindowsXML(actual, baseline) != nil {
		t.Fatalf("original wired profile was not restored: %v", err)
	}
}

func saveWindowsEAPLabRecovery(t *testing.T, system *WindowsEAPSystem, job EAPCleanup, preexisting string) string {
	t.Helper()
	directory := `C:\ProgramData\OpenSoha\Task53-Lab`
	path := filepath.Join(directory, "recovery-"+eapPayloadUUID(system.deviceID+"/"+job.RequestID)+".json")
	raw, err := json.Marshal(struct {
		Task        string     `json:"task"`
		VMID        int        `json:"vmid"`
		UserSID     string     `json:"userSid"`
		DeviceID    string     `json:"deviceId"`
		Cleanup     EAPCleanup `json:"cleanup"`
		Preexisting string     `json:"preexistingRoot,omitempty"`
	}{"task53", 1532, system.userSID, system.deviceID, job, preexisting})
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.CreateTemp(directory, ".recovery-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(raw)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(file.Name(), path); err != nil {
		t.Fatal(err)
	}
	return path
}

func traceWindowsEAPLabRoot(request eapUserRequest, phase string) error {
	path := filepath.Join(os.TempDir(), "soha-task53-root-"+request.RequestID+".log")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := fmt.Fprintln(file, request.Action, phase)
	return errors.Join(writeErr, file.Sync(), file.Close())
}

func runWindowsEAPLabAssertion(request eapUserRequest) error {
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || current.User.Sid.IsWellKnown(windows.WinLocalSystemSid) || current.User.Sid.String() != request.ExpectedSID || !strings.HasPrefix(request.DeviceID, "task53-native-") || !identifierPattern.MatchString(request.DeviceID) || !identifierPattern.MatchString(request.RequestID) || request.Profile == nil {
		return errors.New("native test assertion has an invalid user or device")
	}
	switch request.Action {
	case "lab_assert_desktop":
		var info windows.StartupInfo
		if err := windows.GetStartupInfo(&info); err != nil || !strings.EqualFold(windows.UTF16PtrToString(info.Desktop), `winsta0\default`) {
			return errors.New("helper startup does not specify the interactive user desktop")
		}
	case "lab_process_oversize":
		_, err := os.Stdout.Write(bytes.Repeat([]byte("x"), (256<<10)+1))
		return err
	case "lab_process_wait":
		time.Sleep(time.Minute)
	case "lab_ui_pipe_client":
		return windowsNativeUIPipeClient(request.RequestID)
	case "lab_seed_preexisting", "lab_remove_preexisting":
		for _, encoded := range request.Profile.CACertificates {
			certificate, err := parseEAPCertificate(encoded)
			if err != nil {
				return err
			}
			if err := traceWindowsEAPLabRoot(request, "open"); err != nil {
				return err
			}
			store, err := openEAPUserStore("ROOT")
			if err != nil {
				return err
			}
			if err := traceWindowsEAPLabRoot(request, "opened"); err != nil {
				return err
			}
			defer windows.CertCloseStore(store, 0)
			if request.Action == "lab_seed_preexisting" {
				context, err := windows.CertCreateCertificateContext(windows.X509_ASN_ENCODING, &certificate.Raw[0], uint32(len(certificate.Raw)))
				if err != nil {
					return err
				}
				defer windows.CertFreeCertificateContext(context)
				if err := traceWindowsEAPLabRoot(request, "add"); err != nil {
					return err
				}
				if err := windows.CertAddCertificateContextToStore(store, context, windows.CERT_STORE_ADD_NEW, nil); err != nil {
					return err
				}
				if err := traceWindowsEAPLabRoot(request, "added"); err != nil {
					return err
				}
			} else {
				digest := sha1.Sum(certificate.Raw)
				query := windows.CryptHashBlob{Size: uint32(len(digest)), Data: &digest[0]}
				context, err := windows.CertFindCertificateInStore(store, windows.X509_ASN_ENCODING, 0, windows.CERT_FIND_SHA1_HASH, unsafe.Pointer(&query), nil)
				if err != nil {
					if uint32Error(err) == uint32(windows.CRYPT_E_NOT_FOUND) {
						continue
					}
					return err
				}
				if context.Length != uint32(len(certificate.Raw)) || !bytes.Equal(unsafe.Slice(context.EncodedCert, context.Length), certificate.Raw) {
					_ = windows.CertFreeCertificateContext(context)
					return errors.New("lab certificate does not match its exact DER")
				}
				if err := windows.CertDeleteCertificateFromStore(context); err != nil {
					return err
				}
			}
		}
	case "lab_assert_nonexportable":
		key, err := openEAPCNGKey(request.DeviceID, request.RequestID, false)
		if err != nil {
			return err
		}
		defer key.Close()
		var size uint32
		if err := callEAPCNG(eapNCryptExportKey, key.key, 0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("ECCPRIVATEBLOB"))), 0, 0, 0, uintptr(unsafe.Pointer(&size)), 0); err != eapCNGStatus(0x80090010) && err != eapCNGStatus(0x80090029) {
			return fmt.Errorf("native CNG private-key export was not denied by policy: %v", err)
		}
	case "lab_assert_retired":
		if request.Cleanup == nil || request.Cleanup.Certificate == nil {
			return errors.New("native retirement assertion has no certificate")
		}
		key, err := openEAPCNGKey(request.DeviceID, request.RequestID, false)
		if err != eapCNGStatus(0x80090016) && err != eapCNGStatus(0x80090011) {
			if key != nil {
				key.Close()
			}
			return errors.New("native CNG key was not confirmed absent")
		}
		leaf, err := parseEAPCertificate(request.Cleanup.Certificate.CertificatePEM)
		if err != nil || readbackEAPUserCertificate(leaf) == nil {
			return errors.New("retired native EAP certificate is still usable")
		}
		for _, encoded := range request.Cleanup.CACertificates {
			if slices.Contains(request.Profile.CACertificates, encoded) {
				continue
			}
			certificate, err := parseEAPCertificate(encoded)
			if err != nil {
				return err
			}
			if readbackEAPPublicCertificate("CA", certificate) == nil || readbackEAPPublicCertificate("ROOT", certificate) == nil {
				return errors.New("owned EAP trust certificate was not retired")
			}
		}
		for _, encoded := range request.Profile.CACertificates {
			certificate, err := parseEAPCertificate(encoded)
			if err != nil || readbackEAPPublicCertificate("ROOT", certificate) != nil {
				return errors.New("preexisting user trust certificate was removed")
			}
		}
	default:
		return errors.New("unknown native lab assertion")
	}
	return nil
}
