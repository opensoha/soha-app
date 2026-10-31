//go:build windows

package endpointservice

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

func RunEAPUserHelper(ctx context.Context, input io.Reader, output io.Writer) error {
	raw, err := io.ReadAll(io.LimitReader(input, (256<<10)+1))
	if err != nil || len(raw) > 256<<10 {
		return errors.New("EAP user request exceeds the safe size")
	}
	var request eapUserRequest
	if err := decodeStrict(raw, &request); err != nil {
		return errors.New("EAP user request is invalid")
	}
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || current.User.Sid.IsWellKnown(windows.WinLocalSystemSid) || current.User.Sid.String() != request.ExpectedSID || !identifierPattern.MatchString(request.DeviceID) || request.Action != "network_remove" && request.Action != "cleanup" && !identifierPattern.MatchString(request.RequestID) {
		return errors.New("EAP user request identity is invalid")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var response eapUserResponse
	if request.Cleanup != nil && request.Action != "cleanup" {
		return errors.New("EAP request has unrelated cleanup parameters")
	}
	if strings.HasPrefix(request.Action, "network_") {
		if request.Profile == nil || request.Adapter == nil || !identifierPattern.MatchString(request.Profile.ID) || request.Profile.AccessMedium != request.Adapter.Medium {
			return errors.New("EAP network request has no valid profile or adapter")
		}
		if err := validateWindowsEAPAdapter(ctx, *request.Adapter, request.Action != "network_remove"); err != nil {
			return err
		}
	} else if request.Adapter != nil || len(request.ExpectedXML) != 0 {
		return errors.New("EAP identity request has unrelated network parameters")
	}
	switch request.Action {
	case "cleanup":
		if request.Cleanup == nil || request.Profile != nil || request.Certificate != nil || request.Cleanup.RequestID != request.RequestID {
			return errors.New("EAP cleanup request has unrelated parameters")
		}
		if err := cleanupWindowsEAPUser(request.DeviceID, *request.Cleanup); err != nil {
			return err
		}
	case "csr":
		if request.Profile != nil || request.Certificate != nil {
			return errors.New("EAP CSR request has unrelated parameters")
		}
		key, err := openEAPCNGKey(request.DeviceID, request.RequestID, true)
		if err != nil {
			return err
		}
		defer key.Close()
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "Soha EAP request"}, SignatureAlgorithm: x509.ECDSAWithSHA256}, key)
		if err != nil {
			return err
		}
		response.CSR = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
		if _, err := parseEAPCSR(response.CSR); err != nil {
			return err
		}
	case "network_remove":
		if request.Certificate != nil || request.RequestID != "" || request.Adapter.Medium != "wifi" || len(request.ExpectedXML) == 0 {
			return errors.New("EAP network removal parameters are invalid")
		}
		client, err := openEAPWlan(*request.Adapter)
		if err != nil {
			return err
		}
		defer client.Close()
		if err := client.remove("Soha-EAP-"+eapPayloadUUID(request.DeviceID+"/"+request.Profile.ID), request.ExpectedXML); err != nil {
			return err
		}
	case "install", "readback", "network_inspect", "network_stage", "network_readback", "network_connect":
		if request.Profile == nil || request.Certificate == nil {
			return errors.New("EAP certificate request has no profile or certificate")
		}
		key, err := openEAPCNGKey(request.DeviceID, request.RequestID, false)
		if err != nil {
			return err
		}
		defer key.Close()
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "Soha EAP readback"}, SignatureAlgorithm: x509.ECDSAWithSHA256}, key)
		if err != nil {
			return err
		}
		csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
		if err := validateAdmissionProfile(*request.Profile, time.Now()); err != nil {
			return err
		}
		if err := validateEAPCertificate(*request.Certificate, csr, request.DeviceID, request.Profile.Identity, time.Now()); err != nil {
			return err
		}
		leaf, err := parseEAPCertificate(request.Certificate.CertificatePEM)
		if err != nil {
			return err
		}
		issuer, err := parseEAPCertificate(request.Certificate.CACertificatePEM)
		if err != nil {
			return err
		}
		if request.Action == "install" {
			if err := addEAPUserCertificate("CA", issuer, nil, request.DeviceID); err != nil {
				return err
			}
			for _, encoded := range request.Profile.CACertificates {
				anchor, err := parseEAPCertificate(encoded)
				if err != nil {
					return err
				}
				if err := addEAPUserCertificate("ROOT", anchor, nil, request.DeviceID); err != nil {
					return err
				}
			}
			if err := addEAPUserCertificate("MY", leaf, key, request.DeviceID); err != nil {
				return err
			}
		}
		if request.Action != "network_inspect" {
			if err := readbackEAPUserCertificate(leaf); err != nil {
				return err
			}
			if err := readbackEAPPublicCertificate("CA", issuer); err != nil {
				return err
			}
			for _, encoded := range request.Profile.CACertificates {
				anchor, err := parseEAPCertificate(encoded)
				if err != nil {
					return err
				}
				if err := readbackEAPPublicCertificate("ROOT", anchor); err != nil {
					return err
				}
			}
		}
		if strings.HasPrefix(request.Action, "network_") {
			configuration, err := renderEAPWindowsProfile(*request.Profile, request.DeviceID, *request.Certificate, time.Now())
			if err != nil {
				return err
			}
			if request.Adapter.Medium == "wifi" {
				client, err := openEAPWlan(*request.Adapter)
				if err != nil {
					return err
				}
				defer client.Close()
				switch request.Action {
				case "network_inspect":
					response.ProfileXML, response.Present, err = client.get(configuration.Name)
				case "network_stage":
					err = client.set(configuration, request.ExpectedXML)
				case "network_readback", "network_connect":
					err = client.readback(configuration)
					if err == nil && request.Action == "network_connect" {
						err = client.connect(configuration.Name)
					}
				}
				if err != nil {
					return err
				}
			} else {
				if request.Action != "network_readback" {
					return errors.New("wired EAP profile operations belong to the protected service")
				}
				if err := setWindowsLANUserData(ctx, request.Adapter.Name, configuration.UserData); err != nil {
					return err
				}
			}
		}
		response.Fingerprint = request.Certificate.Fingerprint
	default:
		return errors.New("EAP user operation is unsupported")
	}
	response.OK = true
	return json.NewEncoder(output).Encode(response)
}

func setWindowsLANUserData(ctx context.Context, adapterName string, configuration []byte) error {
	file, err := os.CreateTemp("", "Soha-EAP-*.xml")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(configuration)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	_, err = eapWindowsNetsh(ctx, "lan", "set", "eapuserdata", "filename="+file.Name(), "allusers=no", "interface="+adapterName)
	return err
}
