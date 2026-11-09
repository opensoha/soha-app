package endpointservice

import "crypto/x509"

// Both wired and wireless TTLS use the enrolled user's exact owned CA store path.
func prepareEAPPasswordTrust(profile AdmissionProfile, action string, install, readback func(*x509.Certificate) error) error {
	for _, encoded := range profile.CACertificates {
		anchor, err := parseEAPCertificate(encoded)
		if err != nil {
			return err
		}
		if action == "network_stage" {
			if err := install(anchor); err != nil {
				return err
			}
		}
		if action != "network_inspect" {
			if err := readback(anchor); err != nil {
				return err
			}
		}
	}
	return nil
}
