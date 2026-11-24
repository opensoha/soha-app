//go:build windows

package endpointservice

import "testing"

func TestWindowsEAPRequestRetainsKeyProvider(t *testing.T) {
	system := &WindowsEAPSystem{requireTPM: true}
	tpm := system.EAPIdentityRequestID("new-identity")
	system.requireTPM = false
	if eapCNGProviderForRequest(tpm) != eapTPMProvider {
		t.Fatal("a TPM key fell back to the software provider after a configuration change")
	}
	if eapCNGProviderForRequest(system.EAPIdentityRequestID("old-identity")) != eapCNGProvider {
		t.Fatal("a legacy request moved to the TPM provider")
	}
}
