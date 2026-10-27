package endpointservice

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"strings"
	"time"
)

type eapWindowsProfile struct {
	Name     string
	XML      []byte
	UserData []byte
}

func eapXMLText(value string) string {
	var output bytes.Buffer
	_ = xml.EscapeText(&output, []byte(value))
	return output.String()
}

func renderEAPWindowsProfile(profile AdmissionProfile, deviceID string, certificate EAPCertificateResult, now time.Time) (eapWindowsProfile, error) {
	if err := validateAdmissionProfile(profile, now); err != nil {
		return eapWindowsProfile{}, err
	}
	leaf, err := parseEAPCertificate(certificate.CertificatePEM)
	if err != nil {
		return eapWindowsProfile{}, err
	}
	var anchors strings.Builder
	for _, raw := range profile.CACertificates {
		ca, err := parseEAPCertificate(raw)
		if err != nil {
			return eapWindowsProfile{}, err
		}
		// Windows uses SHA-1 thumbprints to select certificates, not to validate TLS signatures.
		digest := sha1.Sum(ca.Raw)
		fmt.Fprintf(&anchors, "<TrustedRootCA>%x</TrustedRootCA>", digest)
	}
	eap := `<OneX xmlns="http://www.microsoft.com/networking/OneX/v1"><cacheUserData>true</cacheUserData><authMode>user</authMode><EAPConfig><EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig"><EapMethod><Type xmlns="http://www.microsoft.com/provisioning/EapCommon">13</Type><AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId></EapMethod><Config><Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>13</Type><EapType xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1"><CredentialsSource><CertificateStore><SimpleCertSelection>false</SimpleCertSelection></CertificateStore></CredentialsSource><ServerValidation><DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation><ServerNames>` + eapXMLText(strings.Join(profile.ServerNames, ";")) + `</ServerNames>` + anchors.String() + `</ServerValidation><DifferentUsername>true</DifferentUsername><PerformServerValidation xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true</PerformServerValidation><AcceptServerName xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true</AcceptServerName></EapType></Eap></Config></EapHostConfig></EAPConfig></OneX>`
	name := "Soha-EAP-" + eapPayloadUUID(deviceID+"/"+profile.ID)
	var configuration string
	if profile.AccessMedium == "wifi" {
		authentication := "WPA2"
		if profile.WifiSecurity == "wpa3-enterprise" {
			authentication = "WPA3ENT"
		}
		configuration = `<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1"><name>` + name + `</name><SSIDConfig><SSID><hex>` + hex.EncodeToString([]byte(profile.SSID)) + `</hex></SSID><nonBroadcast>false</nonBroadcast></SSIDConfig><connectionType>ESS</connectionType><connectionMode>manual</connectionMode><MSM><security><authEncryption><authentication>` + authentication + `</authentication><encryption>AES</encryption><useOneX>true</useOneX></authEncryption>` + eap + `</security></MSM></WLANProfile>`
	} else {
		configuration = `<LANProfile xmlns="http://www.microsoft.com/networking/LAN/profile/v1"><MSM><security><OneXEnforced>true</OneXEnforced><OneXEnabled>true</OneXEnabled>` + eap + `</security></MSM></LANProfile>`
	}
	thumbprint := sha1.Sum(leaf.Raw)
	user := `<EapHostUserCredentials xmlns="http://www.microsoft.com/provisioning/EapHostUserCredentials" xmlns:eapCommon="http://www.microsoft.com/provisioning/EapCommon"><EapMethod><eapCommon:Type>13</eapCommon:Type><eapCommon:AuthorId>0</eapCommon:AuthorId></EapMethod><Credentials><Eap xmlns="http://www.microsoft.com/provisioning/BaseEapUserPropertiesV1"><Type>13</Type><EapType xmlns="http://www.microsoft.com/provisioning/EapTlsUserPropertiesV1"><Username>` + eapXMLText(profile.Identity) + `</Username><UserCert>` + fmt.Sprintf("%x", thumbprint) + `</UserCert></EapType></Eap></Credentials></EapHostUserCredentials>`
	return eapWindowsProfile{Name: name, XML: []byte(xml.Header + configuration), UserData: []byte(xml.Header + user)}, nil
}
