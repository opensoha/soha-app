package endpointservice

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestEAPCNGP256PublicBlobAndSignatureConversion(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blob := make([]byte, 72)
	binary.LittleEndian.PutUint32(blob[:4], 0x31534345)
	binary.LittleEndian.PutUint32(blob[4:8], 32)
	key.X.FillBytes(blob[8:40])
	key.Y.FillBytes(blob[40:])
	public, err := parseEAPP256Blob(blob)
	if err != nil || !key.PublicKey.Equal(public) {
		t.Fatalf("public key = %v, %v", public, err)
	}
	digest := sha256.Sum256([]byte("EAP CSR signature conversion"))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	der, err := encodeEAPCNGSignature(raw)
	if err != nil || !ecdsa.VerifyASN1(public, digest[:], der) {
		t.Fatal("CNG signature conversion did not preserve the valid signature")
	}
	for _, invalid := range [][]byte{nil, make([]byte, 63), make([]byte, 64)} {
		if _, err := encodeEAPCNGSignature(invalid); err == nil {
			t.Fatal("invalid CNG signature accepted")
		}
	}
	blob[0] = 0
	if _, err := parseEAPP256Blob(blob); err == nil {
		t.Fatal("different CNG key algorithm accepted")
	}
}
