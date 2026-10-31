package endpointservice

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"
)

func parseEAPP256Blob(raw []byte) (*ecdsa.PublicKey, error) {
	if len(raw) != 72 || binary.LittleEndian.Uint32(raw[:4]) != 0x31534345 || binary.LittleEndian.Uint32(raw[4:8]) != 32 {
		return nil, errors.New("CNG EAP public key is not P-256")
	}
	key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(raw[8:40]), Y: new(big.Int).SetBytes(raw[40:])}
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, errors.New("CNG EAP public point is invalid")
	}
	return key, nil
}

func encodeEAPCNGSignature(raw []byte) ([]byte, error) {
	if len(raw) != 64 {
		return nil, errors.New("CNG EAP signature has an invalid length")
	}
	signature := struct{ R, S *big.Int }{new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])}
	if signature.R.Sign() <= 0 || signature.S.Sign() <= 0 || signature.R.Cmp(elliptic.P256().Params().N) >= 0 || signature.S.Cmp(elliptic.P256().Params().N) >= 0 {
		return nil, errors.New("CNG EAP signature is out of range")
	}
	return asn1.Marshal(signature)
}
