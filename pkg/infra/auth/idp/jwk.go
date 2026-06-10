package idp

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
)

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	KeyID     string   `json:"kid"`
	KeyType   string   `json:"kty"`
	Algorithm string   `json:"alg"`
	Use       string   `json:"use"`
	N         string   `json:"n"`
	E         string   `json:"e"`
	X5C       []string `json:"x5c"`
}

func (k jwk) publicKey() (any, error) {
	if len(k.X5C) > 0 {
		der, err := base64.StdEncoding.DecodeString(k.X5C[0])
		if err != nil {
			return nil, fmt.Errorf("%w: decode x5c: %v", ErrUnsupportedKey, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: parse x5c: %v", ErrUnsupportedKey, err)
		}
		return cert.PublicKey, nil
	}
	if k.KeyType != "RSA" {
		return nil, fmt.Errorf("%w: kty %q", ErrUnsupportedKey, k.KeyType)
	}
	modulus, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("%w: decode n: %v", ErrUnsupportedKey, err)
	}
	exponent, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("%w: decode e: %v", ErrUnsupportedKey, err)
	}
	e := 0
	for _, b := range exponent {
		e = e<<8 + int(b)
	}
	if e == 0 {
		return nil, fmt.Errorf("%w: empty exponent", ErrUnsupportedKey)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: e}, nil
}

func parsePEMPublicKey(raw string) (any, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, fmt.Errorf("%w: invalid pem", ErrUnsupportedKey)
	}
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		return cert.PublicKey, nil
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse pem public key: %v", ErrUnsupportedKey, err)
	}
	return key, nil
}
