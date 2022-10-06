package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

func GenerateRSAPrivateKey(bits int) ([]byte, error) {
	var key *rsa.PrivateKey
	var data []byte
	var err error
	if key, err = rsa.GenerateKey(rand.Reader, bits); err != nil {
		return nil, err
	}
	if data, err = x509.MarshalPKCS8PrivateKey(key); err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data}), nil
}
