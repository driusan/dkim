package algorithms

import (
	"crypto/x509"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEd25519Sha256_ExportPublicKey(t *testing.T) {
	_, pubKey, err := Ed25519Sha256.GenerateKey()
	assert.Nil(t, err)

	pemBlock, err := Ed25519Sha256.ExportPublicKey(pubKey)
	assert.Nil(t, err)

	parsedPublicKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	assert.Nil(t, err)

	assert.Equal(t, pubKey, parsedPublicKey)
}

func TestEd25519Sha256_ExportPrivateKey(t *testing.T) {
	privKey, _, err := Ed25519Sha256.GenerateKey()
	assert.Nil(t, err)

	pemBlock, err := Ed25519Sha256.ExportPrivateKey(privKey)
	assert.Nil(t, err)

	parsedPrivateKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	assert.Nil(t, err)

	assert.Equal(t, privKey, parsedPrivateKey)
}
