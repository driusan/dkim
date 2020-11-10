package algorithms

import (
	"crypto/x509"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEd25519Sha256_ExportPublicKey(t *testing.T) {
	err, _, pubKey := Ed25519Sha256.GenerateKey()
	assert.Nil(t, err)

	pemBlock, err := Ed25519Sha256.ExportPublicKey(pubKey)
	assert.Nil(t, err)

	parsedPublicKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	assert.Nil(t, err)

	assert.Equal(t, pubKey, parsedPublicKey)
}
