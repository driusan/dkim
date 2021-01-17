package algorithms

import (
	"crypto"
	"encoding/pem"
)

type Algorithm interface {
	Name() string // e.g: rsa-sha256
	BaseName() string // e.g: rsa
	Sign(message []byte, key crypto.PrivateKey) (string, error)
	Verify(message []byte, signature []byte, key crypto.PublicKey) error
	ParsePrivateKey(block *pem.Block) (crypto.PrivateKey, error)
	ParsePublicKey(block *pem.Block) (crypto.PublicKey, error)
	ExportPrivateKey(key crypto.PrivateKey) (*pem.Block, error)
	ExportPublicKey(key crypto.PublicKey) (*pem.Block, error)
	ExportPublicKeyBytes(key crypto.PublicKey) ([]byte, error)
	GenerateKey() (crypto.PrivateKey, crypto.PublicKey, error)
}

func Find(name string) Algorithm {
	switch name {
	case "rsa-sha1":
		return RSASha1
	case "rsa-sha256":
		return RSASha256
	case "ed25519-sha256":
		return Ed25519Sha256
	default:
		return nil
	}
}
