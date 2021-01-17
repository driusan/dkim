package algorithms

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"os"
)

var _ Algorithm = &ed25519Sha256{}

var Ed25519Sha256 Algorithm = &ed25519Sha256{
	hashingAlgorithm: sha256.New(),
}

type ed25519Sha256 struct {
	hashingAlgorithm hash.Hash
}

func (e *ed25519Sha256) ExportPublicKeyBytes(key crypto.PublicKey) ([]byte, error) {
	return exportPublicKeyBytesEd25519(key)
}

func exportPublicKeyBytesEd25519(key crypto.PublicKey) ([]byte, error) {
	ed25519PubKey := key.(ed25519.PublicKey)
	return ed25519PubKey, nil
}

func (e *ed25519Sha256) BaseName() string {
	return "ed25519"
}

func (e *ed25519Sha256) ExportPrivateKey(key crypto.PrivateKey) (*pem.Block, error) {
	ed25519PrivKey := key.(ed25519.PrivateKey)
	marshalledKey, err := x509.MarshalPKCS8PrivateKey(ed25519PrivKey)
	if err != nil {
		return nil, err
	}
	return &pem.Block{
		Type:    "PRIVATE KEY",
		Headers: nil,
		Bytes:   marshalledKey,
	}, nil
}

func (e *ed25519Sha256) ExportPublicKey(key crypto.PublicKey) (*pem.Block, error) {
	ed25519PubKey := key.(ed25519.PublicKey)
	marshalledKey, err := x509.MarshalPKIXPublicKey(ed25519PubKey)
	if err != nil {
		return nil, err
	}
	return &pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   marshalledKey,
	}, err
}

func (e *ed25519Sha256) GenerateKey() (crypto.PrivateKey, crypto.PublicKey, error) {
	return generateKeyED25519()
}

func generateKeyED25519() (crypto.PrivateKey, crypto.PublicKey, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	return private, public, err
}

func (e *ed25519Sha256) ParsePrivateKey(block *pem.Block) (crypto.PrivateKey, error) {
	return parsePrivKeyEd25519(block)
}

func (e *ed25519Sha256) ParsePublicKey(block *pem.Block) (crypto.PublicKey, error) {
	return parsePublicKeyEd25519(block)
}

func parsePublicKeyEd25519(pemBlock *pem.Block) (crypto.PublicKey, error) {
	if pemBlock == nil || pemBlock.Type != "PUBLIC KEY" {
		_, _ = fmt.Fprintln(os.Stderr, "Could read private key or unsupported format")
		os.Exit(1)
	}
	key, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Could not parse private key: %v\n", err)
		os.Exit(1)
	}
	return key, err
}

func parsePrivKeyEd25519(pemBlock *pem.Block) (crypto.PrivateKey, error) {
	if pemBlock == nil || pemBlock.Type != "PRIVATE KEY" {
		_, _ = fmt.Fprintln(os.Stderr, "Could read private key or unsupported format")
		os.Exit(1)
	}
	key, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Could not parse private key: %v\n", err)
		os.Exit(1)
	}
	return key, err
}

func (e *ed25519Sha256) Name() string {
	return "ed25519-sha256"
}

func (e *ed25519Sha256) Sign(message []byte, key crypto.PrivateKey) (string, error) {
	e.hashingAlgorithm.Reset()
	if _, err := e.hashingAlgorithm.Write(message); err != nil {
		return "", err
	}
	computedHash := e.hashingAlgorithm.Sum(nil)
	v := ed25519.Sign(key.(ed25519.PrivateKey), computedHash)
	return base64.StdEncoding.EncodeToString(v), nil
}

func (e *ed25519Sha256) Verify(message []byte, signature []byte, key crypto.PublicKey) error {
	e.hashingAlgorithm.Reset()
	if _, err := e.hashingAlgorithm.Write(message); err != nil {
		return err
	}
	computedHash := e.hashingAlgorithm.Sum(nil)
	result := ed25519.Verify(key.(ed25519.PublicKey), computedHash[:], signature)

	if !result {
		return errors.New("invalid signature")
	}
	return nil
}