package algorithms

import (
	"crypto"
	ed255192 "crypto/ed25519"
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

type ed25519Sha256 struct {
	hashingAlgorithm hash.Hash
}

func (e *ed25519Sha256) ExportPublicKeyBytes(key crypto.PublicKey) (error, []byte) {
	return exportPublicKeyBytesEd25519(key)
}

func exportPublicKeyBytesEd25519(key crypto.PublicKey) (error, []byte) {
	ed25519PubKey := key.(ed255192.PublicKey)
	return nil, ed25519PubKey
}

func (e *ed25519Sha256) BaseName() string {
	return "ed25519"
}

func (e *ed25519Sha256) ExportPrivateKey(key crypto.PrivateKey) (error, *pem.Block) {
	ed255192PrivKey := key.(ed255192.PrivateKey)
	marshalledKey, err := x509.MarshalPKCS8PrivateKey(ed255192PrivKey)
	if err != nil {
		return err, nil
	}
	return nil, &pem.Block{
		Type:    "PRIVATE KEY",
		Headers: nil,
		Bytes:   marshalledKey,
	}
}

func (e *ed25519Sha256) ExportPublicKey(key crypto.PublicKey) (error, *pem.Block) {
	ed255192PubKey := key.(ed255192.PublicKey)
	marshalledKey, err := x509.MarshalPKIXPublicKey(ed255192PubKey)
	if err != nil {
		return err, nil
	}
	return nil, &pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   marshalledKey,
	}
}

func (e *ed25519Sha256) GenerateKey() (error, crypto.PrivateKey, crypto.PublicKey) {
	return generateKeyED25519()
}

func generateKeyED25519() (error, crypto.PrivateKey, crypto.PublicKey) {
	pubKey, privKey, err := ed255192.GenerateKey(rand.Reader)
	return err, privKey, pubKey
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

var Ed25519Sha256 Algorithm = &ed25519Sha256{
	hashingAlgorithm: sha256.New(),
}

func parsePrivKeyEd25519(pemBlock *pem.Block) (crypto.PrivateKey, error) {
	if pemBlock == nil || pemBlock.Type != "PRIVATE KEY" {
		_, _ = fmt.Fprintln(os.Stderr, "Could read private key or unsupported format")
		os.Exit(1)
	}
	key, err := x509.ParseECPrivateKey(pemBlock.Bytes)
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
	e.hashingAlgorithm.Write(message)
	computedHash := e.hashingAlgorithm.Sum([]byte{})
	v := ed255192.Sign(key.(ed255192.PrivateKey), computedHash)
	return base64.StdEncoding.EncodeToString(v), nil
}

func (e *ed25519Sha256) Verify(message []byte, signature []byte, key crypto.PublicKey) error {
	e.hashingAlgorithm.Reset()
	e.hashingAlgorithm.Write(message)
	computedHash := e.hashingAlgorithm.Sum([]byte{})
	result := ed255192.Verify(key.(ed255192.PublicKey), computedHash[:], signature)

	if !result {
		return errors.New("invalid signature")
	}
	return nil
}