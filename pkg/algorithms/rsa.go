package algorithms

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"hash"
	"os"
)

type rsaSha256 struct {
	key              *rsa.PrivateKey
	hashingAlgorithm hash.Hash
}

func (r *rsaSha256) ExportPublicKeyBytes(key crypto.PublicKey) ([]byte, error) {
	return exportPublicKeyBytesRSA(key)
}

func (r *rsaSha256) BaseName() string {
	return "rsa"
}

func (r *rsaSha256) ExportPrivateKey(key crypto.PrivateKey) (*pem.Block, error) {
	return exportPrivateKeyRSA(key)
}

func (r *rsaSha256) ExportPublicKey(key crypto.PublicKey) (*pem.Block, error) {
	return exportPublicKeyRSA(key)
}

func exportPublicKeyRSA(key crypto.PublicKey) (*pem.Block, error) {
	rsaPublicKey := key.(rsa.PublicKey)
	return &pem.Block{
		Type:    "RSA PUBLIC KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PublicKey(&rsaPublicKey),
	}, nil
}

func exportPrivateKeyRSA(key crypto.PublicKey) (*pem.Block, error) {
	rsaPrivateKey := key.(rsa.PrivateKey)
	return &pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(&rsaPrivateKey),
	}, nil
}

func (r *rsaSha256) GenerateKey() (crypto.PrivateKey, crypto.PublicKey, error) {
	return generateKeyRSA()
}

func generateKeyRSA() (crypto.PrivateKey, crypto.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	return *privateKey, privateKey.PublicKey, nil
}

func parsePrivateKeyRSA(pemBlock *pem.Block) (crypto.PrivateKey, error) {
	if pemBlock == nil || pemBlock.Type != "RSA PRIVATE KEY" {
		_, _ = fmt.Fprintln(os.Stderr, "Could read private key or unsupported format")
		os.Exit(1)
	}
	key, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Could not parse private key: %v\n", err)
		os.Exit(1)
	}
	return key, err
}

func parsePublicKeyRSA(pemBlock *pem.Block) (crypto.PublicKey, error) {
	if pemBlock == nil || pemBlock.Type != "RSA PUBLIC KEY" {
		_, _ = fmt.Fprintln(os.Stderr, "Could read private key or unsupported format")
		os.Exit(1)
	}
	key, err := x509.ParsePKCS1PublicKey(pemBlock.Bytes)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Could not parse private key: %v\n", err)
		os.Exit(1)
	}
	return key, err
}

func (r *rsaSha256) ParsePrivateKey(block *pem.Block) (crypto.PrivateKey, error) {
	return parsePrivateKeyRSA(block)
}

func (r *rsaSha256) ParsePublicKey(block *pem.Block) (crypto.PublicKey, error) {
	return parsePublicKeyRSA(block)
}

var RSASha256 Algorithm = &rsaSha256{
	hashingAlgorithm: sha256.New(),
}
var RSASha1 Algorithm = &rsaSha1{
	hashingAlgorithm: sha1.New(),
}

type rsaSha1 struct {
	key              *rsa.PrivateKey
	hashingAlgorithm hash.Hash
}

func (r rsaSha1) ExportPublicKeyBytes(key crypto.PublicKey) ([]byte, error) {
	return exportPublicKeyBytesRSA(key)
}

func exportPublicKeyBytesRSA(key crypto.PublicKey) ([]byte, error) {
	rsaPublicKey := key.(rsa.PublicKey)
	return x509.MarshalPKCS1PublicKey(&rsaPublicKey), nil
}

func (r rsaSha1) BaseName() string {
	return "rsa"
}

func (r rsaSha1) ExportPrivateKey(key crypto.PrivateKey) (*pem.Block, error) {
	return exportPrivateKeyRSA(key)
}

func (r rsaSha1) ExportPublicKey(key crypto.PublicKey) (*pem.Block, error) {
	return exportPublicKeyRSA(key)
}

func (r rsaSha1) GenerateKey() (crypto.PrivateKey, crypto.PublicKey, error) {
	return generateKeyRSA()
}

func (r rsaSha1) ParsePrivateKey(block *pem.Block) (crypto.PrivateKey, error) {
	return parsePrivateKeyRSA(block)
}

func (r rsaSha1) ParsePublicKey(block *pem.Block) (crypto.PublicKey, error) {
	return parsePublicKeyRSA(block)
}

func (r *rsaSha256) Verify(message []byte, signature []byte, key crypto.PublicKey) error {
	r.hashingAlgorithm.Reset()
	if _, err := r.hashingAlgorithm.Write(message); err != nil {
		return err
	}
	computedHash := r.hashingAlgorithm.Sum(nil)
	return rsa.VerifyPKCS1v15(key.(*rsa.PublicKey), crypto.SHA256, computedHash[:], signature)
}

func (r rsaSha1) Verify(message []byte, signature []byte, key crypto.PublicKey) error {
	r.hashingAlgorithm.Reset()
	if _, err := r.hashingAlgorithm.Write(message); err != nil {
		return err
	}
	computedHash := r.hashingAlgorithm.Sum(nil)
	return rsa.VerifyPKCS1v15(key.(*rsa.PublicKey), crypto.SHA1, computedHash[:], signature)
}

func (r rsaSha1) Name() string {
	return "rsa-sha1"
}

func (r rsaSha1) Sign(message []byte, key crypto.PrivateKey) (string, error) {
	r.hashingAlgorithm.Reset()
	if _, err := r.hashingAlgorithm.Write(message); err != nil {
		return "", err
	}
	computedHash := r.hashingAlgorithm.Sum(nil)
	v, err := rsa.SignPKCS1v15(nil, key.(*rsa.PrivateKey), crypto.SHA1, computedHash[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(v), nil
}

func (*rsaSha256) Name() string {
	return "rsa-sha256"
}

func (r *rsaSha256) Sign(message []byte, key crypto.PrivateKey) (string, error) {
	r.hashingAlgorithm.Reset()
	r.hashingAlgorithm.Write(message)
	computedHash := r.hashingAlgorithm.Sum(nil)
	v, err := rsa.SignPKCS1v15(nil, key.(*rsa.PrivateKey), crypto.SHA256, computedHash[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(v), nil
}
