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

type RsaSha256 struct {
	key              *rsa.PrivateKey
	bits             int
	hashingAlgorithm hash.Hash
}

func (r *RsaSha256) ExportPublicKeyBytes(key crypto.PublicKey) ([]byte, error) {
	return exportPublicKeyBytesRSA(key)
}

func (r *RsaSha256) BaseName() string {
	return "rsa"
}

func (r *RsaSha256) ExportPrivateKey(key crypto.PrivateKey) (*pem.Block, error) {
	return exportPrivateKeyRSA(key)
}

func (r *RsaSha256) ExportPublicKey(key crypto.PublicKey) (*pem.Block, error) {
	return exportPublicKeyRSA(key)
}

func (r *RsaSha256) SetKeySize(bits int) {
	r.bits = bits
}

func (r *RsaSha1) SetKeySize(bits int) {
	r.bits = bits
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

func (r *RsaSha256) GenerateKey() (crypto.PrivateKey, crypto.PublicKey, error) {
	return generateKeyRSA(r.bits)
}

func generateKeyRSA(bits int) (crypto.PrivateKey, crypto.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
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

func (r *RsaSha256) ParsePrivateKey(block *pem.Block) (crypto.PrivateKey, error) {
	return parsePrivateKeyRSA(block)
}

func (r *RsaSha256) ParsePublicKey(block *pem.Block) (crypto.PublicKey, error) {
	return parsePublicKeyRSA(block)
}

var RSASha256 Algorithm = &RsaSha256{
	hashingAlgorithm: sha256.New(),
	bits:             2048,
}
var RSASha1 Algorithm = &RsaSha1{
	hashingAlgorithm: sha1.New(),
	bits:             2048,
}

type RsaSha1 struct {
	key              *rsa.PrivateKey
	hashingAlgorithm hash.Hash
	bits             int
}

func (r RsaSha1) ExportPublicKeyBytes(key crypto.PublicKey) ([]byte, error) {
	return exportPublicKeyBytesRSA(key)
}

func exportPublicKeyBytesRSA(key crypto.PublicKey) ([]byte, error) {
	rsaPublicKey := key.(rsa.PublicKey)
	return x509.MarshalPKCS1PublicKey(&rsaPublicKey), nil
}

func (r RsaSha1) BaseName() string {
	return "rsa"
}

func (r RsaSha1) ExportPrivateKey(key crypto.PrivateKey) (*pem.Block, error) {
	return exportPrivateKeyRSA(key)
}

func (r RsaSha1) ExportPublicKey(key crypto.PublicKey) (*pem.Block, error) {
	return exportPublicKeyRSA(key)
}

func (r RsaSha1) GenerateKey() (crypto.PrivateKey, crypto.PublicKey, error) {
	return generateKeyRSA(r.bits)
}

func (r RsaSha1) ParsePrivateKey(block *pem.Block) (crypto.PrivateKey, error) {
	return parsePrivateKeyRSA(block)
}

func (r RsaSha1) ParsePublicKey(block *pem.Block) (crypto.PublicKey, error) {
	return parsePublicKeyRSA(block)
}

func (r *RsaSha256) Verify(message []byte, signature []byte, key crypto.PublicKey) error {
	r.hashingAlgorithm.Reset()
	if _, err := r.hashingAlgorithm.Write(message); err != nil {
		return err
	}
	computedHash := r.hashingAlgorithm.Sum(nil)
	return rsa.VerifyPKCS1v15(key.(*rsa.PublicKey), crypto.SHA256, computedHash[:], signature)
}

func (r RsaSha1) Verify(message []byte, signature []byte, key crypto.PublicKey) error {
	r.hashingAlgorithm.Reset()
	if _, err := r.hashingAlgorithm.Write(message); err != nil {
		return err
	}
	computedHash := r.hashingAlgorithm.Sum(nil)
	return rsa.VerifyPKCS1v15(key.(*rsa.PublicKey), crypto.SHA1, computedHash[:], signature)
}

func (r RsaSha1) Name() string {
	return "rsa-sha1"
}

func (r RsaSha1) Sign(message []byte, key crypto.PrivateKey) (string, error) {
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

func (*RsaSha256) Name() string {
	return "rsa-sha256"
}

func (r *RsaSha256) Sign(message []byte, key crypto.PrivateKey) (string, error) {
	r.hashingAlgorithm.Reset()
	r.hashingAlgorithm.Write(message)
	computedHash := r.hashingAlgorithm.Sum(nil)
	v, err := rsa.SignPKCS1v15(nil, key.(*rsa.PrivateKey), crypto.SHA256, computedHash[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(v), nil
}
