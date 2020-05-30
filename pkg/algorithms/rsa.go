package algorithms

import (
	"crypto"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"hash"
)

type rsaSha256 struct {
	key              *rsa.PrivateKey
	hashingAlgorithm hash.Hash
}

var RSASha256 Algorithm = &rsaSha256{
	hashingAlgorithm: crypto.SHA256.New(),
}
var RSASha1 Algorithm = &rsaSha1{
	hashingAlgorithm: crypto.SHA1.New(),
}

type rsaSha1 struct {
	key              *rsa.PrivateKey
	hashingAlgorithm hash.Hash
}

func (r *rsaSha256) Verify(message []byte, signature []byte, key interface{}) error {
	r.hashingAlgorithm.Reset()
	r.hashingAlgorithm.Write(message)
	computedHash := r.hashingAlgorithm.Sum([]byte{})
	return rsa.VerifyPKCS1v15(key.(*rsa.PublicKey), crypto.SHA256, computedHash[:], signature)
}

func (r rsaSha1) Verify(message []byte, signature []byte, key interface{}) error {
	r.hashingAlgorithm.Reset()
	r.hashingAlgorithm.Write(message)
	computedHash := r.hashingAlgorithm.Sum([]byte{})
	return rsa.VerifyPKCS1v15(key.(*rsa.PublicKey), crypto.SHA1, computedHash[:], signature)
}

func (r rsaSha1) Name() string {
	return "rsa-sha1"
}

func (r rsaSha1) Sign() {
	panic("implement me")
}

func (*rsaSha256) Name() string {
	return "rsa-sha256"
}

func (*rsaSha256) Sign() {

}