package main

import (
	"fmt"
	"os"

	"encoding/pem"
	//	"encoding/gob"
	//"encoding/asn1"
	"crypto/x509"
	"encoding/base64"

	"crypto/rand"
	"crypto/rsa"
)

func main() {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	asn1bytes, err := x509.MarshalPKIXPublicKey(&pk.PublicKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	f, err := os.Create("dns.txt")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}

	b64 := base64.StdEncoding.EncodeToString(asn1bytes)
	fmt.Fprintf(f, "v=DKIM1; k=rsa; p=%s", b64)
	f.Close()

	f, err = os.Create("private.pem")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(4)
	}
	err = pem.Encode(f, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(pk),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(5)

	}
	f.Close()
}
