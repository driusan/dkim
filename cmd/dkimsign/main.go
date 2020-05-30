package main

import (
	"flag"
	"fmt"
	"github.com/driusan/dkim/pkg"
	"io/ioutil"
	"os"
	"strings"

	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

func signMessage(sig pkg.Signature, key *rsa.PrivateKey, unix bool, dotstuffed bool, hdronly bool) error {
	r := pkg.NormalizeReader(os.Stdin)
	if dotstuffed {
		r.Unstuff()
	}
	file, err := pkg.FileBuffer(r)
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())

	var nl string
	if unix {
		nl = "\n"
	}
	if hdronly {
		return pkg.SignedHeader(sig, file, os.Stdout, key, nl)
	}
	return pkg.SignMessage(sig, file, os.Stdout, key, nl)
}

func main() {
	var canon = "relaxed/relaxed"
	var s, domain string
	var headers string
	var unstuff, nl bool
	var headerOnly bool
	var privateKey string
	flag.StringVar(&canon, "c", "relaxed/relaxed", "Canonicalization scheme")
	flag.StringVar(&s, "s", "", "Domain selector")
	flag.StringVar(&domain, "d", "", "Domain name")
	flag.StringVar(&headers, "h", "From:Subject:To:Date", "Colon separated list of headers to sign")
	flag.BoolVar(&unstuff, "u", false, "Assume input is already SMTP dot stuffed when calculating signature and un dot-stuff it while printing")
	flag.BoolVar(&nl, "n", false, `Print final message with \n instead of \r\n line endings`)
	flag.BoolVar(&headerOnly, "hd", false, "Only print the header, not the whole message after signing")
	flag.StringVar(&privateKey, "key", "", "Location of PEM encoded private key")
	flag.Parse()

	if domain == "" || s == "" {
		_, _ = fmt.Fprintln(os.Stderr, "Selector and domain are required")
		os.Exit(1)
	}
	var key *rsa.PrivateKey
	kf, err := os.Open(privateKey)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Could not open private key: %v\n", err)
		os.Exit(1)

	}
	defer kf.Close()
	keyFile, err := ioutil.ReadAll(kf)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Could read private key: %v\n", err)
		os.Exit(1)
	}

	pemBlock, _ := pem.Decode(keyFile)
	if pemBlock == nil || pemBlock.Type != "RSA PRIVATE KEY" {
		_, _ = fmt.Fprintln(os.Stderr, "Could read private key or unsupported format")
		os.Exit(1)
	}
	key, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Could not parse private key: %v\n", err)
		os.Exit(1)
	}

	sig, err := pkg.NewSignature(canon, s, domain, strings.Split(headers, ":"))

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := signMessage(sig, key, nl, unstuff, headerOnly); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
