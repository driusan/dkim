package main

import (
	"crypto"
	"flag"
	"fmt"
	"github.com/driusan/dkim/pkg"
	"github.com/driusan/dkim/pkg/algorithms"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"encoding/pem"
)

func signMessage(sig dkim.Signature, key crypto.PrivateKey, unix bool, dotstuffed bool, hdronly bool) error {
	r := dkim.NormalizeReader(os.Stdin)
	if dotstuffed {
		r.Unstuff()
	}
	file, err := dkim.FileBuffer(r)
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())

	var nl string
	if unix {
		nl = "\n"
	}
	if hdronly {
		return dkim.SignedHeader(sig, file, os.Stdout, key, nl)
	}
	return dkim.SignMessage(sig, file, os.Stdout, key, nl)
}

func main() {
	var canon = "relaxed/relaxed"
	var algorithmInput, s, domain string
	var headers string
	var unstuff, nl bool
	var headerOnly bool
	var privateKey string
	flag.StringVar(&algorithmInput, "a", "rsa-sha256", "Algorithm")
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
		log.Fatalln("Selector and domain are required")
	}

	algorithm := algorithms.Find(algorithmInput)
	if algorithm == nil {
		log.Fatalf( "invalid algorithm selected: %s does not exist\n", algorithmInput)
	}

	kf, err := os.Open(privateKey)
	if err != nil {
		log.Fatalf( "Could not open private key: %v\n", err)
	}
	defer kf.Close()
	keyFile, err := ioutil.ReadAll(kf)
	if err != nil {
		log.Fatalf( "Could read private key: %v\n", err)
	}

	pemBlock, _ := pem.Decode(keyFile)
	key, err := algorithm.ParsePrivateKey(pemBlock)
	if err != nil {
		log.Fatalln(err)
	}
	sig, err := dkim.NewSignature(canon, s, algorithm, domain, strings.Split(headers, ":"))

	if err != nil {
		log.Fatalln(err)
	}
	if err := signMessage(sig, key, nl, unstuff, headerOnly); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
