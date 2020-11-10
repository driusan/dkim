package main

import (
	"flag"
	"fmt"
	"github.com/driusan/dkim/pkg/algorithms"
	"log"
	"os"

	"encoding/base64"
	"encoding/pem"
)

func main() {
	var algorithmInput, outputPath, dnsOutputPath string
	var keySize int
	flag.StringVar(&algorithmInput, "a", "rsa-sha256", "Algorithm")
	flag.IntVar(&keySize, "s", -1, "Key Size (for RSA)")
	flag.StringVar(&outputPath, "o", "privkey.pem", "Save location for the PEM encoded private key")
	flag.StringVar(&dnsOutputPath, "d", "dns.txt", "Save location for the TXT DNS entry")
	flag.Parse()

	if outputPath == "" {
		log.Fatal("invalid output path")
	}

	if dnsOutputPath == "" {
		log.Fatal( "invalid DNS output path")
	}

	algorithm := algorithms.Find(algorithmInput)
	if algorithm == nil {
		log.Fatalf("invalid algorithm provided, %s does not exist\n", algorithmInput)
	}

	if keySize != -1 {
		switch algorithm.(type) {
		case *algorithms.RsaSha256:
			algorithm.(*algorithms.RsaSha256).SetKeySize(keySize)
		case *algorithms.RsaSha1:
			algorithm.(*algorithms.RsaSha1).SetKeySize(keySize)
		}
	}
	
	privKey, pubKey, err := algorithm.GenerateKey()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	privKeyPem, err := algorithm.ExportPrivateKey(privKey)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}

	pubKeyBytes, err := algorithm.ExportPublicKeyBytes(pubKey)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}

	f, err := os.Create(dnsOutputPath)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(4)
	}

	b64 := base64.StdEncoding.EncodeToString(pubKeyBytes)
	_, _ = fmt.Fprintf(f, "v=DKIM1; k=%s; p=%s", algorithm.BaseName(), b64)
	f.Close()

	f, err = os.Create(outputPath)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(5)
	}
	err = pem.Encode(f, privKeyPem)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(6)

	}
	f.Close()
}
