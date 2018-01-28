package main

import (
	"crypto/rsa"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/driusan/dkim"
)

func main() {
	pubkey := flag.String("txt", "", "Use argument file as DNS TXT entry instead of looking it up")
	flag.Parse()

	var key *rsa.PublicKey
	if *pubkey != "" {
		// This assumes the
		keybytes, err := ioutil.ReadFile(*pubkey)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		dkey, err := dkim.DecodeDNSTXT(string(keybytes))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		key = dkey
	}
	var files []string
	if args := flag.Args(); len(args) > 0 {
		files = args
	}
	var numfails int
	if len(files) > 0 {
		for _, f := range files {
			fd, err := os.Open(f)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
			file, err := dkim.FileBuffer(dkim.NormalizeReader(fd))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
			}

			if err := dkim.VerifyWithPublicKey(file, key); err != nil {
				fmt.Fprintf(os.Stderr, "%v: %v\n", f, err)
				numfails++
			}
			file.Close()
			fd.Close()
			if err := os.Remove(file.Name()); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}

		}
	} else {
		file, err := dkim.FileBuffer(dkim.NormalizeReader(os.Stdin))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		if err := dkim.VerifyWithPublicKey(file, key); err != nil {
			fmt.Fprintf(os.Stderr, "<stdin>: %v\n", err)
			numfails++
		}
		if err := os.Remove(file.Name()); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}

	}
	os.Exit(numfails)
}
