package main

import (
	"crypto/rsa"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/driusan/dkim"
)

func main() {
	pubkey := flag.String("txt", "", "Use argument file as DNS TXT entry instead of looking it up")
	hd := flag.String("hd", "", "Print the results to an SMTP header on stdout instead of stderr")
	hdprefix := flag.String("hdprefix", "", "Prefix the results of the header with this string")
	hdsuffix := flag.String("hdsuffix", "", "Suffix the results of the header with this string")
	flag.Parse()

	var key *rsa.PublicKey
	if *pubkey != "" {
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

			if err := dkim.VerifyWithPublicKey(file, key); err != nil || *hd != "" {
				printResult(*hd, *hdprefix, *hdsuffix, f, err)
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
		if err := dkim.VerifyWithPublicKey(file, key); err != nil || *hd != "" {
			printResult(*hd, *hdprefix, *hdsuffix, "<stdin>", err)
			numfails++
		}
		if err := os.Remove(file.Name()); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}

	}
	os.Exit(numfails)
}

// Helper to print the results for either stdin or per file.
func printResult(hd, hdprefix, hdsuffix string, filename string, err error) {
	if hd != "" {
		if err == nil {
			fmt.Printf("%v: %vPass%v\n", hd, hdprefix, hdsuffix)
		} else if errstr := err.Error(); errstr == "Permanent failure: no DKIM signature" || strings.Index(errstr, "Temporary failure") >= 0 {
			// Nothing
		} else {
			fmt.Printf("%v: %vFail%v\n", hd, hdprefix, hdsuffix)
		}
	} else {
		fmt.Fprintf(os.Stderr, "%v: %v\n", filename, err)
	}

}
