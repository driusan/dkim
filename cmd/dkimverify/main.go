package main

import (
	"crypto"
	"flag"
	"fmt"
	dkim "github.com/driusan/dkim/pkg"
	"io/ioutil"
	"os"
	"strings"
)

func main() {
	var pubKey, hd, headerPrefix, headerSuffix string
	flag.StringVar(&pubKey, "txt", "", "Use argument file as DNS TXT entry instead of looking it up")
	flag.StringVar(&hd, "hd", "", "Print the results to an SMTP header on stdout instead of stderr")
	flag.StringVar(&headerPrefix, "hdprefix", "", "Prefix the results of the header with this string")
	flag.StringVar(&headerSuffix, "hdsuffix", "", "Suffix the results of the header with this string")
	flag.Parse()

	var key crypto.PublicKey
	if pubKey != "" {
		keyBytes, err := ioutil.ReadFile(pubKey)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		domainKey, err := dkim.DecodeDNSTXT(string(keyBytes))
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		key = domainKey
	}
	var files []string
	if args := flag.Args(); len(args) > 0 {
		files = args
	}
	var numFailures int
	if len(files) > 0 {
		for _, f := range files {
			fd, err := os.Open(f)
			if err != nil {
				_, _ = fmt.Fprintln(os.Stderr, err)
			}
			file, err := dkim.FileBuffer(dkim.NormalizeReader(fd))
			if err != nil {
				_, _ = fmt.Fprintln(os.Stderr, err)
			}

			if err := dkim.VerifyWithPublicKey(file, key); err != nil || hd != "" {
				printResult(hd, headerPrefix, headerSuffix, f, err)
				numFailures++
			}
			file.Close()
			fd.Close()
			if err := os.Remove(file.Name()); err != nil {
				_, _ = fmt.Fprintln(os.Stderr, err)
			}

		}
	} else {
		file, err := dkim.FileBuffer(dkim.NormalizeReader(os.Stdin))
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
		}
		if err := dkim.VerifyWithPublicKey(file, key); err != nil || hd != "" {
			printResult(hd, headerPrefix, headerSuffix, "<stdin>", err)
			numFailures++
		}
		if err := os.Remove(file.Name()); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
		}

	}
	os.Exit(numFailures)
}

// Helper to print the results for either stdin or per file.
func printResult(hd, headerPrefix string, headerSuffix string, filename string, err error) {
	if hd != "" {
		if err == nil {
			fmt.Printf("%v: %vPass%v\n", hd, headerPrefix, headerSuffix)
		} else if errorString := err.Error(); errorString == "Permanent failure: no DKIM signature" || strings.Index(errorString, "Temporary failure") >= 0 {
			// Nothing
		} else {
			fmt.Printf("%v: %vFail%v\n", hd, headerPrefix, headerSuffix)
		}
	} else {
		_, _ = fmt.Fprintf(os.Stderr, "%v: %v\n", filename, err)
	}

}
