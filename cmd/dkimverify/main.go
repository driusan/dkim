package main

import (
	"fmt"
	"os"

	"github.com/driusan/dkim"
)

func main() {
	var files []string
	if len(os.Args) > 1 {
		files = os.Args[1:]
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

			if err := dkim.Verify(file); err != nil {
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
		if err := dkim.Verify(file); err != nil {
			fmt.Fprintf(os.Stderr, "<stdin>: %v\n", err)
			numfails++
		}
		if err := os.Remove(file.Name()); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}

	}
	os.Exit(numfails)
}
