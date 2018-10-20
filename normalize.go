package dkim

import (
	"regexp"
	//	"fmt"
	"bytes"
	"io"
	"io/ioutil"
	"os"
)

var nonnormalLineRE = regexp.MustCompile("([^\r]|^)\n")

// A normalizeReader wraps an io.Reader to normalize the line endings and
// encoding of a stream of bytes.
// It reads into a tempfile, which it deletes on close, so that it also
// implements the seek
type normalizeReader struct {
	// The underlying reader
	io.Reader
	// Any leftover bytes after doing the normalization from the last
	// call.
	leftOver []byte
	eof      bool

	unstuff bool
}

// If called, the reader will un dot-stuff lines that it reads.
func (n *normalizeReader) Unstuff() {
	n.unstuff = true
}
func (n *normalizeReader) Read(r []byte) (int, error) {
	var err error
	// If there's already enough from the last read to fill this buffer,
	// don't bother with the read.
	if len(n.leftOver) < len(r)/2 {
		// There wasn't enough data, so append it to the scratch
		// buffer
		var j int
		j, err = n.Reader.Read(r)
		n.leftOver = append(n.leftOver, r[:j]...)
		if err == io.EOF {
			//println("EOF")
			n.eof = true
		}
	}

	if len(n.leftOver) == 0 && n.eof {
		return 0, io.EOF
	}
	// Replace all non-normalized lines remaining with \r\n
	//	n.leftOver = nonnormalLineRE.ReplaceAll(n.leftOver, []byte{'$', '1', '\r', '\n'})
	n.leftOver = bytes.Replace(n.leftOver, []byte{'\r', '\n'}, []byte{'\n'}, -1)
	n.leftOver = bytes.Replace(n.leftOver, []byte{'\r'}, []byte{'\n'}, -1)
	n.leftOver = bytes.Replace(n.leftOver, []byte{'\n'}, []byte{'\r', '\n'}, -1)
	if n.unstuff {
		n.leftOver = bytes.Replace(n.leftOver, []byte{'\n', '.'}, []byte{'\n'}, -1)
	}
	// If there's up to len(r), fill up r and return the amount that
	// was read.
	if len(n.leftOver) <= len(r) {
		size := len(n.leftOver)
		for i := range n.leftOver {
			r[i] = n.leftOver[i]
		}
		n.leftOver = nil
		if n.eof {
			return size, io.EOF
		}
		return size, err
	}

	// If there was more than len(r), fill up what we can and store
	// the rest n.leftOver
	for i := range r {
		r[i] = n.leftOver[i]
	}
	n.leftOver = r[len(r):]
	return len(r), err

}

func FileBuffer(r io.Reader) (*os.File, error) {
	tempfile, err := ioutil.TempFile("", "readbuffer")
	if err != nil {
		return nil, err
	}
	_, err = io.Copy(tempfile, r)
	tempfile.Seek(0, io.SeekStart)
	return tempfile, err
}

func NormalizeReader(r io.Reader) *normalizeReader {
	return &normalizeReader{r, nil, false, false}
}
