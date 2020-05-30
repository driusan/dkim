package pkg

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
)

var HeaderEnd = fmt.Errorf("end of mail headers")
var headerEndRE = regexp.MustCompile("\r\n[^\t \n]")

func readRawHeader(r io.ReadSeeker) (raw []byte, err error) {
	buf := make([]byte, 8192)
	// Take a bookmark so that we can seek back to the start of the
	// header for the next read.
	start, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	n, err := r.Read(buf)
	if err != io.EOF && err != nil {
		return nil, err
	}
	if err == io.EOF && n == 0 {
		return nil, io.EOF
	}
	buf = buf[:n]
	re := headerEndRE.FindIndex(buf)
	if re == nil {
		// There was no line ending, so just return what we read and assume
		// it's the end of the headers.
		return buf, nil
	}
	if re[0] == 0 {
		// There were 2 consecutive line ends, marking the end of the
		// header section, so seek to the start of the body after the
		// blank line.
		if _, err := r.Seek(start+2, io.SeekStart); err != nil {
			return nil, err
		}
		return nil, HeaderEnd
	}
	end := re[1] - 1
	// Seek back over anything we over read, so that the next call
	// starts at the right place.
	if _, err := r.Seek(start+int64(end), io.SeekStart); err != nil {
		return nil, err
	}
	return buf[:end], nil
}

func ReadSMTPHeaderSimple(r io.ReadSeeker) (raw, converted []byte, err error) {
	rawBytes, err := readRawHeader(r)
	return rawBytes, rawBytes, err
}

var whitespaceRE = regexp.MustCompile("[\t \n\r]+")

//var whitespaceRE *regexp.Regexp = regexp.MustCompile("[\t \n]+")
var headerRE = regexp.MustCompile("^([[:graph:]]+)[[:space:]]*:[[:space:]]*")

func relaxHeader(rawBytes []byte) []byte {
	conv := whitespaceRE.ReplaceAll(rawBytes, []byte{' '})
	split := headerRE.FindSubmatchIndex(conv)
	if split == nil {
		// This should probably be an error?
		return conv
	}

	convHeader := bytes.ToLower(conv[split[2]:split[3]])
	body := bytes.TrimSpace(conv[split[1]:])
	final := make([]byte, 0, len(convHeader)+1+len(body)+2)
	final = append(final, convHeader...)
	final = append(final, ':')
	final = append(final, body...)
	final = append(final, '\r', '\n')
	return final
}
func ReadSMTPHeaderRelaxed(r io.ReadSeeker) (raw, converted []byte, err error) {
	rawBytes, err := readRawHeader(r)
	if err != nil {
		return nil, nil, err
	}
	final := relaxHeader(rawBytes)
	return rawBytes, final, err
}
