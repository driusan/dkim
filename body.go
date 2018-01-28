package dkim

import (
	"bufio"
	"bytes"
	"io"
)

func ReadSMTPBodyRelaxed(r io.Reader) (raw []byte, err error) {
	linescan := bufio.NewScanner(r)
	for linescan.Scan() {
		if err := linescan.Err(); err != nil {
			return nil, err
		}
		line := whitespaceRE.ReplaceAll(linescan.Bytes(), []byte{' '})
		line = bytes.TrimRight(line, " \t")
		raw = append(raw, line...)
		raw = append(raw, '\r', '\n')
	}
	return raw, nil
}
