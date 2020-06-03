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

	// Trim trailing \r\n
	for {
		trimmed := bytes.TrimSuffix(raw, []byte("\r\n"))
		if string(trimmed) == string(raw) {
			break
		}
		raw = trimmed
	}
	if len(raw) == 0 {
		return raw, nil
	}
	return append(raw, '\r', '\n'), nil
}
