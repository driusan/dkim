package dkim

import (
	"bytes"
	"fmt"
	"io"
	"net"

	"encoding/base64"

	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"regexp"
	"strconv"
	"strings"
)

type Signature struct {
	Version                                      int
	Algorithm                                    string
	HeaderCanonicalization, BodyCanonicalization string
	Domain, Selector                             string
	Headers                                      []string
	BodyHash                                     string
	Body                                         string
}

type Tag struct {
	Name, Value string
}

func splitTags(s []byte) []Tag {
	var tgs []Tag
	tags := bytes.Split(s, []byte{';'})
	for _, t := range tags {
		splitb := bytes.SplitN(t, []byte{'='}, 2)
		tgs = append(tgs, Tag{string(bytes.TrimSpace(splitb[0])), string(splitb[1])})
	}
	return tgs
}
func ParseSignature(header []byte) *Signature {
	splith := bytes.SplitN(header, []byte{':'}, 2)
	name := string(splith[0])
	if strings.ToLower(name) != "dkim-signature" {
		return nil
	}
	tags := splitTags(splith[1])
	var s Signature
	for _, t := range tags {
		switch t.Name {
		case "v":
			v, err := strconv.Atoi(t.Value)
			if err != nil {
				return nil
			}
			s.Version = v
		case "a":
			s.Algorithm = t.Value
		case "bh":
			s.BodyHash = whitespaceRE.ReplaceAllString(t.Value, "")
		case "b":
			s.Body = whitespaceRE.ReplaceAllString(t.Value, "")
		case "c":
			switch t.Value {
			case "simple", "simple/simple":
				s.HeaderCanonicalization = "simple"
				s.BodyCanonicalization = "simple"
			case "relaxed", "relaxed/relaxed":
				s.HeaderCanonicalization = "relaxed"
				s.BodyCanonicalization = "relaxed"
			case "simple/relaxed":
				s.HeaderCanonicalization = "simple"
				s.BodyCanonicalization = "relaxed"
			case "relaxed/simple":
				s.HeaderCanonicalization = "relaxed"
				s.BodyCanonicalization = "simple"
			default:
				return nil
			}
		case "d":
			s.Domain = t.Value
		case "h":
			s.Headers = strings.Split(whitespaceRE.ReplaceAllString(t.Value, ""), ":")
		case "s":
			s.Selector = t.Value
			// FIXME: Add i, l, q, t, x, z
		}
	}
	return &s
}

type Header struct {
	Raw, Relaxed []byte
}

// signatureBase calculates the basic parts of the DKIM signature
// shared by both signing and verifying.
//
// It extracts the mail headers from r and returns them in a map along
// with the signature. The bodyhash returned is already base64 encoded.
//
// Newlines must already be normalized to CRLF in r.
func signatureBase(r io.ReadSeeker) (sig *Signature, msg, dkimheader []byte, err error) {
	headers := make(map[string][]Header)
	for raw, conv, err := ReadSMTPHeaderRelaxed(r); err == nil; raw, conv, err = ReadSMTPHeaderRelaxed(r) {
		split := bytes.SplitN(conv, []byte{':'}, 2)
		name := string(split[0])
		// headers acts as an upside-down stack. We add the oldest ones
		// to the start, and consume from the front in dkimMessageBase.
		headers[name] = append([]Header{Header{raw, conv}}, headers[name]...)
		if name == "dkim-signature" {
			sig = ParseSignature(raw)
		}
	}
	cbody, err := ReadSMTPBodyRelaxed(r)
	if err != nil {
		return nil, nil, nil, err
	}
	sha := sha256.Sum256(cbody[:])
	encoded := string(base64.StdEncoding.EncodeToString(sha[:]))
	if sig == nil {
		return nil, nil, nil, fmt.Errorf("Permanent failure: no DKIM signature")
	}
	if encoded != sig.BodyHash {
		return nil, nil, nil, fmt.Errorf("Permanent failure: body hash does not match")
	}

	var tohash []byte
	for _, h := range sig.Headers {
		var hval Header
		lh := strings.ToLower(h)
		if header, ok := headers[lh]; ok && len(header) > 0 {
			// If there is a header, consume it so that if a header
			// is included in sig.Headers multiple times the next
			// one is correct.
			hval = header[0]
			headers[lh] = header[1:]
		}
		switch sig.HeaderCanonicalization {
		case "simple":
			tohash = append(tohash, hval.Raw...)
		case "relaxed":
			tohash = append(tohash, hval.Relaxed...)
		}
	}
	var sighead []byte
	rawsig, ok := headers["dkim-signature"]
	if !ok {
		return nil, nil, nil, fmt.Errorf("Permanent failure: No DKIM-Signature")
	}
	if sig.HeaderCanonicalization == "relaxed" {
		sighead = bytes.TrimRight(rawsig[0].Relaxed, "\r\n")
	} else {
		sighead = bytes.TrimRight(rawsig[0].Raw, "\r\n")
	}
	return sig, tohash, sighead, nil

}

var bRE = regexp.MustCompile("b=.+($|;)")

// VerifyWithPublicKey verifies that a message verifies with header of dkimsig and a
//signature of sig, using the PublicKey key.
//
// message must already prepared according to the DKIM standard (ie. it must only be the
// headers of the DKIM-Signature field, and they must already be canonicalized). dkimsig
// must also be canonicalized, but does not need to have had the b= tag stripped yet.
//
// This function is mostly for testing with a known key. In general, you should use the
// Verify function which does the same thing, but extracts the public key from the appropriate
// place according to the dkimsig.
func VerifyWithPublicKey(message, dkimsig []byte, sig []byte, algorithm string, key *rsa.PublicKey) error {
	dkimsig = bRE.ReplaceAll(dkimsig, []byte{'b', '='})
	message = append(message, dkimsig...)
	switch algorithm {
	case "rsa-sha256", "sha256":
		hash := sha256.Sum256(message)
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], sig)
	case "rsa-sha1", "sha1":
		hash := sha1.Sum(message)
		return rsa.VerifyPKCS1v15(key, crypto.SHA1, hash[:], sig)
	}
	return fmt.Errorf("Permanent failure: unknown algorithm")
}

// Verify verifies the message from reader r has a valid DKIM signature.
//
// Newlines in r must already be in CRLF format.
func Verify(r io.ReadSeeker) error {
	sig, msg, sighead, err := signatureBase(r)
	if err != nil {
		return err
	}
	sighash, err := base64.StdEncoding.DecodeString(sig.Body)
	if err != nil {
		return fmt.Errorf("Permanent failure: could not decode body")
	}

	txt, err := net.LookupTXT(sig.Selector + "._domainkey." + sig.Domain)
	if err != nil {
		return fmt.Errorf("Temporary failure: %v", err)
	}
	var pub *rsa.PublicKey
	for _, entry := range txt {
		// FIXME: This should check the k tag instead of assuming
		// rsa
		for _, tag := range splitTags([]byte(entry)) {
			if tag.Name == "p" {
				decoded, err := base64.StdEncoding.DecodeString(tag.Value)
				if err != nil {
					continue
				}
				key, err := x509.ParsePKIXPublicKey(decoded)
				if err != nil {
					continue
				}
				if c, ok := key.(*rsa.PublicKey); ok {
					pub = c
					goto verify
				}
			}
		}
	}
verify:
	if pub == nil {
		return fmt.Errorf("Permanent error: no public key")
	}
	if err := VerifyWithPublicKey(msg, sighead, sighash, sig.Algorithm, pub); err != nil {
		return fmt.Errorf("Permenent error: %v", err)
	}
	return nil
}
