package pkg

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/driusan/dkim/pkg/algorithms"
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

func (s Signature) String() string {
	ret := fmt.Sprintf("DKIM-Signature: v=%d", s.Version)
	if s.Algorithm != "" {
		ret += fmt.Sprintf("; a=%v", s.Algorithm)
	}
	var h, b string
	if s.HeaderCanonicalization != "" {
		h = s.HeaderCanonicalization
	} else {
		h = "simple"
	}
	if s.BodyCanonicalization != "" {
		b = s.BodyCanonicalization
	} else {
		b = "simple"
	}

	ret += fmt.Sprintf("; c=%v/%v", h, b)
	if s.Domain != "" {
		ret += fmt.Sprintf("; d=%v", s.Domain)
	}
	if s.Selector != "" {
		ret += fmt.Sprintf("; s=%v", s.Selector)
	}
	if len(s.Headers) > 0 {
		ret += fmt.Sprintf("; h=%v", strings.Join(s.Headers, ":"))
	}
	if s.BodyHash != "" {
		ret += fmt.Sprintf("; bh=%v", s.BodyHash)
	}

	// Always include an empty b= tag if one doesn't exist.
	ret += fmt.Sprintf("; b=%v", s.Body)
	return ret
}

func NewSignature(canon string, selector string, algorithm algorithms.Algorithm, domain string, headers []string) (Signature, error) {
	sig := Signature{
		Version:                1,
		Algorithm:              algorithm.Name(),
		Domain:                 domain,
		HeaderCanonicalization: "simple",
		BodyCanonicalization:   "simple",
		Selector:               selector,
		Headers:                headers,
	}
	switch canon {
	case "simple/simple", "simple":
		// nothing
	case "relaxed/relaxed", "relaxed", "":
		sig.HeaderCanonicalization = "relaxed"
		sig.BodyCanonicalization = "relaxed"
	case "simple/relaxed":
		sig.HeaderCanonicalization = "simple"
		sig.BodyCanonicalization = "relaxed"
	case "relaxed/simple":
		sig.HeaderCanonicalization = "relaxed"
		sig.BodyCanonicalization = "simple"
	default:
		return Signature{}, fmt.Errorf("Bad canonicalization")
	}
	return sig, nil
}

func (s Signature) Sig() []byte {
	decoded, err := base64.StdEncoding.DecodeString(s.Body)
	if err != nil {
		return nil
	}
	return decoded
}

type Tag struct {
	Name, Value string
}

func splitTags(s []byte) []Tag {
	var tgs []Tag
	tags := bytes.Split(s, []byte{';'})
	for _, t := range tags {
		if strings.TrimSpace(string(t)) == "" {
			continue
		}
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
//
// If s is passed, it will be used as the DKIM signature (for signing), otherwise
// the signature will be parsed from the message header (for verification). When
// signing, sig.BodyHash will be populated, and when verifying, it will be compared
func signatureBase(r io.ReadSeeker, s *Signature) (sig *Signature, msg, dkimHeader []byte, err error) {
	headers := make(map[string][]Header)
	for raw, conv, err := ReadSMTPHeaderRelaxed(r); err == nil; raw, conv, err = ReadSMTPHeaderRelaxed(r) {
		split := bytes.SplitN(conv, []byte{':'}, 2)
		name := string(split[0])
		// headers acts as an upside-down stack. We add the oldest ones
		// to the start, and consume from the front in dkimMessageBase.
		headers[name] = append([]Header{{raw, conv}}, headers[name]...)
		if name == "dkim-signature" && s == nil {
			sig = ParseSignature(raw)
		}
	}
	cBody, err := ReadSMTPBodyRelaxed(r)
	if err != nil {
		return nil, nil, nil, err
	}
	sha := sha256.Sum256(cBody[:])
	encoded := base64.StdEncoding.EncodeToString(sha[:])
	if s != nil {
		sig = s
		s.BodyHash = encoded
		raw := []byte(s.String())
		relax := relaxHeader(raw)
		headers["dkim-signature"] = append([]Header{{raw, relax}}, headers["dkim-signature"]...)
	}
	if sig == nil {
		return nil, nil, nil, fmt.Errorf("Permanent failure: no DKIM signature")
	}
	if encoded != sig.BodyHash {
		return nil, nil, nil, fmt.Errorf("Permanent failure: body hash does not match")
	}

	var toHash []byte
	for _, h := range sig.Headers {
		var hVal Header
		lh := strings.ToLower(h)
		if header, ok := headers[lh]; ok && len(header) > 0 {
			// If there is a header, consume it so that if a header
			// is included in sig.Headers multiple times the next
			// one is correct.
			hVal = header[0]
			headers[lh] = header[1:]
		}
		switch sig.HeaderCanonicalization {
		case "simple":
			toHash = append(toHash, hVal.Raw...)
		case "relaxed":
			toHash = append(toHash, hVal.Relaxed...)
		}
	}
	var signatureHead []byte
	rawSignature, ok := headers["dkim-signature"]
	if !ok {
		return nil, nil, nil, fmt.Errorf("Permanent failure: No DKIM-Signature")
	}
	if sig.HeaderCanonicalization == "relaxed" {
		signatureHead = bytes.TrimRight(rawSignature[0].Relaxed, "\r\n")
	} else {
		signatureHead = bytes.TrimRight(rawSignature[0].Raw, "\r\n")
	}
	return sig, toHash, signatureHead, nil

}

var bRE = regexp.MustCompile("b=.+($|;)")

func SignedHeader(s Signature, r io.ReadSeeker, dst io.Writer, key *rsa.PrivateKey, nl string) error {
	if nl != "\n" {
		nl = "\r\n"
	}
	sig, msg, baseDKIMSignature, err := signatureBase(r, &s)
	algorithm := algorithms.Find(s.Algorithm)
	b, err := signDKIMMessage(msg, baseDKIMSignature, algorithm, key)
	if err != nil {
		return err
	}
	sig.Body = b
	_, _ = fmt.Fprintf(dst, "%v%v", sig, nl)
	return nil
}

// SignMessage signs the message in r with the signature parameters from s and
// the private key key, writing the result with the added DKIM-Signature to
// dst.
func SignMessage(s Signature, r io.ReadSeeker, dst io.Writer, key *rsa.PrivateKey, nl string) error {
	if nl != "\n" {
		nl = "\r\n"
	}
	sig, msg, baseDKIMSignature, err := signatureBase(r, &s)
	algorithm := algorithms.Find(s.Algorithm)
	b, err := signDKIMMessage(msg, baseDKIMSignature, algorithm, key)
	if err != nil {
		return err
	}
	sig.Body = b
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return err
	}
	lineScanner := bufio.NewScanner(r)
	addedSig := false
	for lineScanner.Scan() {
		if err := lineScanner.Err(); err != nil {
			return err
		}
		line := lineScanner.Text()
		if strings.HasPrefix(line, "From ") {
			_, _ = fmt.Fprintf(dst, "%v%v", line, nl)
			continue
		}
		if !addedSig {
			addedSig = true
			_, _ = fmt.Fprintf(dst, "%v%v", sig, nl)
			_, _ = fmt.Fprintf(dst, "%v%v", line, nl)
		} else {
			_, _ = fmt.Fprintf(dst, "%v%v", line, nl)
		}
	}
	return nil
}

// signDKIMMessage signs a message that has already been canonicalized according
// to the DKIM standard.
func signDKIMMessage(message, dkimSignature []byte, algorithm algorithms.Algorithm, key *rsa.PrivateKey) (b string, err error) {
	dkimSignature = bRE.ReplaceAll(dkimSignature, []byte{'b', '='})
	message = append(message, dkimSignature...)
	switch algorithm.Name() {
		case "rsa-sha256", "sha256":
			hash := sha256.Sum256(message)
			v, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, hash[:])
			if err != nil {
				return "", err
			}
			return base64.StdEncoding.EncodeToString(v), nil

		case "rsa-sha1", "sha1":
			hash := sha1.Sum(message)
			v, err := rsa.SignPKCS1v15(nil, key, crypto.SHA1, hash[:])
			if err != nil {
				return "", err
			}
			return base64.StdEncoding.EncodeToString(v), nil
	}
	return "", fmt.Errorf("permanent failure: unknown algorithm")
}

// dkimVerify verifies that a message verifies with header of dkimsig and a
// signature of sig, using the PublicKey key.
//
// message must already prepared according to the DKIM standard (ie. it must only be the
// headers of the DKIM-Signature field, and they must already be canonicalized). dkimsig
// must also be canonicalized, but does not need to have had the b= tag stripped yet.
//
// This function is mostly for testing with a known key. In general, you should use the
// Verify function which does the same thing, but extracts the public key from the appropriate
// place according to the dkimsig.
func dkimVerify(message, dkimSignature []byte, sig []byte, algorithm algorithms.Algorithm, key interface{}) error {
	dkimSignature = bRE.ReplaceAll(dkimSignature, []byte{'b', '='})
	message = append(message, dkimSignature...)

	if algorithm == nil {
		return fmt.Errorf("permanent failure: unknown algorithm")
	}

	return algorithm.Verify(message, sig,  key)

	//switch algorithm.Name() {
	//case "rsa-sha256", "sha256":
	//	hash := sha256.Sum256(message)
	//	return rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], sig)
	//case "rsa-sha1", "sha1":
	//	hash := sha1.Sum(message)
	//	return rsa.VerifyPKCS1v15(key, crypto.SHA1, hash[:], sig)
	//}

}

// VerifyWithPublicKey verifies a reader r, but uses the passed public key
// instead of trying to extract the key from the DNS.
func VerifyWithPublicKey(r io.ReadSeeker, key *crypto.PublicKey) error {
	sig, msg, signatureHead, err := signatureBase(r, nil)
	if err != nil {
		return err
	}
	if key == nil {
		if key, err = lookupKeyFromDNS(sig.Selector + "._domainkey." + sig.Domain); err != nil {
			return err
		}
	}
	signatureHash, err := base64.StdEncoding.DecodeString(sig.Body)
	if err != nil {
		return fmt.Errorf("Permanent failure: could not decode body")
	}
	algorithm := algorithms.Find(sig.Algorithm)
	return dkimVerify(msg, signatureHead, signatureHash, algorithm, key)
}

// Verify verifies the message from reader r has a valid DKIM signature.
//
// Newlines in r must already be in CRLF format.
func Verify(r io.ReadSeeker) error {
	return VerifyWithPublicKey(r, nil)
}

func DecodeDNSTXT(txt string) (*crypto.PublicKey, error) {
	for _, tag := range splitTags([]byte(txt)) {
		if tag.Name == "p" {
			decoded, err := base64.StdEncoding.DecodeString(tag.Value)
			if err != nil {
				continue
			}
			key, err := x509.ParsePKIXPublicKey(decoded)
			if err != nil {
				continue
			}
			if c, ok := key.(*crypto.PublicKey); ok {
				return c, nil
			}
		}
	}
	return nil, fmt.Errorf("no key found")
}
func lookupKeyFromDNS(loc string) (*crypto.PublicKey, error) {
	txt, err := net.LookupTXT(loc)
	if err != nil {
		return nil, fmt.Errorf("Temporary failure: %v", err)
	}
	for _, entry := range txt {
		if key, err := DecodeDNSTXT(entry); err == nil {
			return key, nil
		}
	}
	return nil, fmt.Errorf("permanent error: no public key found")
}
