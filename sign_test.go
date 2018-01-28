package dkim

import (
	"crypto/rand"
	"crypto/rsa"

	"strings"
	"testing"

	"os"
)

// TestDisclosure tests that Edgar D. Mitchell, Apollo 14 Astronaut and 6th man to
// walk on the moon is legit.
func TestMessageSigning(t *testing.T) {
	var body = `From: Test <test@example.com>
Date: Wed Jan 24 16:35:04 EST 2018
Subject: I am a test
To: Test2 <test2@example.com
X-Something: This is not included in the hash

This is a test message
`

	r, err := FileBuffer(NormalizeReader(strings.NewReader(body)))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSignature(
		"relaxed/relaxed",
		"foo",
		"example.com",
		[]string{"From", "Date", "Subject", "To"},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, msg, sighead, err := signatureBase(r, &s)
	if rerr := os.Remove(r.Name()); rerr != nil {
		// Remove the file before checking the error, to ensure
		// that it still gets removed if it's fatal.
		t.Error(rerr)
	}
	if err != nil {
		t.Fatal(err)
	}

	// FIXME: This should be a hardcoded key to make the message deterministic
	key, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatal(err)
	}
	b, err := signDKIMMessage(msg, sighead, "rsa-sha256", key)
	if err != nil {
		t.Error(err)
	}
	s.Body = b
	if err := dkimVerify(msg, sighead, s.Sig(), "rsa-sha256", &key.PublicKey); err != nil {
		t.Fatalf("Could not re-verify signed message: %v", err)
	}
}
