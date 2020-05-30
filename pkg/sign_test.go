package pkg

import (
	"crypto/rsa"
	"github.com/driusan/dkim/pkg/algorithms"
	"math/rand"
	"strings"
	"testing"

	"os"
)

const EmailBody = `From: Test <test@example.com>
Date: Wed Jan 24 16:35:04 EST 2018
Subject: I am a test
To: Test2 <test2@example.com
X-Something: This is not included in the hash

This is a test message
`

func TestMessageSigningRSASha256(t *testing.T) {
	r, err := FileBuffer(NormalizeReader(strings.NewReader(EmailBody)))
	if err != nil {
		t.Fatal(err)
	}
	algorithm := algorithms.Find("rsa-sha256")
	s, err := NewSignature(
		"relaxed/relaxed",
		"foo",
		algorithm,
		"example.com",
		[]string{"From", "Date", "Subject", "To"},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, msg, signatureHead, err := signatureBase(r, &s)
	if err := os.Remove(r.Name()); err != nil {
		// Remove the file before checking the error, to ensure
		// that it still gets removed if it's fatal.
		t.Error(err)
	}
	if err != nil {
		t.Fatal(err)
	}

	key, err := rsa.GenerateKey(rand.New(rand.NewSource(0)), 512)
	if err != nil {
		t.Fatal(err)
	}

	b, err := signDKIMMessage(msg, signatureHead, algorithm, key)
	if err != nil {
		t.Error(err)
	}
	s.Body = b
	if err := dkimVerify(msg, signatureHead, s.Sig(), algorithm, &key.PublicKey); err != nil {
		t.Fatalf("Could not re-verify signed message: %v", err)
	}
}

func TestMessageSigningEd25519(t *testing.T) {
	r, err := FileBuffer(NormalizeReader(strings.NewReader(EmailBody)))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSignature(
		"relaxed/relaxed",
		"foo",
		algorithms.RSASha256,
		"example.com",
		[]string{"From", "Date", "Subject", "To"},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, msg, signatureHead, err := signatureBase(r, &s)
	if err := os.Remove(r.Name()); err != nil {
		// Remove the file before checking the error, to ensure
		// that it still gets removed if it's fatal.
		t.Error(err)
	}
	if err != nil {
		t.Fatal(err)
	}

	key, err := rsa.GenerateKey(rand.New(rand.NewSource(0)), 512)
	if err != nil {
		t.Fatal(err)
	}
	b, err := signDKIMMessage(msg, signatureHead, algorithms.RSASha256, key)
	if err != nil {
		t.Error(err)
	}
	s.Body = b
	if err := dkimVerify(msg, signatureHead, s.Sig(), algorithms.RSASha256, &key.PublicKey); err != nil {
		t.Fatalf("Could not re-verify signed message: %v", err)
	}
}

