package pkg

import (
	ed255192 "crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"github.com/driusan/dkim/pkg/algorithms"
	"github.com/stretchr/testify/assert"
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

func TestEd25519Sha256DKIM(t *testing.T) {
	const messageContent = `From: Joe SixPack <joe@football.example.com>
To: Suzie Q <suzie@shopping.example.net>
Subject: Is dinner ready?
Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
Message-ID: <20030712040037.46341.5F8J@football.example.com>
DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;
    d=football.example.com; i=@football.example.com;
    q=dns/txt; s=brisbane; t=1528637909; h=from : to :
    subject : date : message-id : from : subject : date;
    bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
    b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus
    Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==

Hi.

We lost the game.  Are you hungry yet?

Joe.
`

	const dkimDNSRecord = `v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=`

	r, err := FileBuffer(NormalizeReader(strings.NewReader(messageContent)))
	sig, msg, signHead, err := signatureBase(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(r.Name()); err != nil {
		t.Error(err)
	}

	pubKey, err := DecodeDNSTXT(dkimDNSRecord)
	assert.Nil(t, err)
	assert.Equal(t, "ed25519-sha256", sig.Algorithm)
	algorithm := algorithms.Find(sig.Algorithm)

	if err := dkimVerify(msg, signHead, sig.Sig(), algorithm, pubKey); err != nil {
		t.Fatalf("Could not re-verify signed message: %v", err)
	}
}

func TestMessageSigningEd25519Sha256(t *testing.T) {
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

	pubKey, privKey, err := ed255192.GenerateKey(rand.New(rand.NewSource(0)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := signDKIMMessage(msg, signatureHead, algorithms.Ed25519Sha256, privKey)
	if err != nil {
		t.Error(err)
	}
	s.Body = b
	if err := dkimVerify(msg, signatureHead, s.Sig(), algorithms.Ed25519Sha256, pubKey); err != nil {
		t.Fatalf("Could not re-verify signed message: %v", err)
	}
}

func TestDNSRecord1(t *testing.T){
	const rfc  = `v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=`
	pubKey, err := DecodeDNSTXT(rfc)
	assert.Nil(t, err)
	ed255192PubKey := pubKey.(ed255192.PublicKey)
	assert.Equal(t, base64.StdEncoding.EncodeToString(ed255192PubKey), `11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=`)

	const mine = `v=DKIM1; k=ed25519; p=B8MDQdyVkX4sFJ1MIk7XRyH39grXCF5SKkaietDfeSI=`
	pubKey, err = DecodeDNSTXT(mine)
	assert.Nil(t, err)
	ed255192PubKey = pubKey.(ed255192.PublicKey)
	assert.Equal(t, base64.StdEncoding.EncodeToString(ed255192PubKey), `B8MDQdyVkX4sFJ1MIk7XRyH39grXCF5SKkaietDfeSI=`)
}