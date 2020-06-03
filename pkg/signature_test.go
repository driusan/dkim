package pkg

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func compareSignature(a, b Signature) bool {
	if a.Version != b.Version {
		return false
	}
	if a.Algorithm != b.Algorithm {
		return false
	}
	if a.HeaderCanonicalization != b.HeaderCanonicalization {
		return false
	}
	if a.BodyCanonicalization != b.BodyCanonicalization {
		return false
	}
	if a.Domain != b.Domain {
		return false
	}
	if a.Selector != b.Selector {
		return false
	}
	if a.BodyHash != b.BodyHash {
		return false
	}
	if a.Body != b.Body {
		return false
	}
	if len(a.Headers) != len(b.Headers) {
		return false
	}
	for i := range a.Headers {
		if a.Headers[i] != b.Headers[i] {
			return false
		}
	}
	return true
}
func TestParseSignature(t *testing.T) {
	tests := []struct {
		Header   string
		Expected Signature
	}{
		{
			`DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
		           d=gmail.com; s=20120113;
		           h=mime-version:date:message-id:subject:from:to:content-type;
		           bh=dR8juwuev4e6Fvx8i83p3bEGBvVNoqjMODydu5jBO3w=;
		           b=JCDj28y8XYsO966hVa5ZEuWjfJE/X8+taTThyL2oSn+2ia76pc8sifMt1vJYqI6Pq/
		            sy0gpVqrnB5DVOZjG2mkRpE+wnQTgChTFNBwGdlV1aMNIjvNzhRU4kEyAd9e4G7XzENP
		            yH2tE9JFrap10ic5zb1WP4nl3ZPu8xg9+wuHg8GarD3cbmFhjJQgRf2bZ4yJA6NTgtTV
		            +vt8AZYGV6+Ar6OQ+Jhhmto/fI3ISLyWiorfg/brJLhDdo68h88Hs/KME2Kzqm5yN5it
		            rggEx7csYBYRQDDu9b8TdXU6Y5gSa4qHrDQtGmXpAFzeH/+N21pWnL6jdHZy5d70NvAA
		            MJ3A==`,
			Signature{
				Version:                1,
				Algorithm:              "rsa-sha256",
				HeaderCanonicalization: "relaxed",
				BodyCanonicalization:   "relaxed",
				Domain:                 "gmail.com",
				Selector:               "20120113",
				Headers:                []string{"mime-version", "date", "message-id", "subject", "from", "to", "content-type"},
				BodyHash:               "dR8juwuev4e6Fvx8i83p3bEGBvVNoqjMODydu5jBO3w=",
				Body:                   `JCDj28y8XYsO966hVa5ZEuWjfJE/X8+taTThyL2oSn+2ia76pc8sifMt1vJYqI6Pq/sy0gpVqrnB5DVOZjG2mkRpE+wnQTgChTFNBwGdlV1aMNIjvNzhRU4kEyAd9e4G7XzENPyH2tE9JFrap10ic5zb1WP4nl3ZPu8xg9+wuHg8GarD3cbmFhjJQgRf2bZ4yJA6NTgtTV+vt8AZYGV6+Ar6OQ+Jhhmto/fI3ISLyWiorfg/brJLhDdo68h88Hs/KME2Kzqm5yN5itrggEx7csYBYRQDDu9b8TdXU6Y5gSa4qHrDQtGmXpAFzeH/+N21pWnL6jdHZy5d70NvAAMJ3A==`,
			},
		},
	}
	for i, tc := range tests {
		got := ParseSignature([]byte(tc.Header))
		if got == nil {
			t.Errorf("Case %d: got nil", i)
			continue
		}
		if !compareSignature(*got, tc.Expected) {
			t.Errorf("Case %d: got %v want %v", i, *got, tc.Expected)
		}
	}
}

func TestMySignature(t *testing.T){
	const mail=`DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=denv.it; s=dkim; h=From:Subject:To:Date; bh=OtkrXxv14T+F6uhQyzH47PWSt1t+ylmui9+0BU1g9gY=; b=AcHNxiJiKGhXCSQMlTZTLkRevyRcer8ByFfIVtQZJFLGDfUGRWR8g27TMaY1lx5Keebyog/jyGV+6YfQySXXBA==
Received: from _
	by mail.ded2.denv.it (chasquid) with ESMTPSA
	tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(over submission, TLS-1.2, envelope from "denys@denv.it")
	; Sun, 31 May 2020 12:45:12 +0000
MIME-Version: 1.0
Date: Sun, 31 May 2020 12:45:12 +0000
Content-Type: multipart/alternative;
 boundary="--=_RainLoop_515_726042556.1590929112"
X-Mailer: RainLoop/1.14.0
From: denys@denv.it
Message-ID: <2c321e8c3622fa4d7bc291de4b6a4ead@denv.it>
Subject: test dkim
To: denys.vitali@gmail.com


----=_RainLoop_515_726042556.1590929112
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: quoted-printable

dkim test

----=_RainLoop_515_726042556.1590929112
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE html><html><head><meta http-equiv=3D"Content-Type" content=3D"t=
ext/html; charset=3Dutf-8" /></head><body><div data-html-editor-font-wrap=
per=3D"true" style=3D"font-family: arial, sans-serif; font-size: 13px;">d=
kim test<br><br><signature></signature></div></body></html>

----=_RainLoop_515_726042556.1590929112--`

	const dnsRecord = `v=DKIM1; k=ed25519; p=B8MDQdyVkX4sFJ1MIk7XRyH39grXCF5SKkaietDfeSI=`

	r, err := FileBuffer(NormalizeReader(strings.NewReader(mail)))
	if err != nil {
		t.Fatal(err)
	}

	pubKey, err := DecodeDNSTXT(dnsRecord)
	if err != nil {
		t.Fatal(err)
	}

	err = VerifyWithPublicKey(r, pubKey)
	assert.Nil(t, err)
}
