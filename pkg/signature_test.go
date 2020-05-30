package pkg

import (
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
