package dkim

import (
	//"fmt"
	"encoding/base64"
	"os"

	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"
)

// TestDisclosure tests that Edgar D. Mitchell, Apollo 14 Astronaut and 6th man to
// walk on the moon is legit.
func TestDisclosure(t *testing.T) {
	var body = `Delivered-To: john.podesta@gmail.com
Received: by 10.204.162.79 with SMTP id u15csp206492bkx;
        Tue, 14 Jan 2014 03:29:55 -0800 (PST)
Return-Path: <rhardcastlewright@gmail.com>
Received-SPF: pass (google.com: domain of rhardcastlewright@gmail.com designates 10.205.0.4 as permitted sender) client-ip=10.205.0.4
Authentication-Results: mr.google.com;
       spf=pass (google.com: domain of rhardcastlewright@gmail.com designates 10.205.0.4 as permitted sender) smtp.mail=rhardcastlewright@gmail.com;
       dkim=pass header.i=@gmail.com
X-Received: from mr.google.com ([10.205.0.4])
        by 10.205.0.4 with SMTP id nk4mr20177bkb.166.1389698995180 (num_hops = 1);
        Tue, 14 Jan 2014 03:29:55 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20120113;
        h=mime-version:date:message-id:subject:from:to:content-type;
        bh=dR8juwuev4e6Fvx8i83p3bEGBvVNoqjMODydu5jBO3w=;
        b=JCDj28y8XYsO966hVa5ZEuWjfJE/X8+taTThyL2oSn+2ia76pc8sifMt1vJYqI6Pq/
         sy0gpVqrnB5DVOZjG2mkRpE+wnQTgChTFNBwGdlV1aMNIjvNzhRU4kEyAd9e4G7XzENP
         yH2tE9JFrap10ic5zb1WP4nl3ZPu8xg9+wuHg8GarD3cbmFhjJQgRf2bZ4yJA6NTgtTV
         +vt8AZYGV6+Ar6OQ+Jhhmto/fI3ISLyWiorfg/brJLhDdo68h88Hs/KME2Kzqm5yN5it
         rggEx7csYBYRQDDu9b8TdXU6Y5gSa4qHrDQtGmXpAFzeH/+N21pWnL6jdHZy5d70NvAA
         MJ3A==
MIME-Version: 1.0
X-Received: by 10.205.0.4 with SMTP id nk4mr25478bkb.166.1389698995105; Tue,
 14 Jan 2014 03:29:55 -0800 (PST)
Received: by 10.204.233.201 with HTTP; Tue, 14 Jan 2014 03:29:55 -0800 (PST)
Date: Tue, 14 Jan 2014 06:29:55 -0500
Message-ID: <CAEae_ZALrrD81_kAD9TLKBpAXPaaaTWqmuw3S5w444t2+iud3Q@mail.gmail.com>
Subject: Dr Edgar Mitchell Request for Appointment
From: Rebecca Hardcastle Wright <rhardcastlewright@gmail.com>
To: John Podesta <john.podesta@gmail.com>, 
 John Podesta <jpodesta@americanprogress.org>, 
 Eryn Sepp <eryn.sepp@gmail.com>, Eryn Sepp <esepp@americanprogress.org>
Content-Type: multipart/alternative; boundary=20cf301cc2ccf2dab204efec82f8

--20cf301cc2ccf2dab204efec82f8
Content-Type: text/plain; charset=windows-1252
Content-Transfer-Encoding: quoted-printable

Re:  Dr. Edgar Mitchell requests a phone appointment to discuss Disclosure
of the Extraterrestrial Presence


Dear John Podesta:



Congratulations on your recent appointment as counselor to President Barack
Obama. Now within the Obama administration, you are in the unique position
to address disclosure of the extraterrestrial presence in a manner that
promotes science, technology, peace, Earth sustainability and space.



John, I would like to schedule a phone conversation at your earliest
convenience to discuss what I feel are intensifying imperatives for
extraterrestrial disclosure.



For many years you and I have shared a mutual vision of disclosure. I
highly commend your public record urging disclosure which includes the
forward you wrote for Leslie Kean=92s book and your call for the Pentagon=
=92s
release of 25 year old classified government papers on UFO investigations.
 When our government releases this classified information we become
the twenty-fifth country to make public disclosure.


You and I also share a mutual vision for earth sustainability apparent in
the escalating demand for a change in global energy policy. Our phone
discussion will also include the zero point energy research and
applications developed by my Quantrek international science team. Advanced
energy science is linked to consciousness research and public disclosure of
the extraterrestrial presence.



Global consciousness remains one of my top priorities. I envision our
species entering deep space as advanced, cooperative, consciously aware and
nonviolent. We are not alone in the universe. How we relate to other
intelligent life matters. Understanding how nonviolent ETI from the
contiguous universe travel to Earth by means of zero point energy is key to
our acceleration as space-faring humans.



Thank you for letting me know your availability for our phone call.
Rebecca Hardcastle Wright, our Washington DC representative for Quantrek,
will be in contact with Eryn Sepp regarding scheduling.



Best regards,

Edgar



Edgar D. Mitchell, ScD

Chief Science Officer & Founder, Quantrek

Apollo 14 astronaut

6th man to walk on the Moon

--20cf301cc2ccf2dab204efec82f8
Content-Type: text/html; charset=windows-1252
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><p class=3D"MsoNormal" style=3D"margin-bottom:0.0001pt;fon=
t-family:arial,sans-serif"><span style=3D"font-family:Arial,sans-serif"><fo=
nt>Re: =A0Dr. Edgar Mitchell requests a phone appointment to discuss Disclo=
sure of the Extraterrestrial Presence=A0</font></span></p>
<p class=3D"MsoNormal" style=3D"margin-bottom:0.0001pt;font-family:arial,sa=
ns-serif"><span style=3D"font-family:Arial,sans-serif"><br></span></p><p cl=
ass=3D"MsoNormal" style=3D"margin-bottom:0.0001pt;font-family:arial,sans-se=
rif"><span style=3D"font-family:Arial,sans-serif">Dear=A0<font color=3D"#00=
0000" style=3D"background-color:rgb(255,255,255)"><span class=3D"">John</sp=
an>=A0<span class=3D"">Podesta</span>:</font></span></p>
<p class=3D"MsoNormal" style=3D"margin-bottom:0.0001pt;font-family:arial,sa=
ns-serif"><span style=3D"font-family:Arial,sans-serif">=A0</span></p><p cla=
ss=3D"MsoNormal" style=3D"margin-bottom:0.0001pt;font-family:arial,sans-ser=
if"><span style=3D"font-family:Arial,sans-serif">Congratulations on your re=
cent appointment as counselor to President Barack Obama. Now within the Oba=
ma administration, you are in the unique position to address disclosure of =
the extraterrestrial presence in a manner that promotes science, technology=
, peace, Earth sustainability and space.</span></p>
<p class=3D"MsoNormal" style=3D"margin-bottom:0.0001pt;font-family:arial,sa=
ns-serif"><span style=3D"font-family:Arial,sans-serif">=A0</span></p><p cla=
ss=3D"MsoNormal" style=3D"margin-bottom:0.0001pt;font-family:arial,sans-ser=
if"><span style=3D"font-family:Arial,sans-serif"><span style=3D"background-=
color:rgb(255,255,255)"><span class=3D"">John</span>,</span> I would like t=
o schedule a phone conversation at your earliest convenience to discuss wha=
t I feel are intensifying imperatives for extraterrestrial disclosure.=A0</=
span></p>
<p class=3D"MsoNormal" style=3D"margin-bottom:0.0001pt;font-family:arial,sa=
ns-serif"><span style=3D"font-family:Arial,sans-serif">=A0</span></p><p cla=
ss=3D"MsoNormal" style=3D"margin-bottom:0.0001pt;font-family:arial,sans-ser=
if"><font face=3D"Arial, sans-serif">For many years you and I have shared a=
 mutual vision of disclosure. I highly commend your public record urging di=
sclosure which includes the forward you wrote for Leslie Kean=92s book and =
your call for the Pentagon=92s release of 25 year old classified government=
 papers on UFO investigations. =A0When our government releases this classif=
ied information we become the=A0twenty-fifth=A0country to make public discl=
osure.</font></p>
<p class=3D"MsoNormal" style=3D"margin-bottom:0.0001pt;font-family:arial,sa=
ns-serif"><span style=3D"font-family:Arial,sans-serif"><br></span></p><p cl=
ass=3D"MsoNormal" style=3D"margin-bottom:0.0001pt;font-family:arial,sans-se=
rif"><span style=3D"font-family:Arial,sans-serif">You and I also share a mu=
tual vision for earth sustainability apparent in the escalating demand for =
a change in global energy policy. Our phone discussion will also include th=
e zero point energy research and applications developed by my Quantrek inte=
rnational science team. Advanced energy science is linked to consciousness =
research and public disclosure of the extraterrestrial presence.=A0</span><=
span style=3D"font-family:Arial,sans-serif">=A0</span></p>
<p class=3D"MsoNormal" style=3D"margin-bottom:0.0001pt;font-family:arial,sa=
ns-serif"><span style=3D"font-family:Arial,sans-serif">=A0</span></p><p cla=
ss=3D"MsoNormal" style=3D"margin-bottom:0.0001pt;font-family:arial,sans-ser=
if"><span style=3D"font-family:Arial,sans-serif">Global consciousness remai=
ns one of my top priorities. I envision our species entering deep space as =
advanced, cooperative, consciously aware and nonviolent. We are not alone i=
n the universe. How we relate to other intelligent life matters. Understand=
ing how nonviolent ETI from the contiguous universe travel to Earth by mean=
s of zero point energy is key to our acceleration as space-faring humans.</=
span></p>
<p class=3D"MsoNormal" style=3D"margin-bottom:0.0001pt;font-family:arial,sa=
ns-serif"><span style=3D"font-family:Arial,sans-serif">=A0</span></p><p cla=
ss=3D"MsoNormal" style=3D"margin-bottom:0.0001pt;font-family:arial,sans-ser=
if"><span style=3D"font-family:Arial,sans-serif">Thank you for letting me k=
now your availability for our phone call.=A0 Rebecca Hardcastle Wright, our=
 Washington DC representative for Quantrek, will be in contact with Eryn Se=
pp regarding scheduling. =A0</span><span style=3D"font-family:&#39;Times Ne=
w Roman&#39;,serif"></span></p>
<p class=3D"MsoNormal" align=3D"right" style=3D"margin-bottom:0.0001pt;font=
-family:arial,sans-serif;text-align:right"><span style=3D"font-family:Arial=
,sans-serif">=A0</span></p><p class=3D"MsoNormal" align=3D"right" style=3D"=
margin-bottom:0.0001pt;font-family:arial,sans-serif;text-align:right">
<span style=3D"font-family:Arial,sans-serif">Best regards,</span><span styl=
e=3D"font-family:&#39;Times New Roman&#39;,serif"></span></p><p class=3D"Ms=
oNormal" align=3D"right" style=3D"margin-bottom:0.0001pt;font-family:arial,=
sans-serif;text-align:right">
<span style=3D"font-family:Arial,sans-serif">Edgar</span><span style=3D"fon=
t-family:&#39;Times New Roman&#39;,serif"></span></p><p class=3D"MsoNormal"=
 align=3D"right" style=3D"margin-bottom:0.0001pt;font-family:arial,sans-ser=
if;text-align:right">
<span style=3D"font-family:Arial,sans-serif">=A0</span><span style=3D"font-=
family:&#39;Times New Roman&#39;,serif"></span></p><p class=3D"MsoNormal" a=
lign=3D"right" style=3D"margin-bottom:0.0001pt;font-family:arial,sans-serif=
;text-align:right">
<span style=3D"font-family:Arial,sans-serif">Edgar D. Mitchell, ScD</span><=
span style=3D"font-family:&#39;Times New Roman&#39;,serif"></span></p><p cl=
ass=3D"MsoNormal" align=3D"right" style=3D"margin-bottom:0.0001pt;font-fami=
ly:arial,sans-serif;text-align:right">
<span style=3D"font-family:Arial,sans-serif">Chief Science Officer &amp; Fo=
under, Quantrek</span><span style=3D"font-family:&#39;Times New Roman&#39;,=
serif"></span></p><p class=3D"MsoNormal" align=3D"right" style=3D"margin-bo=
ttom:0.0001pt;font-family:arial,sans-serif;text-align:right">
<span style=3D"font-family:Arial,sans-serif">Apollo 14 astronaut</span><spa=
n style=3D"font-family:&#39;Times New Roman&#39;,serif"></span></p><p class=
=3D"MsoNormal" align=3D"right" style=3D"margin-bottom:0.0001pt;font-family:=
arial,sans-serif;text-align:right">
<span style=3D"font-family:Arial,sans-serif"><font>6th man to walk on the M=
oon</font></span></p></div>

--20cf301cc2ccf2dab204efec82f8--
`

	r, err := FileBuffer(NormalizeReader(strings.NewReader(body)))
	sig, msg, sighead, err := signatureBase(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(r.Name()); err != nil {
		t.Error(err)
	}

	// Snapshot of the key from the DNS record at the time of writing this test..
	keybytes, err := base64.StdEncoding.DecodeString("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Kd87/UeJjenpabgbFwh+eBCsSTrqmwIYYvywlbhbqoo2DymndFkbjOVIPIldNs/m40KF+yzMn1skyoxcTUGCQs8g3FgD2Ap3ZB5DekAo5wMmk4wimDO+U8QzI3SD07y2+07wlNWwIt8svnxgdxGkVbbhzY8i+RQ9DpSVpPbF7ykQxtKXkv/ahW3KjViiAH+ghvvIhkx4xYSIc9oSwVmAl5OctMEeWUwg8Istjqz8BZeTWbf41fbNhte7Y+YqZOwq1Sd0DbvYAD9NOZK9vlfuac0598HY+vtSBczUiKERHv1yRbcaQtZFh5wtiRrN04BLUTD21MycBX5jYchHjPY/wIDAQAB")
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKIXPublicKey(keybytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		t.Fatal("Could not parse public key")
	}
	sighash, err := base64.StdEncoding.DecodeString(sig.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := dkimVerify(msg, sighead, sighash, sig.Algorithm, pub); err != nil {
		t.Error(err)
	}

	// Add some newlines and try again, since it's relaxed body
	// canonicalization this should still succeed.
	r, err = FileBuffer(NormalizeReader(strings.NewReader(body + "\r\n\r\n")))
	sig, msg, sighead, err = signatureBase(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(r.Name()); err != nil {
		t.Error(err)
	}

	if err := dkimVerify(msg, sighead, sighash, sig.Algorithm, pub); err != nil {
		t.Error(err)
	}

	// Change a random character and ensure that it fails.

	bodybyte := []byte(body)
	bodybyte[2048] = 'q'
	r, err = FileBuffer(NormalizeReader(strings.NewReader(string(bodybyte))))

	sig, msg, sighead, err = signatureBase(r, nil)
	if err == nil {
		t.Error("Modified body in signatureBase did not return error")
	}
	if err := os.Remove(r.Name()); err != nil {
		t.Error(err)
	}

	/*	if err := VerifyWithPublicKey(msg, sighead, sighash, sig.Algorithm, pub); err == nil {
		t.Error("Modified body was verified")
	}*/
}
