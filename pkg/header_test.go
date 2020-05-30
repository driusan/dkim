package pkg

import (
	"strings"
	"testing"
)

func TestSimpleHeader(t *testing.T) {
	tests := []struct {
		rawBody  string
		expected []string
	}{
		// Normal case
		{"foo: bar\r\n", []string{"foo: bar\r\n"}},
		// Ensure it doesn't change header case
		{"Foo: bar\r\n", []string{"Foo: bar\r\n"}},
		// See what happens with no line ending. (This shouldn't be
		// possible with SMTP.. but if it happens the whitespace shouldn't
		// be modified.)
		{"Foo: bar", []string{"Foo: bar"}},
		// Ensure it breaks headers at the right place in the normal case
		{"Foo: bar\r\nBar: foo\r\n", []string{"Foo: bar\r\n", "Bar: foo\r\n"}},
		// Ensure continuation lines are part of the right header, but not modified
		{
			"Foo: Bar\r\n with continuation\r\nBar: end\r\n",
			[]string{"Foo: Bar\r\n with continuation\r\n", "Bar: end\r\n"},
		},
		// Ensure the body breaks at the right place
		{
			"Foo: Bar\r\n with continuation\r\nBar: end\r\n\r\nHello",
			[]string{"Foo: Bar\r\n with continuation\r\n", "Bar: end\r\n"},
		},
	}

	for i, tc := range tests {
		body := strings.NewReader(tc.rawBody)
		for j, h := range tc.expected {
			_, converted, err := ReadSMTPHeaderSimple(body)
			if err != nil && err != HeaderEnd {
				t.Errorf("Case %d, Header %d: %v", i, j, err)
				continue
			}
			if string(converted) != h {
				t.Errorf("Case %d, Header %d: got %v want %v", i, j, string(converted), h)
			}
		}
	}
}

func TestRelaxedHeader(t *testing.T) {
	tests := []struct {
		rawbody  string
		expected []string
	}{
		// Normal case
		{"foo: bar\r\n", []string{"foo:bar\r\n"}},
		// Ensure it doesn't change header case
		{"Foo: bar\r\n", []string{"foo:bar\r\n"}},
		// See what happens with no line ending. (This shouldn't be
		// possible with SMTP.. but if it happens the header should still
		// be normalized.)
		{"Foo: bar", []string{"foo:bar\r\n"}},
		// Ensure it breaks headers at the right place in the normal case
		{"Foo: bar\r\nBar: foo\r\n", []string{"foo:bar\r\n", "bar:foo\r\n"}},
		// Ensure continuation lines are normalized
		{
			"Foo: Bar\r\n with continuation\r\nBar: end\r\n",
			[]string{"foo:Bar with continuation\r\n", "bar:end\r\n"},
		},
		// Ensure continuation lines are normalized
		{
			"Foo: Bar\r\n with continuation\r\nBar: end\r\n",
			[]string{"foo:Bar with continuation\r\n", "bar:end\r\n"},
		},
	}

	for i, tc := range tests {
		body := strings.NewReader(tc.rawbody)
		for j, h := range tc.expected {
			_, converted, err := ReadSMTPHeaderRelaxed(body)
			if err != nil && err != HeaderEnd {
				t.Errorf("Case %d, Header %d: %v", i, j, err)
				continue
			}
			if string(converted) != h {
				t.Errorf("Case %d, Header %d: got `%v` want `%v`", i, j, string(converted), h)
			}
		}
	}
}
