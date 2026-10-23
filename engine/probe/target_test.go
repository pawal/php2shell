package probe

import (
	"errors"
	"testing"
)

func TestParseTarget(t *testing.T) {
	cases := []struct{ in, want string }{
		{"example.com", "https://example.com/"},
		{"Example.COM.", "https://example.com/"},
		{"http://example.com", "http://example.com/"},
		{"https://www.example.com/blog/?q=1#x", "https://www.example.com/blog/"},
		{"example.com:8443", "https://example.com:8443/"},
		{"http://93.184.215.14", "http://93.184.215.14/"},
		{"https://[2606:4700::1]:8443/", "https://[2606:4700::1]:8443/"},
		{"xn--rksmrgs-5wao1o.se", "https://xn--rksmrgs-5wao1o.se/"},
		{"cafe.de", "https://cafe.de/"},
		{"8.8.8.8.", "https://8.8.8.8/"},
	}
	for _, c := range cases {
		got, err := ParseTarget(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if got.URL() != c.want {
			t.Errorf("%q: got %s, want %s", c.in, got.URL(), c.want)
		}
	}
}

func TestParseTargetRefuses(t *testing.T) {
	for _, in := range []string{
		"", "ftp://example.com", "file:///etc/passwd", "javascript:alert(1)",
		"https://user:pw@example.com", "localhost", "intranet", "example.com:0", "example.com:99999",
		"2130706433", "http://2130706433/", "127.1", "0x7f.1", "1.0x7f",
		"http://0x7f000001/", "räksmörgås.se", "exa mple.com", "-a.example.com",
		"http://[fe80::1%25en0]/", "example..com",
	} {
		_, err := ParseTarget(in)
		if !errors.Is(err, ErrInvalidTarget) {
			t.Errorf("%q: got %v, want a refusal", in, err)
		}
	}
}

func TestDefaultedSchemeAndPlainHTTP(t *testing.T) {
	bare, _ := ParseTarget("example.com")
	explicit, _ := ParseTarget("https://example.com/")
	custom, _ := ParseTarget("example.com:8443")
	if !bare.Defaulted || explicit.Defaulted || !custom.Defaulted {
		t.Errorf("defaulted: %v %v %v", bare.Defaulted, explicit.Defaulted, custom.Defaulted)
	}
	if plain := bare.PlainHTTP(); plain.URL() != "http://example.com/" || plain.Defaulted {
		t.Errorf("plain: %+v", plain)
	}
	if plain := custom.PlainHTTP(); plain.URL() != "http://example.com:8443/" {
		t.Errorf("custom port: %s", plain.URL())
	}
}
