package probe

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pawal/php2shell/engine/verdict"
)

func TestOtherPlatforms(t *testing.T) {
	cases := []struct {
		name               string
		cookies, poweredBy []string
		want               string
	}{
		{"java", []string{"JSESSIONID"}, nil, "Java (JSESSIONID cookie)"},
		{"play once", []string{"PLAY_FLASH", "PLAY_SESSION"}, nil, "Play Framework (PLAY_SESSION cookie)"},
		{"asp.net session", []string{"ASP.NET_SessionId"}, nil, "ASP.NET (ASP.NET_SessionId cookie)"},
		{"express header", nil, []string{"Express"}, "Express (X-Powered-By Express)"},
		{"next.js", nil, []string{"Next.js"}, "Next.js (X-Powered-By Next.js)"},
		{"django", []string{"csrftoken", "sessionid"}, nil, "Django (csrftoken cookie)"},
		{"two platforms", []string{"JSESSIONID"}, []string{"Express"}, "Java (JSESSIONID cookie),Express (X-Powered-By Express)"},
		{"iis header is not asp.net", nil, []string{"ASP.NET"}, ""},
		{"lowercase lookalike", []string{"jsessionid"}, nil, ""},
		{"php", []string{"PHPSESSID"}, []string{"PHP/8.4.27"}, ""},
	}
	for _, c := range cases {
		if got := strings.Join(otherPlatforms(c.cookies, c.poweredBy), ","); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// A cookie set on a redirect counts, as on a login flow.
func TestCheckNamesOtherPlatform(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "abc"})
			http.Redirect(w, r, "/portal", http.StatusFound)
			return
		}
		fmt.Fprint(w, "<html><body>login</body></html>")
	}))
	defer srv.Close()
	in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL, false)
	if err != nil {
		t.Fatal(err)
	}
	got := verdict.Judge(in)
	if strings.Join(evidence.Passive.Platforms, ",") != "Java (JSESSIONID cookie)" || got.Verdict != verdict.NoPHPSignal || !strings.Contains(got.Summary, "they point to Java (JSESSIONID cookie) instead") {
		t.Errorf("%+v %+v", evidence.Passive.Platforms, got)
	}
}
