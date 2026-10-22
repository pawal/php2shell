package probe

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pawal/php2shell/engine/verdict"
)

func TestRoundcubeFingerprints(t *testing.T) {
	cases := []struct {
		name, body string
		headers    map[string][]string
		signal     string
	}{
		{"session cookie", "", map[string][]string{"Set-Cookie": {"roundcube_sessid=private; HttpOnly; Secure"}}, "cookie"},
		{"auth cookie", "", map[string][]string{"Set-Cookie": {"roundcube_sessauth=private; HttpOnly; Secure"}}, "cookie"},
		{"generator", `<meta content="Roundcube Webmail 1.6.19" name=generator>`, nil, "generator"},
		{"elastic minified assets", `<script src="program/js/common.min.js?s=123"></script><script src="program/js/app.min.js?s=123"></script>`, nil, "assets"},
		{"subdirectory unminified assets", `<script src="/webmail/program/js/common.js"></script><script src="/webmail/program/js/app.js"></script>`, nil, "assets"},
		{"title alone", `<title>Roundcube Webmail</title>`, nil, ""},
		{"prose", `<p>Roundcube uses program/js/app.js and program/js/common.js</p>`, nil, ""},
		{"generic asset pair", `<script src="/js/common.js"></script><script src="/js/app.js"></script>`, nil, ""},
		{"lookalike directory", `<script src="/otherprogram/js/common.js"></script><script src="/otherprogram/js/app.js"></script>`, nil, ""},
		{"cookie suffix lookalike", "", map[string][]string{"Set-Cookie": {"roundcube_sessid_fake=x"}}, ""},
		{"partial assets", `<script src="program/js/app.js"></script>`, nil, ""},
		{"generator prefix lookalike", `<meta name=generator content=Roundcubelike>`, nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := applicationFingerprints(response("/", c.headers), c.body)
			if c.signal == "" {
				if len(got) != 0 {
					t.Fatalf("false positive: %+v", got)
				}
				return
			}
			if len(got) != 1 || got[0].Technology != "Roundcube" || got[0].Signal != c.signal || !strings.Contains(got[0].Source, "roundcube/roundcubemail") {
				t.Fatalf("%+v", got)
			}
			if strings.Contains(fmt.Sprint(got), "private") {
				t.Fatal("cookie value leaked")
			}
		})
	}
}

func TestRoundcubeCheckWithoutPHPVersion(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.SetCookie(w, &http.Cookie{Name: "roundcube_sessid", Value: "private"})
		fmt.Fprint(w, `<title>Roundcube Webmail</title><script src="program/js/common.min.js"></script><script src="program/js/app.min.js"></script><script>rcmail.set_env({"rcversion":10619});</script>`)
	}))
	defer srv.Close()
	in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL, false)
	if err != nil {
		t.Fatal(err)
	}
	result := verdict.Judge(in)
	if requests != 1 || result.Verdict != verdict.Inconclusive || result.Version != nil || !strings.Contains(result.Summary, "Roundcube") || len(evidence.Passive.Fingerprints) != 2 {
		t.Fatalf("%d %+v %+v", requests, result, evidence)
	}
}
