package probe

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pawal/php2shell/engine/verdict"
)

func TestInspectionBlock(t *testing.T) {
	cases := []struct {
		name, body, header string
		status             int
		blocked            bool
	}{
		{"cloudflare header", "", "challenge", 200, true},
		{"cloudflare page", `<title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/a.js"></script>`, "", 200, true},
		{"observed javascript challenge", `<title>One moment, please...</title><script>var b='wsidchk';</script>`, "", 200, true},
		{"ordinary loading page", `<title>One moment, please...</title><script>loadApp()</script>`, "", 200, false},
		{"ordinary cloudflare proxy", `<p>Welcome</p>`, "", 200, false},
		{"authentication", "", "", 401, true},
		{"forbidden", "", "", 403, true},
		{"rate limited", "", "", 429, true},
		{"not found", "", "", 404, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := response("/", map[string][]string{"Cf-Mitigated": {c.header}})
			resp.StatusCode = c.status
			if got := inspectionBlock(resp, c.body); (got != "") != c.blocked {
				t.Fatalf("%q", got)
			}
		})
	}
}

func TestBlockedCheckSendsNoFurtherRequests(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Cf-Mitigated", "challenge")
		fmt.Fprint(w, `<a href="/login.php">login</a><meta name="generator" content="WordPress">`)
	}))
	defer srv.Close()
	in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 1 || in.Oracle != verdict.OracleNotRun || verdict.Judge(in).Verdict != verdict.InspectionBlocked || len(in.Hints) != 0 || evidence.Passive.Blocked == "" {
		t.Fatalf("%d %+v %+v", requests, in, evidence)
	}
}

func TestBlockedOracleStopsFurtherRequests(t *testing.T) {
	posts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
			w.Header().Set("Cf-Mitigated", "challenge")
			fmt.Fprint(w, readWarnings)
		}
	}))
	defer srv.Close()
	in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	if posts != 1 || verdict.Judge(in).Verdict != verdict.InspectionBlocked || evidence.Requests[0].Blocked == "" {
		t.Fatalf("%d %+v %+v", posts, in, evidence)
	}
}
