package probe

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/pawal/php2shell/engine/verdict"
)

func externalFixture(t *testing.T, apps map[string]externalApp) *FingerprintDatabase {
	t.Helper()
	data, err := json.Marshal(externalDatabase{Source: "https://example.com/source", License: "test", Apps: apps})
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	db, err := LoadFingerprintDatabase(name)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestExternalPassiveChannels(t *testing.T) {
	db := externalFixture(t, map[string]externalApp{
		"Example CMS": {
			Source: "https://example.com/source", Cookies: map[string]string{"example_sid": "^private-"},
			Headers: map[string]string{"X-Example": "^Example/"}, Meta: map[string]string{"generator": "^Example CMS(?: |$)"},
			ScriptSrc: []string{`/example-cms/app\.js(?:\?|$)`},
		},
	})
	cases := []struct {
		name, body string
		headers    map[string][]string
		want       string
	}{
		{"cookie", "", map[string][]string{"Set-Cookie": {"example_sid=private-cookie-secret"}}, "database_cookie"},
		{"repeated header", "", map[string][]string{"X-Example": {"unrelated", "Example/9.2"}}, "database_header"},
		{"meta", `<META CONTENT="Example CMS 9.2" NAME="GENERATOR">`, nil, "database_meta"},
		{"script", `<script src="/example-cms/app.js?v=9.2"></script>`, nil, "database_scriptSrc"},
		{"cookie value mismatch", "", map[string][]string{"Set-Cookie": {"example_sid=other"}}, ""},
		{"cookie suffix mismatch", "", map[string][]string{"Set-Cookie": {"example_sid_fake=private-secret"}}, ""},
		{"comments", `<!-- <meta name=generator content="Example CMS"> -->`, nil, ""},
		{"inline script", `<script>const x='<meta name=generator content="Example CMS">';</script>`, nil, ""},
		{"data script", `<script src="data:text/javascript,/example-cms/app.js"></script>`, nil, ""},
		{"prose", `<p>Example CMS /example-cms/app.js</p>`, nil, ""},
		{"missing meta content", `<meta name=generator>`, nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := db.Match(response("/", c.headers), c.body)
			if c.want == "" {
				if len(got) != 0 {
					t.Fatalf("unexpected match: %+v", got)
				}
				return
			}
			if len(got) != 1 || got[0].Technology != "Example CMS" || got[0].Signal != c.want || got[0].Confidence != "low" || strings.Contains(fmt.Sprint(got), "secret") {
				t.Fatalf("unexpected evidence: %+v", got)
			}
		})
	}
	resp := response("/", map[string][]string{"X-Example": {"Example/9.2"}})
	resp.StatusCode = 403
	if got := db.Match(resp, ""); len(got) != 0 {
		t.Fatalf("access denial fingerprinted: %+v", got)
	}
}

func TestExternalFingerprintIntegration(t *testing.T) {
	db := externalFixture(t, map[string]externalApp{
		"Example CMS": {Source: "https://example.com/source", Meta: map[string]string{"generator": "^Example CMS"}, Headers: map[string]string{"X-Example": "^Example/"}},
	})
	var mu sync.Mutex
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		if r.URL.Path == "/" {
			w.Header().Set("X-Example", "Example/9.2")
			http.Redirect(w, r, "/landing", http.StatusFound)
			return
		}
		fmt.Fprint(w, `<meta name=generator content="Example CMS 9.2">`)
	}))
	defer srv.Close()
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true, Fingerprints: db}, srv.URL, false)
			if err != nil {
				t.Error(err)
				return
			}
			result := verdict.Judge(in)
			if len(evidence.Passive.Fingerprints) != 2 || !strings.Contains(result.Summary, "Example CMS") || result.Version != nil || result.Verdict != verdict.Inconclusive {
				t.Errorf("%+v %+v", result, evidence)
			}
		})
	}
	wg.Wait()
	if requests != 8 {
		t.Fatalf("fingerprinting added requests: %d", requests)
	}
}

func TestExternalFingerprintInvalidFiles(t *testing.T) {
	for _, content := range []string{
		`{}`, `{`, `{"source":"test","license":"test","apps":{}}`,
		`{"source":"test","license":"test","apps":{}} {}`,
		`{"source":"test","license":"test","apps":{"Example":{"source":"test","headers":{"X-Test":"["}}}}`,
		`{"source":"test","license":"test","apps":{"Example":{"source":"test","scriptSrc":[""]}}}`,
		`{"source":"test","license":"test","apps":{"Example":{"source":"test","js":{"test":""}}}}`,
	} {
		name := filepath.Join(t.TempDir(), "rules.json")
		if err := os.WriteFile(name, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadFingerprintDatabase(name); err == nil {
			t.Fatalf("invalid file accepted: %s", content)
		}
	}
}

func TestExternalDatabase(t *testing.T) {
	filename := os.Getenv("PHP2SHELL_FINGERPRINT_DB")
	if filename == "" {
		t.Skip("set PHP2SHELL_FINGERPRINT_DB to evaluate the downloaded rules")
	}
	db, err := LoadFingerprintDatabase(filename)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, rule := range db.rules {
		seen[rule.technology] = true
	}
	t.Logf("loaded %d passive rules for %d PHP-related technologies", len(db.rules), len(seen))
	cases := []struct{ technology, cookie, header, value, body string }{
		{"Open Journal Systems", "OJSSID=private-value", "", "", ""},
		{"osCommerce", "osCsid=private-value", "", "", ""},
		{"CMS Made Simple", "CMSSESSID=private-value", "", "", ""},
		{"Symfony", "sf_redirect=private-value", "", "", ""},
		{"CakePHP", "", "", "", `<meta name=application-name content=CakePHP>`},
		{"ThinkPHP", "", "X-Powered-By", "ThinkPHP", ""},
		{"Backdrop", "", "X-Backdrop-Cache", "HIT", ""},
		{"Zen Cart", "", "", "", `<meta name=generator content="Zen Cart">`},
		{"e107", "", "", "", `<script src="/e107.js"></script>`},
	}
	for _, c := range cases {
		t.Run(c.technology, func(t *testing.T) {
			headers := map[string][]string{}
			if c.cookie != "" {
				headers["Set-Cookie"] = []string{c.cookie}
			}
			if c.header != "" {
				headers[c.header] = []string{c.value}
			}
			got := db.Match(response("/", headers), c.body)
			if !slices.ContainsFunc(got, func(f Fingerprint) bool { return f.Technology == c.technology }) {
				t.Fatalf("expected %s: %+v", c.technology, got)
			}
		})
	}
	matched := 0
	for _, fixture := range applicationFixtures(t) {
		resp := response("/", fixture.Headers)
		resp.StatusCode = fixture.Status
		got := db.Match(resp, fixture.Body)
		if slices.ContainsFunc(got, func(f Fingerprint) bool { return strings.EqualFold(f.Technology, fixture.Technology) }) {
			matched++
		}
	}
	t.Logf("external rules identify %d of %d existing synthetic application fixtures; built-in rules remain enabled", matched, len(applicationFixtures(t)))
}
