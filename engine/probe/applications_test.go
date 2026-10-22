package probe

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/pawal/php2shell/engine/verdict"
)

type applicationFixture struct {
	Technology string              `json:"technology"`
	Status     int                 `json:"status"`
	Headers    map[string][]string `json:"headers"`
	Body       string              `json:"body"`
}

func applicationFixtures(t *testing.T) []applicationFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/applications.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []applicationFixture
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures
}

func TestAdditionalApplicationFingerprints(t *testing.T) {
	fixtures := applicationFixtures(t)
	if len(fixtures) != 50 {
		t.Fatalf("expected fifty additional application fixtures, got %d", len(fixtures))
	}
	for _, fixture := range fixtures {
		t.Run(fixture.Technology, func(t *testing.T) {
			resp := response("/", fixture.Headers)
			resp.StatusCode = fixture.Status
			matches := applicationFingerprints(resp, fixture.Body)
			if len(matches) != 1 || matches[0].Technology != fixture.Technology {
				t.Fatalf("%+v", matches)
			}
			if matches[0].Source == "" || matches[0].Confidence == "" {
				t.Fatal("missing provenance")
			}
			if strings.Contains(fmt.Sprint(matches), "/private/source.php") || strings.Contains(fmt.Sprint(matches), "sample-secret-123") {
				t.Fatal("response contents leaked into evidence")
			}
			hints := applicationHints(resp, fixture.Body)
			result := verdict.Judge(verdict.Input{Reachable: true, Hints: hints, Oracle: verdict.OracleNotRun})
			if result.Verdict != verdict.Inconclusive || result.Version != nil || !strings.Contains(result.Summary, fixture.Technology) {
				t.Fatalf("%+v", result)
			}
			if fixture.Status >= 500 {
				resp.StatusCode = 200
				if got := applicationFingerprints(resp, fixture.Body); len(got) != 0 {
					t.Fatalf("diagnostic quoted on an ordinary page: %+v", got)
				}
			}
		})
	}
}

func TestApplicationCatalogueCoverage(t *testing.T) {
	seen := map[string]bool{}
	for _, name := range generatorApps {
		seen[strings.ToLower(name)] = true
	}
	expected := map[string]bool{"Roundcube": true}
	for _, fixture := range applicationFixtures(t) {
		expected[fixture.Technology] = true
	}
	if len(expected) != 51 || len(applicationCatalogue) != len(expected) {
		t.Fatalf("catalogue and fixture coverage differ: %d versus %d", len(applicationCatalogue), len(expected))
	}
	source := func(value string) {
		t.Helper()
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			t.Fatalf("invalid source %q", value)
		}
	}
	for _, spec := range applicationCatalogue {
		name := strings.ToLower(spec.Technology)
		if seen[name] || !expected[spec.Technology] {
			t.Fatalf("duplicate or undocumented application %s", spec.Technology)
		}
		seen[name] = true
		delete(expected, spec.Technology)
		source(spec.Source)
		for _, reference := range spec.References {
			source(reference)
		}
		if len(spec.Aliases) == 0 || spec.Confidence != "medium" || (!spec.EmitsGenerator && len(spec.Diagnostics)+len(spec.Cookies)+len(spec.Assets)+len(spec.Markup) == 0) {
			t.Fatalf("entry lacks a researched signal: %+v", spec)
		}
		for _, cookie := range spec.Cookies {
			source(cookie.Source)
			if cookie.Confidence != "low" || (cookie.Name == "" && cookie.Pattern == "") || cookie.Pattern != "" && (!strings.HasPrefix(cookie.Pattern, "^") || !strings.HasSuffix(cookie.Pattern, "$")) {
				t.Fatalf("unsafe cookie rule %+v", cookie)
			}
		}
		for _, asset := range spec.Assets {
			source(asset.Source)
			if asset.Confidence != "low" || len(asset.Names) == 0 || asset.Tag != "" && asset.Tag != "link" {
				t.Fatalf("invalid asset rule %+v", asset)
			}
		}
		for _, markup := range spec.Markup {
			for _, element := range markup.Elements {
				if element.Tag == "" || len(element.Attributes) == 0 {
					t.Fatalf("unconstrained markup element %+v", element)
				}
			}
			source(markup.Source)
			if markup.Confidence != "low" || len(markup.Elements) == 0 {
				t.Fatalf("invalid markup rule %+v", markup)
			}
		}
	}
}

func TestApplicationMarkupAndCookieFalsePositives(t *testing.T) {
	cases := []struct{ name, body, cookie string }{
		{"product mentions", `<p>We compare phpMyAdmin, XenForo, GLPI, BookStack, Matomo and Moodle.</p>`, ""},
		{"cookie lookalikes", "", "OSTSESSID_fake=x; KB_SID_fake=y; MoodleSessionFake=z; bookstack_session_fake=x"},
		{"generic cookies", "", "PHPSESSID=x; session=y; filemanager=z; XSRF-TOKEN=a; _csrf=b"},
		{"wrong dolibarr hash", "", "DOLSESSID_not_a_hash=x"},
		{"unrelated script names", `<script src="/js/general.js"></script><script src="/js/viewer.js"></script><link rel="stylesheet" href="/css/default.css">`, ""},
		{"asset names in prose", `<p>js/zp_general.js css/shaarli.min.css css/bbpress.css</p>`, ""},
		{"assets in comments", `<!-- <link rel="stylesheet" href="css/bbpress.css"> -->`, ""},
		{"stylesheet rel required", `<link rel="alternate" href="css/shaarli.min.css">`, ""},
		{"separate glpi attributes", `<html data-glpi-theme="light"><body data-glpi-request-id="a">`, ""},
		{"separate login forms", `<form><input name="fm_usr"></form><form><input type="password" name="fm_pwd"></form>`, ""},
		{"freescout article link", `<article><a href="https://freescout.net">FreeScout</a></article><div class="footer">Copyright</div>`, ""},
		{"owncloud article link", `<article><a href="https://owncloud.com">ownCloud</a></article><footer role="contentinfo"><p class="info">Copyright</p></footer>`, ""},
		{"fake footer in comment", `<!-- <div class="footer"><a href="https://freescout.net">FreeScout</a></div> -->`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			headers := map[string][]string{}
			if c.cookie != "" {
				for _, part := range strings.Split(c.cookie, "; ") {
					headers["Set-Cookie"] = append(headers["Set-Cookie"], part)
				}
			}
			if got := applicationFingerprints(response("/", headers), c.body); len(got) != 0 {
				t.Fatalf("%+v", got)
			}
		})
	}
}

func TestGLPICheckRecordsEvidenceWithoutExtraRequests(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		fmt.Fprint(w, `<html data-glpi-theme="light" data-glpi-request-id="private-request-id"><body>Login</body></html>`)
	}))
	defer srv.Close()
	in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL, false)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 1 || verdict.Judge(in).Verdict != verdict.Inconclusive || len(evidence.Passive.Fingerprints) != 1 || evidence.Passive.Fingerprints[0].Technology != "GLPI" {
		t.Fatalf("%d %+v %+v", requests, in, evidence)
	}
	if strings.Contains(fmt.Sprint(evidence.Passive.Fingerprints), "private-request-id") {
		t.Fatal("request ID leaked")
	}
}
