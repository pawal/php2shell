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
	if len(fixtures) != 59 {
		t.Fatalf("expected 59 additional application fixtures, got %d", len(fixtures))
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
	if len(expected) != 60 || len(applicationCatalogue) != len(expected) {
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
		for _, header := range spec.Headers {
			source(header.Source)
			if header.Name == "" || header.Confidence != "medium" || header.Scope == "" || !strings.HasPrefix(header.Pattern, "^") || !strings.HasSuffix(header.Pattern, "$") {
				t.Fatalf("unsafe header rule %+v", header)
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

func TestExtendedApplicationSignals(t *testing.T) {
	cases := []struct{ name, cookie, body, want string }{
		{"bludit https", "__Secure-BLUDIT-KEY=sample-secret-123", "", "Bludit"},
		{"processwire https", "wires=sample-secret-123", "", "ProcessWire"},
		{"piwigo without generator", "pwg_id=sample-secret-123", "", "Piwigo"},
		{"custom cookie", "custom_session=x", "", ""},
		{"cookie lookalikes", "wires_extra=x", "", ""},
		{"bludit lookalike", "__Secure-BLUDIT-KEY_extra=x", "", ""},
		{"piwigo lookalike", "pwg_id_extra=x", "", ""},
		{"product mentions", "", "<p>Bludit, ProcessWire and Serendipity</p>", ""},
		{"generator lookalike", "", `<meta name="generator" content="SerendipityClone">`, ""},
		{"commented generator", "", `<!-- <meta name="generator" content="Serendipity"> -->`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := applicationFingerprints(response("/", map[string][]string{"Set-Cookie": {c.cookie}}), c.body)
			if c.want == "" {
				if len(got) != 0 {
					t.Fatalf("unexpected fingerprint: %+v", got)
				}
				return
			}
			if len(got) != 1 || got[0].Technology != c.want || got[0].Confidence != "low" || strings.Contains(fmt.Sprint(got), "sample-secret") {
				t.Fatalf("unexpected evidence: %+v", got)
			}
		})
	}
}

// Session cookies and headers the applications send to anonymous visitors.
func TestApplicationSessionSignals(t *testing.T) {
	cases := []struct {
		name, want string
		headers    map[string][]string
	}{
		{"flarum session", "Flarum", map[string][]string{"Set-Cookie": {"flarum_session=abc; Path=/; HttpOnly"}}},
		{"glpi 10 session", "GLPI", map[string][]string{"Set-Cookie": {"glpi_" + strings.Repeat("a1", 16) + "=abc; Path=/"}}},
		{"glpi 11 session", "GLPI", map[string][]string{"Set-Cookie": {"glpi_" + strings.Repeat("0f", 64) + "=abc; Path=/"}}},
		{"glpi lookalike", "", map[string][]string{"Set-Cookie": {"glpi_" + strings.Repeat("a", 40) + "=abc; Path=/"}}},
		{"chamilo session", "Chamilo", map[string][]string{"Set-Cookie": {"ch_sid=abc; Path=/"}}},
		{"limesurvey session", "LimeSurvey", map[string][]string{"Set-Cookie": {"LS-HIQBFUVHDRJIFHMG=abc; Path=/"}}},
		{"limesurvey lookalike", "", map[string][]string{"Set-Cookie": {"LS-hiqbfuvhdrjifhmg=abc; Path=/"}}},
		{"matomo request id", "Matomo", map[string][]string{"X-Matomo-Request-Id": {"3fa9c"}}},
		{"matomo lookalike", "", map[string][]string{"X-Matomo-Request-Id": {"not-an-id"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matches := applicationFingerprints(response("/", c.headers), "")
			if c.want == "" {
				if len(matches) != 0 {
					t.Fatalf("%+v", matches)
				}
				return
			}
			if len(matches) != 1 || matches[0].Technology != c.want || matches[0].Source == "" {
				t.Fatalf("%+v", matches)
			}
		})
	}
}
