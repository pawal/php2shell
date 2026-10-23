package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pawal/php2shell/engine/probe"
	"github.com/pawal/php2shell/engine/verdict"
)

// fakeChecker answers from a function and counts its calls.
type fakeChecker struct {
	calls atomic.Int32
	fn    func(probe.Target, bool) (verdict.Input, any, error)
}

func (f *fakeChecker) Check(_ context.Context, target probe.Target, oracle bool) (verdict.Input, any, error) {
	f.calls.Add(1)
	if f.fn != nil {
		return f.fn(target, oracle)
	}
	in := verdict.Input{Reachable: true, PoweredBy: "PHP/8.5.11", Oracle: verdict.OracleNotRun}
	if oracle {
		in.Oracle = verdict.OracleUnpatched
	}
	return in, map[string]string{"x_powered_by": in.PoweredBy}, nil
}

func newTestServer(t *testing.T, change func(*Config), checker Checker) *Server {
	t.Helper()
	cfg := DefaultConfig()
	cfg.PublicURL = "https://php2shell.example.net"
	cfg.LogFile = filepath.Join(t.TempDir(), "checks.log")
	if change != nil {
		change(&cfg)
	}
	if checker == nil {
		checker = &fakeChecker{}
	}
	s, err := New(cfg, "v1.2.3", checker, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.scanlog.close() })
	return s
}

func post(t *testing.T, h http.Handler, body string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func errorCodeOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var env errorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("not an error envelope: %s", rec.Body.String())
	}
	return env.Error.Code
}

// Every route carries the header table of the plan.
func TestSecurityHeadersOnEveryRoute(t *testing.T) {
	h := newTestServer(t, nil, nil).Handler()
	paths := []string{"/", "/about", "/static/styles.css", "/robots.txt", "/sitemap.xml", "/healthz",
		"/api/v1/version", "/api/v1/info", "/api/v1/nope", "/nope"}
	for _, path := range paths {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		want := map[string]string{
			"X-Content-Type-Options":       "nosniff",
			"X-Frame-Options":              "DENY",
			"Referrer-Policy":              "no-referrer",
			"Cross-Origin-Opener-Policy":   "same-origin",
			"Cross-Origin-Resource-Policy": "same-origin",
			"Permissions-Policy":           permissionsPolicy,
			"Content-Security-Policy":      policyFor(path),
		}
		for name, value := range want {
			if got := rec.Header().Get(name); got != value {
				t.Errorf("%s: %s is %q, want %q", path, name, got, value)
			}
		}
		cache := rec.Header().Get("Cache-Control")
		switch {
		case strings.HasPrefix(path, "/api/") && cache != "no-store",
			strings.HasPrefix(path, "/static/") && cache != "public, max-age=86400",
			path == "/" && cache != "no-cache":
			t.Errorf("%s: Cache-Control %q", path, cache)
		}
	}
}

func TestDocumentsCarryHeadAndFooter(t *testing.T) {
	h := newTestServer(t, nil, nil).Handler()
	for path, canonical := range map[string]string{"/": "https://php2shell.example.net/", "/about": "https://php2shell.example.net/about"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		body := rec.Body.String()
		for _, want := range []string{
			`<html lang="en">`, `<link rel="canonical" href="` + canonical + `">`,
			`<meta property="og:title"`, `<meta name="description"`,
			`<meta property="og:image" content="https://php2shell.example.net/static/og.png">`,
			`<meta name="twitter:card" content="summary_large_image">`,
			`This service is provided by <a href="https://evilbit.de/">evilbit.de</a>.`, "v1.2.3",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s lacks %s", path, want)
			}
		}
		if strings.Count(body, "<h1>") != 1 {
			t.Errorf("%s has %d h1 elements", path, strings.Count(body, "<h1>"))
		}
		if strings.Contains(body, "style=") || strings.Contains(body, "<script>") {
			t.Errorf("%s carries an inline style or script", path)
		}
	}
}

// The start page alone describes the service as JSON-LD, and only with a public_url.
func TestStructuredData(t *testing.T) {
	const open, end = `<script type="application/ld+json">`, "</script>"
	h := newTestServer(t, nil, nil).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	body := rec.Body.String()
	start := strings.Index(body, open)
	if start < 0 {
		t.Fatal("the start page carries no JSON-LD")
	}
	text, _, _ := strings.Cut(body[start+len(open):], end)
	var data struct {
		Graph []struct {
			Type string `json:"@type"`
			URL  string `json:"url"`
		} `json:"@graph"`
	}
	if err := json.Unmarshal([]byte(text), &data); err != nil {
		t.Fatalf("JSON-LD: %v: %s", err, text)
	}
	if len(data.Graph) != 2 || data.Graph[1].Type != "WebApplication" || data.Graph[1].URL != "https://php2shell.example.net/" {
		t.Errorf("JSON-LD: %s", text)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/about", nil))
	if strings.Contains(rec.Body.String(), open) {
		t.Error("/about carries JSON-LD")
	}
	bare := newTestServer(t, func(c *Config) { c.PublicURL = "" }, nil).Handler()
	rec = httptest.NewRecorder()
	bare.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if body := rec.Body.String(); strings.Contains(body, open) || strings.Contains(body, "og:image") {
		t.Error("the start page without public_url carries JSON-LD or a share image")
	}
}

func TestRobotsAndSitemap(t *testing.T) {
	h := newTestServer(t, nil, nil).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/robots.txt", nil))
	if !strings.Contains(rec.Body.String(), "Disallow: /api/") || !strings.Contains(rec.Body.String(), "Sitemap: https://php2shell.example.net/sitemap.xml") {
		t.Errorf("robots.txt: %s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sitemap.xml", nil))
	if !strings.Contains(rec.Body.String(), "<loc>https://php2shell.example.net/about</loc>") {
		t.Errorf("sitemap.xml: %s", rec.Body.String())
	}

	bare := newTestServer(t, func(c *Config) { c.PublicURL = "" }, nil).Handler()
	rec = httptest.NewRecorder()
	bare.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sitemap.xml", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("sitemap without public_url: %d", rec.Code)
	}
}

func TestCheck(t *testing.T) {
	s := newTestServer(t, nil, nil)
	rec := post(t, s.Handler(), `{"url":"example.com","attested":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var report Report
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Verdict != verdict.Vulnerable || !report.OracleRun || report.Cached || report.Target != "https://example.com/" {
		t.Errorf("report: %+v", report)
	}
}

func TestCheckRefusals(t *testing.T) {
	policy := &fakeChecker{fn: func(probe.Target, bool) (verdict.Input, any, error) {
		return verdict.Input{}, nil, &probe.PolicyError{Host: "internal.example.com", Reason: "10.0.0.1 is private use"}
	}}
	cases := []struct {
		name    string
		checker Checker
		body    string
		headers []string
		status  int
		code    string
	}{
		{"bad json", nil, `{"url":`, nil, 400, codeInvalidRequest},
		{"unknown field", nil, `{"url":"example.com","x":1}`, nil, 400, codeInvalidRequest},
		{"bad target", nil, `{"url":"localhost"}`, nil, 400, codeInvalidTarget},
		{"non-global", policy, `{"url":"internal.example.com"}`, nil, 400, codeNonGlobalAddress},
		{"foreign origin", nil, `{"url":"example.com"}`, []string{"Origin", "https://evil.example"}, 403, codeCSRFOrigin},
		{"too large", nil, `{"url":"` + strings.Repeat("a", 5000) + `"}`, nil, 413, codeRequestTooLarge},
	}
	for _, c := range cases {
		rec := post(t, newTestServer(t, nil, c.checker).Handler(), c.body, c.headers...)
		if rec.Code != c.status || errorCodeOf(t, rec) != c.code {
			t.Errorf("%s: got %d %s, want %d %s", c.name, rec.Code, rec.Body.String(), c.status, c.code)
		}
	}
}

func TestRateLimit(t *testing.T) {
	h := newTestServer(t, func(c *Config) { c.RateLimit.Max = 2 }, nil).Handler()
	for i := range 3 {
		rec := post(t, h, `{"url":"example.com"}`)
		if i < 2 && rec.Code != http.StatusOK {
			t.Fatalf("check %d: %d", i, rec.Code)
		}
		if i == 2 && (rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "") {
			t.Errorf("third check: %d, Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
		}
	}
}

// A repeated check inside the cooldown is answered from the cache, and a
// passive result does not answer a request for the oracle.
func TestCooldown(t *testing.T) {
	checker := &fakeChecker{}
	h := newTestServer(t, nil, checker).Handler()
	post(t, h, `{"url":"example.com"}`)
	rec := post(t, h, `{"url":"https://example.com/other"}`)
	var report Report
	_ = json.Unmarshal(rec.Body.Bytes(), &report)
	if !report.Cached || checker.calls.Load() != 1 {
		t.Errorf("second passive check: cached %v after %d calls", report.Cached, checker.calls.Load())
	}
	post(t, h, `{"url":"example.com","attested":true}`)
	post(t, h, `{"url":"example.com","attested":true}`)
	post(t, h, `{"url":"example.com"}`)
	if checker.calls.Load() != 2 {
		t.Errorf("the oracle ran %d times in all, want one passive and one oracle", checker.calls.Load())
	}
}

func TestBusy(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	checker := &fakeChecker{fn: func(probe.Target, bool) (verdict.Input, any, error) {
		started <- struct{}{}
		<-release
		return verdict.Input{Reachable: true}, nil, nil
	}}
	h := newTestServer(t, func(c *Config) { c.MaxConcurrentChecks = 1 }, checker).Handler()
	done := make(chan struct{})
	go func() { post(t, h, `{"url":"one.example.com"}`); close(done) }()
	<-started
	rec := post(t, h, `{"url":"two.example.com"}`)
	close(release)
	<-done
	if rec.Code != http.StatusServiceUnavailable || errorCodeOf(t, rec) != codeBusy {
		t.Errorf("second concurrent check: %d %s", rec.Code, rec.Body.String())
	}
}

// The log holds the target and the verdict, never the client.
func TestScanLog(t *testing.T) {
	s := newTestServer(t, func(c *Config) { c.TrustedProxyCIDRs = []string{"192.0.2.0/24"} }, nil)
	h := s.Handler()
	post(t, h, `{"url":"example.com","attested":true}`, "X-Forwarded-For", "203.0.113.77")
	data, err := os.ReadFile(s.cfg.LogFile)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(data))
	fields := strings.Fields(line)
	if len(fields) != 4 || fields[1] != "example.com" || fields[2] != verdict.Vulnerable || fields[3] != "oracle" {
		t.Errorf("log line %q", line)
	}
	if _, err := time.Parse(time.RFC3339, fields[0]); err != nil {
		t.Errorf("log time %q: %v", fields[0], err)
	}
	if strings.Contains(line, "203.0.113.77") || strings.Contains(line, "192.0.2.1") {
		t.Errorf("the log records a client address: %q", line)
	}
}

func TestFailureLabel(t *testing.T) {
	if got := failureLabel(&probe.PolicyError{Host: "h", Reason: "r"}); got != "refused:"+codeNonGlobalAddress {
		t.Errorf("policy: %s", got)
	}
	if got := failureLabel(io.ErrUnexpectedEOF); got != "error:"+codeCheckFailed {
		t.Errorf("failure: %s", got)
	}
}

func TestInfoReportsTheLabSwitch(t *testing.T) {
	h := newTestServer(t, func(c *Config) { c.AllowNonGlobalAddresses = true }, nil).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/info", nil))
	if !strings.Contains(rec.Body.String(), `"allow_non_global_addresses":true`) {
		t.Errorf("info: %s", rec.Body.String())
	}
}

func TestInspectionBlockedReport(t *testing.T) {
	checker := &fakeChecker{fn: func(probe.Target, bool) (verdict.Input, any, error) {
		return verdict.Input{Reachable: true, InspectionBlocked: "Cloudflare challenge", Oracle: verdict.OracleNotRun}, map[string]string{"inspection_blocked": "Cloudflare challenge"}, nil
	}}
	h := newTestServer(t, nil, checker).Handler()
	rec := post(t, h, `{"url":"example.com","attested":true}`)
	var report Report
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || report.Verdict != verdict.InspectionBlocked || report.OracleRun || len(report.Recommendations) == 0 {
		t.Fatalf("%d %+v", rec.Code, report)
	}
}

func TestLocalCheckFollowsServerHeader(t *testing.T) {
	freebsd := strings.Join(LocalCheck(verdict.Input{Server: "Apache/2.4.69 (FreeBSD) OpenSSL/3.5.6 PHP/8.5.12"}), "\n")
	if !strings.Contains(freebsd, "pkg info") || strings.Contains(freebsd, "dpkg") {
		t.Errorf("freebsd: %s", freebsd)
	}
	other := strings.Join(LocalCheck(verdict.Input{Server: "Apache/2.4.66 (Debian)"}), "\n")
	if !strings.Contains(other, "dpkg") || strings.Contains(other, "pkg info") {
		t.Errorf("debian: %s", other)
	}
	for name, text := range map[string]string{"freebsd": freebsd, "debian": other} {
		if !strings.Contains(text, `phpversion("session")`) {
			t.Errorf("%s lacks the session extension version: %s", name, text)
		}
	}
}

func TestAboutListsSourceAddresses(t *testing.T) {
	about := func(addresses []string) string {
		h := newTestServer(t, func(c *Config) { c.SourceAddresses = addresses }, nil).Handler()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/about", nil))
		return rec.Body.String()
	}
	listed := about([]string{"192.0.2.10", "2001:db8::10"})
	if !strings.Contains(listed, "They come from <code>192.0.2.10</code> and <code>2001:db8::10</code>.") || !strings.Contains(listed, "allow these addresses") {
		t.Errorf("addresses missing from the about page")
	}
	if plain := about(nil); strings.Contains(plain, "They come from") || !strings.Contains(plain, "allow this User-Agent") {
		t.Errorf("the about page without addresses is wrong")
	}
}
