package probe

import (
	"net/http"
	"net/url"
	"slices"
	"testing"
)

func response(path string, headers map[string][]string) *http.Response {
	return &http.Response{Header: http.Header(headers), Request: &http.Request{URL: &url.URL{Path: path}}}
}

func TestApplicationHints(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		headers map[string][]string
		body    string
		want    []string
	}{
		{"nothing", "/", nil, "<html><body>hello</body></html>", nil},
		{"php header", "/", map[string][]string{"X-Powered-By": {"PHP/8.5.11"}}, "", []string{"PHP header"}},
		{"php final url", "/index.php", nil, "", []string{".php final URL"}},
		{"wp engine behind a cache", "/",
			map[string][]string{"Server": {"nginx"}, "X-Powered-By": {"WP Engine"},
				"Link": {`<https://example.com/wp-json/>; rel="https://api.w.org/"`}},
			`<link href="https://example.com/wp-content/themes/x/style.css"><script src="/wp-includes/js/jquery.js"></script>`,
			[]string{"PHP host header", "WordPress REST API link", "WordPress assets"}},
		{"elementor generator", "/", nil,
			`<meta name="generator" content="Elementor 4.2.3; features: x">`, []string{"generator Elementor"}},
		{"drupal", "/", map[string][]string{"Set-Cookie": {"SESSd41d8cd98f00b204e9800998ecf8427e=abc; Path=/"}},
			`<script src="/sites/default/files/js/x.js"></script><meta name="Generator" content="Drupal 11 (https://www.drupal.org)">`,
			[]string{"Drupal cookie", "Drupal assets", "generator Drupal"}},
		{"laravel cookie", "/", map[string][]string{"Set-Cookie": {"laravel_session=x; Path=/", "XSRF-TOKEN=y"}}, "", []string{"Laravel cookie"}},
		{"vbulletin generator", "/", nil, `<meta name="generator" content="vBulletin 4.2.5">`, []string{"generator vBulletin"}},
		{"vbulletin assets", "/", nil, `<script src="/clientscript/vbulletin-core.js?v=425"></script><script src="/clientscript/vbulletin_global.js"></script>`, []string{"vBulletin assets"}},
		{"vbulletin cookie", "/", map[string][]string{"Set-Cookie": {"bb_sessionhash=abc; Path=/; HttpOnly"}}, "", []string{"vBulletin cookie"}},
		{"mention is not detection", "/", nil, `<p>We used to run vBulletin.</p>`, nil},
		{"unknown generator", "/", nil, `<meta name="generator" content="Hugo 0.150">`, nil},
		{"duplicates collapse", "/", map[string][]string{"X-Powered-By": {"PHP/8.3.6"}, "Server": {"Apache PHP/8.3.6"}},
			`/wp-content/a /wp-content/b /wp-includes/c`, []string{"PHP header", "WordPress assets"}},
	}
	for _, c := range cases {
		got := applicationHints(response(c.path, c.headers), c.body)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
