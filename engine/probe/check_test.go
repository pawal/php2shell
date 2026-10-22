package probe

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pawal/php2shell/engine/verdict"
)

const readWarnings = "Session ID is too long or contains illegal characters. Failed to read session data"

func checkURL(t *testing.T, p *Prober, address string, oracle bool) (verdict.Input, Evidence, error) {
	t.Helper()
	target, err := ParseTarget(address)
	if err != nil {
		t.Fatal(err)
	}
	in, raw, err := p.Check(context.Background(), target, oracle)
	return in, raw.(Evidence), err
}

func TestCheckVerdicts(t *testing.T) {
	cases := []struct {
		name, poweredBy, server, warnings, cookie, want string
		oracle                                          bool
	}{
		{name: "unpatched", warnings: readWarnings + " Failed to write session data", want: verdict.Vulnerable, oracle: true},
		{name: "patched backport", poweredBy: "PHP/8.3.6", warnings: readWarnings, want: verdict.Patched, oracle: true},
		{name: "affected header", poweredBy: "PHP/8.5.11", want: verdict.LikelyVulnerable},
		{name: "fixed server header", server: "Apache PHP/8.5.12", want: verdict.LikelyPatched},
		{name: "backported", poweredBy: "PHP/8.3.6-0ubuntu0.24.04.13", want: verdict.PossiblyBackported, oracle: true},
		{name: "eol", poweredBy: "PHP/8.1.2", want: verdict.EOLBranch},
		{name: "cookie hint", cookie: "PHPSESSID=example", want: verdict.Inconclusive, oracle: true},
		{name: "silent", want: verdict.NoPHPSignal, oracle: true},
		{name: "write alone insufficient", warnings: "Failed to write session data", want: verdict.NoPHPSignal, oracle: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var gets, posts atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.UserAgent() != DefaultUserAgent {
					t.Errorf("user agent %q", r.UserAgent())
				}
				w.Header().Set("X-Powered-By", c.poweredBy)
				w.Header().Set("Server", c.server)
				if c.cookie != "" {
					w.Header().Add("Set-Cookie", c.cookie)
				}
				if r.Method == http.MethodGet {
					gets.Add(1)
					return
				}
				posts.Add(1)
				if r.Header.Get("Cookie") != "PHPSESSID=_" {
					t.Errorf("unexpected session cookie")
				}
				if err := r.ParseMultipartForm(2048); err != nil {
					t.Error(err)
					return
				}
				defer r.MultipartForm.RemoveAll()
				if r.FormValue("PHP_SESSION_UPLOAD_PROGRESS") != "probe" {
					t.Error("missing progress field")
				}
				file, header, err := r.FormFile("f")
				if err != nil {
					t.Error(err)
					return
				}
				file.Close()
				if header.Size != 1 {
					t.Errorf("file size %d", header.Size)
				}
				fmt.Fprint(w, c.warnings)
			}))
			defer srv.Close()
			in, _, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL, c.oracle)
			if err != nil {
				t.Fatal(err)
			}
			if got := verdict.Judge(in).Verdict; got != c.want {
				t.Errorf("got %s, want %s", got, c.want)
			}
			wantGets := int32(1)
			if c.oracle && c.poweredBy == "" && c.server == "" {
				wantGets += int32(len(phpinfoPaths))
			}
			if gets.Load() != wantGets {
				t.Errorf("GET count %d, want %d", gets.Load(), wantGets)
			}
			wantPosts := int32(0)
			if c.oracle {
				wantPosts = 2
				if c.warnings == readWarnings || strings.Contains(c.warnings, readWarnings+" Failed to write") {
					wantPosts = 1
				}
			}
			if posts.Load() != wantPosts {
				t.Errorf("POST count %d, want %d", posts.Load(), wantPosts)
			}
			if !c.oracle && in.Oracle != verdict.OracleNotRun {
				t.Errorf("passive oracle %s", in.Oracle)
			}
		})
	}
}

func TestCheckRedirects(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodPost {
			if r.URL.Path == "/home.php" {
				fmt.Fprint(w, readWarnings)
			}
			return
		}
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/home.php", http.StatusFound)
			return
		}
		w.Header().Set("X-Powered-By", "PHP")
	}))
	defer srv.Close()
	in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	if in.Oracle != verdict.OraclePatched || evidence.Passive.FinalURL != srv.URL+"/home.php" || len(evidence.Passive.Redirects) != 1 {
		t.Fatalf("%+v %+v", in, evidence)
	}
	if got := strings.Join(paths, ","); got != "GET /,GET /home.php,GET /phpinfo.php,GET /info.php,POST /,POST /index.php,POST /home.php" {
		t.Error(got)
	}
}

func TestCheckRedirectLimitAndOffsite(t *testing.T) {
	for _, destination := range []string{"/loop", "http://unrelated.example/", "file:///etc/passwd"} {
		t.Run(destination, func(t *testing.T) {
			var count atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count.Add(1)
				http.Redirect(w, r, destination, http.StatusFound)
			}))
			defer srv.Close()
			_, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL, false)
			if err != nil {
				t.Fatal(err)
			}
			want := int32(1)
			if destination == "/loop" {
				want = 4
			}
			if count.Load() != want || evidence.Passive.Stopped == "" {
				t.Fatalf("requests %d, evidence %+v", count.Load(), evidence)
			}
		})
	}
}

func TestCheckPinnedHostAndRedirectPolicy(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if !strings.HasPrefix(r.Host, "site.example:") {
			t.Errorf("Host %q", r.Host)
		}
		http.Redirect(w, r, "http://child.site.example:1234/", http.StatusFound)
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	resolver := &fakeResolver{answers: map[string][]string{"site.example": {"127.0.0.1"}, "child.site.example": {"127.0.0.1"}}}
	p := &Prober{AllowNonGlobal: true, Resolver: resolver}
	_, _, err := checkURL(t, p, "http://site.example:"+port, false)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || resolver.calls.Load() != 2 {
		t.Errorf("requests %d, resolutions %d", calls.Load(), resolver.calls.Load())
	}
}

func TestCheckBodyBoundAndTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			fmt.Fprint(w, strings.Repeat("x", 128)+readWarnings)
		}
	}))
	defer srv.Close()
	in, _, err := checkURL(t, &Prober{AllowNonGlobal: true, MaxBody: 64}, srv.URL, true)
	if err != nil || in.Oracle != verdict.OracleSilent {
		t.Fatalf("%+v %v", in, err)
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer slow.Close()
	in, _, err = checkURL(t, &Prober{AllowNonGlobal: true, RequestTimeout: 20 * time.Millisecond}, slow.URL, false)
	if err != nil || verdict.Judge(in).Verdict != verdict.Unreachable {
		t.Fatalf("%+v %v", in, err)
	}
}

func TestRedirectRevalidatesAddressAndPort(t *testing.T) {
	for _, destination := range []string{"http://child.site.example/", "http://site.example:22/"} {
		t.Run(destination, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				http.Redirect(w, r, destination, http.StatusFound)
			}))
			defer srv.Close()
			resolver := &fakeResolver{answers: map[string][]string{"child.site.example": {"127.0.0.1"}}}
			s := (&Prober{Resolver: resolver}).newSession()
			defer s.close()
			// Route the initial request locally to isolate the redirect policy.
			s.transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
			}
			_, err := s.fetch(context.Background(), Target{Scheme: "http", Host: "site.example", Port: "80", Path: "/"})
			var policy *PolicyError
			if !errors.As(err, &policy) || calls.Load() != 1 {
				t.Fatalf("requests %d, error %v", calls.Load(), err)
			}
		})
	}
}

func TestPinnedTLSHostAndSNI(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.ServerName != "example.com" {
			t.Errorf("SNI %q", r.TLS.ServerName)
		}
		if !strings.HasPrefix(r.Host, "example.com:") {
			t.Errorf("Host %q", r.Host)
		}
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/end", http.StatusFound)
		}
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	resolver := &fakeResolver{answers: map[string][]string{"example.com": {"127.0.0.1"}}}
	s := (&Prober{AllowNonGlobal: true, Resolver: resolver}).newSession()
	defer s.close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	s.transport.TLSClientConfig.RootCAs = roots
	out, err := s.fetch(context.Background(), Target{Scheme: "https", Host: "example.com", Port: port, Path: "/"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != http.StatusOK || resolver.calls.Load() != 1 {
		t.Fatalf("%+v, lookups %d", out, resolver.calls.Load())
	}
}

func TestWordPressLoginFallback(t *testing.T) {
	for _, oracle := range []bool{false, true} {
		t.Run(fmt.Sprint(oracle), func(t *testing.T) {
			var posts []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					fmt.Fprint(w, `<link href="/wp-content/themes/site/style.css">`)
					return
				}
				posts = append(posts, r.URL.Path)
				if r.URL.Path == "/wp-login.php" {
					fmt.Fprint(w, readWarnings+" Failed to write session data")
				}
			}))
			defer srv.Close()
			in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL, oracle)
			if err != nil {
				t.Fatal(err)
			}
			if !oracle {
				if len(posts) != 0 || in.Oracle != verdict.OracleNotRun {
					t.Fatalf("passive check sent posts: %v", posts)
				}
				return
			}
			if got := strings.Join(posts, ","); got != "/,/index.php,/wp-login.php" {
				t.Fatal(got)
			}
			if in.Oracle != verdict.OracleUnpatched || len(evidence.Requests) != 3 {
				t.Fatalf("%+v %+v", in, evidence)
			}
		})
	}
}

func TestWordPressFallbackUsesFinalOrigin(t *testing.T) {
	target := Target{Scheme: "https", Host: "example.com", Port: "443", Path: "/"}
	paths := oraclePaths(target, Passive{FinalURL: "https://www.example.com/home", Hints: []string{"WordPress assets"}})
	if got := paths[len(paths)-1]; got != "https://www.example.com/wp-login.php" {
		t.Fatal(got)
	}
}

func TestVBulletinWithoutVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<meta name="generator" content="vBulletin 4.2.5">`)
	}))
	defer srv.Close()
	in, _, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL, false)
	if err != nil {
		t.Fatal(err)
	}
	result := verdict.Judge(in)
	if result.Verdict != verdict.Inconclusive || result.Version != nil || !strings.Contains(result.Summary, "vBulletin") {
		t.Fatalf("application version must not be treated as PHP version: %+v", result)
	}
}
