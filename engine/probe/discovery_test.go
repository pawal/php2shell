package probe

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pawal/php2shell/engine/verdict"
)

func TestDiscoveredPaths(t *testing.T) {
	body := `<!-- <a href="comment.php"> -->
 <script>var fake = '<a href="script.php">';</script>
 <a href="https://other.example/external.php">external</a>
 <a href="http://example.com/plain.php">downgrade</a>
 <a href="//example.com:444/port.php">port</a>
 <a href="https://user@example.com/user.php">userinfo</a>
 <a href="/logout.php">logout</a><a href="/delete.php">delete</a>
 <a href="/index.php?action=remove">query</a>
 <a href="/query.php?">empty query</a>
 <a href="javascript:bad.php">script</a>
 <a href="/docs/info.html">html</a>
 <a class='nav' HREF=forum.php#top>forum</a>
 <a href="forum.php#other">duplicate</a>
 <form data-note="x > y" action='log&#105;n.phtml' method="post"></form>
 <a href="third.php">over cap</a>`
	got := discoveredPaths("https://example.com/community/", body)
	want := []string{"https://example.com/community/forum.php", "https://example.com/community/login.phtml"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestDiscoveryFindsVersionAndDoesNotRecurse(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<a href="/forum.php">Forum</a><form action="/login.php"></form><a href="/third.php">more</a>`)
		case "/forum.php":
			w.Header().Set("X-Powered-By", "PHP/8.5.12")
			fmt.Fprint(w, `<a href="/recursive.php">more</a>`)
		}
	}))
	defer srv.Close()
	in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := verdict.Judge(in).Verdict; got != verdict.LikelyPatched {
		t.Fatal(got)
	}
	if len(evidence.Pages) != 2 || strings.Join(paths, ",") != "GET /,GET /forum.php,GET /login.php" {
		t.Fatalf("%+v %v", evidence.Pages, paths)
	}
}

func TestDiscoveryDoesNotFollowRedirectsOrInferPHPFrom404(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<a href="/redirect.php">a</a><a href="/missing.php">b</a>`)
		case "/redirect.php":
			http.Redirect(w, r, "http://127.0.0.1:1/private.php", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL, false)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 3 || evidence.Pages[0].Stopped == "" || verdict.Judge(in).Verdict != verdict.Inconclusive {
		t.Fatalf("%d %+v %+v", requests, evidence, in)
	}
}

func TestDiscoveredPathUsedByAttestedOracle(t *testing.T) {
	var posts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if r.URL.Path == "/" {
				fmt.Fprint(w, `<form action="/community/login.php"></form>`)
			}
			return
		}
		posts = append(posts, r.URL.Path)
		if r.URL.Path == "/community/login.php" {
			fmt.Fprint(w, readWarnings)
		}
	}))
	defer srv.Close()
	in, _, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	if in.Oracle != verdict.OraclePatched || strings.Join(posts, ",") != "/,/index.php,/community/login.php" {
		t.Fatalf("%+v %v", in, posts)
	}
}

func TestDiscoveryTimeoutPreservesInitialEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("X-Powered-By", "PHP/8.5.12")
			fmt.Fprint(w, `<a href="/slow.php">slow</a>`)
			return
		}
		<-r.Context().Done()
	}))
	defer srv.Close()
	in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true, RequestTimeout: 20 * time.Millisecond}, srv.URL, false)
	if err != nil || len(evidence.Pages) != 1 || evidence.Pages[0].Error == "" || verdict.Judge(in).Verdict != verdict.LikelyPatched {
		t.Fatalf("%+v %+v %v", in, evidence, err)
	}
}

func TestRedirectCookieIsRetained(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "not-forwarded"})
			http.Redirect(w, r, "/home", http.StatusFound)
			return
		}
		if r.Header.Get("Cookie") != "" {
			t.Error("discovery must not establish a session")
		}
	}))
	defer srv.Close()
	in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL, false)
	if err != nil || !slices.Contains(in.Hints, "PHPSESSID cookie") || !slices.Contains(evidence.Passive.Cookies, "PHPSESSID") {
		t.Fatalf("%+v %+v %v", in, evidence, err)
	}
}

func TestDiscoveryHonorsParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := (&Prober{AllowNonGlobal: true}).newSession()
	defer s.close()
	if got := s.discover(ctx, Passive{Paths: []string{"http://127.0.0.1/a.php"}}); len(got) != 0 {
		t.Fatal(got)
	}
}
