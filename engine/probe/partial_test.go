package probe

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pawal/php2shell/engine/verdict"
)

// breakOff promises more body than it sends, so the read ends in an error.
func breakOff(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Length", strconv.Itoa(len(body)+100))
	fmt.Fprint(w, body)
}

// A linked page whose body breaks off still counts with its headers.
func TestPartialLinkedPageKeepsItsVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old.php" {
			w.Header().Set("X-Powered-By", "PHP/8.5.11")
			breakOff(w, "<p>old</p>")
			return
		}
		w.Header().Set("X-Powered-By", "PHP/8.5.12")
		fmt.Fprint(w, `<a href="/old.php">old</a>`)
	}))
	defer srv.Close()
	in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL, false)
	if err != nil {
		t.Fatal(err)
	}
	page := evidence.Pages[0]
	if page.Error != "" || page.ReadError == "" || !page.BodyIncomplete {
		t.Errorf("partial page recorded as failed: %+v", page)
	}
	if got := verdict.Judge(in); got.Verdict != verdict.LikelyVulnerable || got.Version.String() != "8.5.11" {
		t.Errorf("older version dropped: %+v", got)
	}
}

// A start page that breaks off keeps the headers and text it delivered.
func TestPartialStartPageIsNotUnreachable(t *testing.T) {
	for _, c := range []struct{ name, poweredBy, body, want string }{
		{"no body byte", "PHP/8.5.11", "", "8.5.11"},
		{"signature before the break", "", "<hr><address>Apache/2.4.62 (Debian) PHP/8.4.26 Server at example.com Port 80</address>", "8.4.26"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Powered-By", c.poweredBy)
			breakOff(w, c.body)
		}))
		in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL, false)
		srv.Close()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := verdict.Judge(in)
		if !in.Reachable || evidence.Passive.ReadError == "" || got.Verdict != verdict.LikelyVulnerable || got.Version.String() != c.want {
			t.Errorf("%s: %+v %+v", c.name, got, evidence.Passive)
		}
	}
}

// A challenge stops session requests even when its body breaks off.
func TestTruncatedChallengeStopsSessionRequests(t *testing.T) {
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.5.11")
		if r.Method == http.MethodPost {
			posts.Add(1)
			w.Header().Set("Cf-Mitigated", "challenge")
			breakOff(w, "<title>Just a moment...</title>")
		}
	}))
	defer srv.Close()
	_, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	if posts.Load() != 1 || len(evidence.Requests) != 1 || !strings.Contains(evidence.Requests[0].Blocked, "Cloudflare") {
		t.Errorf("posts %d, requests %+v", posts.Load(), evidence.Requests)
	}
}
