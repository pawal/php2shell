package probe

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/pawal/php2shell/engine/verdict"
)

// Real PHP behaviour is checked by make test-session-variants. This verifies
// the production request through a frontend, including its streaming order.
func TestCheckSessionThroughProxy(t *testing.T) {
	for _, strip := range []bool{false, true} {
		for _, attested := range []bool{false, true} {
			for _, older := range []bool{false, true} {
				t.Run(fmt.Sprintf("strip=%t/attested=%t/older=%t", strip, attested, older), func(t *testing.T) {
					var posts atomic.Int32
					backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.Method != http.MethodPost {
							return
						}
						posts.Add(1)
						if r.ContentLength <= 0 || r.ContentLength > 1024 {
							t.Errorf("unexpected request size: %d", r.ContentLength)
						}
						cookie, err := r.Cookie("PHPSESSID")
						if strip && err != http.ErrNoCookie || !strip && (err != nil || cookie.Value != "_") {
							t.Errorf("unexpected backend cookie: %v %v", cookie, err)
						}
						reader, err := r.MultipartReader()
						if err != nil {
							t.Error(err)
							return
						}
						parts := []struct{ name, filename, body string }{
							{"PHPSESSID", "", "_"},
							{"PHP_SESSION_UPLOAD_PROGRESS", "", "probe"},
							{"f", "probe.txt", "1"},
						}
						for _, want := range parts {
							part, err := reader.NextPart()
							if err != nil {
								t.Errorf("missing %s: %v", want.name, err)
								return
							}
							body, err := io.ReadAll(part)
							if err != nil || part.FormName() != want.name || part.FileName() != want.filename || string(body) != want.body {
								t.Errorf("unexpected multipart part: %s %s %q %v", part.FormName(), part.FileName(), body, err)
								return
							}
						}
						if _, err := reader.NextPart(); err != io.EOF {
							t.Errorf("unexpected extra part: %v", err)
							return
						}
						fmt.Fprint(w, readWarnings)
						if older {
							fmt.Fprint(w, " "+failedWriteWarning)
						}
					}))
					defer backend.Close()
					upstream, err := url.Parse(backend.URL)
					if err != nil {
						t.Fatal(err)
					}
					proxy := httputil.NewSingleHostReverseProxy(upstream)
					director := proxy.Director
					proxy.Director = func(r *http.Request) {
						director(r)
						if strip {
							r.Header.Del("Cookie")
						}
					}
					frontend := httptest.NewServer(proxy)
					defer frontend.Close()
					in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true}, frontend.URL, attested)
					if err != nil {
						t.Fatal(err)
					}
					wantOracle, wantVerdict, wantPosts := verdict.OracleNotRun, verdict.NoPHPSignal, 0
					if attested {
						wantOracle, wantVerdict, wantPosts = verdict.OraclePatched, verdict.Inconclusive, 2
						if older {
							wantOracle, wantVerdict, wantPosts = verdict.OracleUnpatched, verdict.LikelyVulnerable, 1
						}
					}
					result := verdict.Judge(in)
					if in.Oracle != wantOracle || result.Verdict != wantVerdict || int(posts.Load()) != wantPosts || len(evidence.Requests) != wantPosts {
						t.Fatalf("unexpected fallback result: %+v posts=%d evidence=%+v", result, posts.Load(), evidence)
					}
				})
			}
		}
	}
}
