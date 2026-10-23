package probe

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/pawal/php2shell/engine/verdict"
)

func TestIncompleteSessionResponsesAreNotClassified(t *testing.T) {
	for _, truncated := range []bool{true, false} {
		t.Run(fmt.Sprintf("connection_truncated=%t", truncated), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					return
				}
				if truncated {
					w.Header().Set("Content-Length", strconv.Itoa(len(readWarnings)+100))
					fmt.Fprint(w, readWarnings)
				} else {
					fmt.Fprint(w, readWarnings+strings.Repeat("x", 100)+failedWriteWarning)
				}
			}))
			defer srv.Close()
			p := &Prober{AllowNonGlobal: true}
			if !truncated {
				p.MaxBody = int64(len(readWarnings))
			}
			in, evidence, err := checkURL(t, p, srv.URL, true)
			if err != nil {
				t.Fatal(err)
			}
			result := verdict.Judge(in)
			if result.Verdict != verdict.Inconclusive || in.Oracle != verdict.OracleSilent || len(in.OraclePaths) != 0 || len(evidence.Requests) != 2 {
				t.Fatalf("%+v %+v", result, evidence)
			}
			for _, request := range evidence.Requests {
				if request.Complete || request.Result != verdict.OracleSilent || request.InvalidID != 1 || request.FailedRead != 1 || truncated && request.Error == "" {
					t.Fatalf("incomplete response was not preserved: %+v", request)
				}
			}
		})
	}
}

func TestSessionResponseAtExactBodyCapIsComplete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			fmt.Fprint(w, readWarnings)
		}
	}))
	defer srv.Close()
	in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true, MaxBody: int64(len(readWarnings))}, srv.URL, true)
	if err != nil || in.Oracle != verdict.OraclePatched || verdict.Judge(in).Verdict != verdict.Inconclusive {
		t.Fatalf("%+v %v", in, err)
	}
	for _, request := range evidence.Requests {
		if !request.Complete || request.Result != verdict.OraclePatched {
			t.Fatalf("exact cap lost completeness: %+v", request)
		}
	}
}

func TestSessionSignalDoesNotMaskOlderApplication(t *testing.T) {
	for _, olderResponse := range []string{"", readWarnings, unpatchedPage} {
		t.Run(fmt.Sprintf("older_response_length=%d", len(olderResponse)), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/old.php" {
					w.Header().Set("X-Powered-By", "PHP/8.5.11")
					if r.Method == http.MethodPost {
						fmt.Fprint(w, olderResponse)
					}
					return
				}
				w.Header().Set("X-Powered-By", "PHP/8.5.12")
				if r.Method == http.MethodGet {
					fmt.Fprint(w, `<a href="/old.php">Old application</a>`)
				} else {
					fmt.Fprint(w, readWarnings)
				}
			}))
			defer srv.Close()
			in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL, true)
			if err != nil {
				t.Fatal(err)
			}
			result := verdict.Judge(in)
			if result.Verdict != verdict.LikelyVulnerable || result.Version.String() != "8.5.11" || strings.Contains(result.Summary, "so the package carries") || len(evidence.Requests) != 3 {
				t.Fatalf("%+v %+v", result, evidence)
			}
			last := evidence.Requests[2]
			if last.URL != srv.URL+"/old.php" {
				t.Fatalf("older application was skipped: %+v", evidence.Requests)
			}
			if olderResponse == unpatchedPage && (in.Oracle != verdict.OracleUnpatched || !slices.Equal(in.OraclePaths, []string{last.URL}) || last.Result != verdict.OracleUnpatched) {
				t.Fatalf("strongest observation lost its URL: %+v %+v", in, last)
			}
		})
	}
}

func TestUnsuccessfulSessionPageIsNotClassified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(500)
			fmt.Fprint(w, readWarnings)
		}
	}))
	defer srv.Close()
	in, _, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL, true)
	if err != nil || in.Oracle != verdict.OracleSilent || verdict.Judge(in).Verdict != verdict.Inconclusive {
		t.Fatalf("%+v %v", in, err)
	}
}

// Older behaviour counts however the body ended, since the write warning was read.
func TestOlderSessionBehaviourOnPartialBodies(t *testing.T) {
	for _, truncated := range []bool{true, false} {
		t.Run(fmt.Sprintf("connection_truncated=%t", truncated), func(t *testing.T) {
			older := readWarnings + " " + failedWriteWarning
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					return
				}
				if truncated {
					breakOff(w, older)
				} else {
					fmt.Fprint(w, older+strings.Repeat("x", 200))
				}
			}))
			defer srv.Close()
			p := &Prober{AllowNonGlobal: true}
			if !truncated {
				p.MaxBody = int64(len(older) + 10)
			}
			in, evidence, err := checkURL(t, p, srv.URL, true)
			if err != nil {
				t.Fatal(err)
			}
			if in.Oracle != verdict.OracleUnpatched || evidence.Requests[0].Complete || evidence.Requests[0].Result != verdict.OracleUnpatched {
				t.Fatalf("%+v %+v", in, evidence.Requests)
			}
		})
	}
}

// A page longer than the cap counts once its output follows the startup warnings.
func TestLongPageAfterStartupWarnings(t *testing.T) {
	for _, c := range []struct {
		name  string
		after int
		want  verdict.Oracle
	}{
		{"long page", 3 * DefaultMaxBody, verdict.OraclePatched},
		{"cut near the warnings", 200, verdict.OracleSilent},
	} {
		t.Run(c.name, func(t *testing.T) {
			body := readWarnings + "<br />\n" + strings.Repeat("<p>page</p>", c.after/11+1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					fmt.Fprint(w, body)
				}
			}))
			defer srv.Close()
			p := &Prober{AllowNonGlobal: true}
			if c.after < startupMargin {
				p.MaxBody = int64(len(readWarnings) + c.after)
			}
			in, evidence, err := checkURL(t, p, srv.URL, true)
			if err != nil {
				t.Fatal(err)
			}
			if in.Oracle != c.want || evidence.Requests[0].Complete {
				t.Fatalf("%+v %+v", in.Oracle, evidence.Requests[0])
			}
		})
	}
}
