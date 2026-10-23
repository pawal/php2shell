package probe

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pawal/php2shell/engine/verdict"
)

// An unreachable start page keeps its error and a plain reason.
func TestUnreachableReasons(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := "http://" + closed.Addr().String() + "/"
	closed.Close()
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer slow.Close()
	untrusted := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer untrusted.Close()
	cases := []struct {
		name, address, want string
	}{
		{"refused", refused, verdict.FailedRefused},
		{"timeout", slow.URL, verdict.FailedTimeout},
		{"certificate", untrusted.URL, verdict.FailedCertificate},
	}
	for _, c := range cases {
		in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true, RequestTimeout: 200 * time.Millisecond}, c.address, false)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if in.Reachable || in.Failure != c.want || evidence.Passive.Error == "" {
			t.Errorf("%s: failure %q, error %q", c.name, in.Failure, evidence.Passive.Error)
		}
		if got := verdict.Judge(in); got.Verdict != verdict.Unreachable || !strings.Contains(got.Summary, c.want[1:]) {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
}

// An assumed HTTPS that fails fast is retried over HTTP; an explicit https:// is not.
func TestAssumedHTTPSFallsBackToHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.5.11")
	}))
	defer srv.Close()
	bare := strings.TrimPrefix(srv.URL, "http://")
	in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true}, bare, false)
	if err != nil {
		t.Fatal(err)
	}
	got := verdict.Judge(in)
	if !in.Reachable || in.HTTPSFailure != verdict.FailedHandshake || evidence.HTTPSError == "" || !strings.HasPrefix(evidence.Passive.FinalURL, "http://") {
		t.Fatalf("no fallback: %+v %+v", in, evidence)
	}
	if got.Verdict != verdict.LikelyVulnerable || !strings.HasSuffix(got.Summary, "Over HTTPS, the TLS handshake failed, so the check used plain HTTP.") {
		t.Errorf("summary: %s", got.Summary)
	}
	in, evidence, err = checkURL(t, &Prober{AllowNonGlobal: true}, "https://"+bare, false)
	if err != nil || in.Reachable || evidence.HTTPSError != "" {
		t.Errorf("explicit https was retried: %+v %v", in, err)
	}
}
