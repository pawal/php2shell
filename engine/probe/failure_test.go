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
