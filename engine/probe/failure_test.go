package probe

import (
	"bufio"
	"context"
	"fmt"
	"io"
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

// splitPort never answers a TLS handshake but serves plain HTTP on the same port.
func splitPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				first, err := r.Peek(1)
				if err != nil {
					return
				}
				if first[0] == 0x16 {
					io.Copy(io.Discard, r)
					return
				}
				for line := ""; err == nil && line != "\r\n"; line, err = r.ReadString('\n') {
				}
				fmt.Fprint(c, "HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.5.11\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// An assumed HTTPS that does not answer is retried over HTTP while time remains.
func TestSilentHTTPSFallsBackToHTTP(t *testing.T) {
	address := splitPort(t)
	in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true, RequestTimeout: 300 * time.Millisecond}, address, false)
	if err != nil {
		t.Fatal(err)
	}
	got := verdict.Judge(in)
	if !in.Reachable || in.HTTPSFailure != verdict.FailedTimeout || got.Verdict != verdict.LikelyVulnerable || !strings.HasSuffix(got.Summary, "Over HTTPS, the connection timed out, so the check used plain HTTP.") {
		t.Fatalf("%+v %+v", got, evidence)
	}
	target, err := ParseTarget(address)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	in, _, err = (&Prober{AllowNonGlobal: true, RequestTimeout: 300 * time.Millisecond}).Check(ctx, target, false)
	if err != nil || in.Reachable || in.HTTPSFailure != "" {
		t.Errorf("retried without time left: %+v %v", in, err)
	}
}

// When HTTP fails too, the result names both failures.
func TestBothSchemesFail(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := closed.Addr().String()
	closed.Close()
	in, _, err := checkURL(t, &Prober{AllowNonGlobal: true}, address, false)
	if err != nil {
		t.Fatal(err)
	}
	got := verdict.Judge(in)
	if got.Verdict != verdict.Unreachable || !strings.HasSuffix(got.Summary, "Plain HTTP was tried after HTTPS failed: the connection was refused.") {
		t.Errorf("%+v", got)
	}
}
