package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runArgs(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestUsage(t *testing.T) {
	if code, _, stderr := runArgs(); code != exitUsage || !strings.Contains(stderr, "Usage:") {
		t.Errorf("no arguments: %d %q", code, stderr)
	}
	if code, stdout, _ := runArgs("help"); code != exitOK || !strings.Contains(stdout, "-allow-non-global") {
		t.Errorf("help: %d", code)
	}
	if code, _, _ := runArgs("nope"); code != exitUsage {
		t.Errorf("unknown subcommand: %d", code)
	}
	if code, stdout, _ := runArgs("version"); code != exitOK || strings.TrimSpace(stdout) == "" {
		t.Errorf("version: %d %q", code, stdout)
	}
}

func TestCheckRefusesBeforeAnyRequest(t *testing.T) {
	for _, target := range []string{"localhost", "http://127.0.0.1/", "http://[::ffff:127.0.0.1]/", "http://10.0.0.1/"} {
		code, _, stderr := runArgs("check", target)
		if code == exitOK || stderr == "" {
			t.Errorf("%s: %d %q", target, code, stderr)
		}
	}
}

func TestServeDumpConfig(t *testing.T) {
	code, stdout, stderr := runArgs("serve", "-dump-config", "-public-url", "https://php2shell.example.net")
	if code != exitOK || !strings.Contains(stdout, `"public_url": "https://php2shell.example.net"`) {
		t.Errorf("dump-config: %d %q %q", code, stdout, stderr)
	}
}

func TestUserAgent(t *testing.T) {
	if ua := userAgent("https://php2shell.example.net"); !strings.HasPrefix(ua, "php2shell-check/") || !strings.HasSuffix(ua, "(+https://php2shell.example.net/about)") {
		t.Errorf("user agent %q", ua)
	}
}

func TestCheckExternalFingerprints(t *testing.T) {
	file := filepath.Join(t.TempDir(), "php.json")
	data := `{"source":"https://example.com/database","license":"test","apps":{"Example CMS":{"source":"https://example.com/rule","meta":{"generator":"^Example CMS"}}}}`
	if err := os.WriteFile(file, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		fmt.Fprint(w, `<meta name=generator content="Example CMS 9.2">`)
	}))
	defer srv.Close()
	code, stdout, stderr := runArgs("check", "-allow-non-global", "-passive", "-json", "-fingerprints", file, srv.URL)
	if code != exitOK || stderr != "" || !strings.Contains(stdout, `"technology": "Example CMS"`) || strings.Contains(stdout, `"version":`) || requests != 1 {
		t.Fatalf("%d %s %s requests=%d", code, stdout, stderr, requests)
	}
	code, _, stderr = runArgs("check", "-passive", "-fingerprints", file+".missing", srv.URL)
	if code != exitUsage || !strings.Contains(stderr, "fingerprint database") || requests != 1 {
		t.Fatalf("invalid database did not fail before fetching: %d %s", code, stderr)
	}
	code, _, stderr = runArgs("serve", "-fingerprints", file+".missing")
	if code != exitUsage || !strings.Contains(stderr, "fingerprint database") {
		t.Fatalf("invalid service database accepted: %d %s", code, stderr)
	}
}
