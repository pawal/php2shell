package probe

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pawal/php2shell/engine/verdict"
)

// A hostile site cannot inflate a report beyond the bounds, and its version still counts.
func TestHostileSiteIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", strings.Repeat("Z", 20000))
		w.Header().Set("Server", "Apache "+strings.Repeat("S", 10000))
		for i := range 1500 {
			w.Header().Add("Set-Cookie", fmt.Sprintf("c%d=1", i))
		}
		fmt.Fprint(w, "<address>Apache PHP/8.4.1-"+strings.Repeat("y", 60000)+" Server</address>")
	}))
	defer srv.Close()
	in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true, MaxBody: 256 << 10}, srv.URL, false)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(evidence)
	p := evidence.Passive
	if len(data) > 16<<10 || len(p.PoweredBy) > maxValue+3 || len(p.Server) > maxValue+3 || len(p.Signature) > maxValue+3 || len(p.Cookies) != maxCookies {
		t.Errorf("evidence is %d bytes: powered %d, server %d, signature %d, cookies %d", len(data), len(p.PoweredBy), len(p.Server), len(p.Signature), len(p.Cookies))
	}
	got := verdict.Judge(in)
	if got.Verdict != verdict.LikelyVulnerable || len(got.Version.Raw) > 128 {
		t.Errorf("verdict %s, raw version %d bytes", got.Verdict, len(got.Version.Raw))
	}
}

func TestClip(t *testing.T) {
	if got := clip("short", 10); got != "short" {
		t.Errorf("short: %q", got)
	}
	if got := clip(strings.Repeat("é", 10), 5); got != "éé..." {
		t.Errorf("multibyte cut: %q", got)
	}
	if got := clipAll([]string{"a", "b", "c"}, 10, 2); len(got) != 2 {
		t.Errorf("most: %v", got)
	}
}
