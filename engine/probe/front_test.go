package probe

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pawal/php2shell/engine/verdict"
)

func TestFrontLayers(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string][]string
		want    string
	}{
		{"cloudflare", map[string][]string{"Cf-Ray": {"8d2f1c3b4a5e6f70-ARN"}, "Server": {"cloudflare"}}, "Cloudflare"},
		{"cloudfront id", map[string][]string{"X-Amz-Cf-Id": {"abc=="}}, "Amazon CloudFront"},
		{"cloudfront via", map[string][]string{"Via": {"1.1 d111111abcdef8.cloudfront.net (CloudFront)"}}, "Amazon CloudFront"},
		{"fastly", map[string][]string{"X-Served-By": {"cache-lhr7351-LHR"}, "X-Varnish": {"123 456"}, "Via": {"1.1 varnish"}}, "Fastly"},
		{"fastly shield", map[string][]string{"X-Served-By": {"cache-iad-kiad7000031-IAD, cache-arn1230-ARN"}}, "Fastly"},
		{"other x-served-by", map[string][]string{"X-Served-By": {"web01"}}, ""},
		{"akamai", map[string][]string{"Server": {"AkamaiGHost"}}, "Akamai"},
		{"akamai request number", map[string][]string{"Akamai-Grn": {"0.57ad1302.1792706757.c49211e"}}, "Akamai"},
		{"azure front door", map[string][]string{"X-Azure-Ref": {"0zxV+XAAAAABKMMOjBv2NT4TY6SQVjC0zV1NURURHRTA2MjEANjMxOTJiZjctOWNiYi00ZjdlLWIyNTMtMTA2ZmY0M2Y3NDlj"}}, "Azure Front Door"},
		{"sucuri id", map[string][]string{"X-Sucuri-Id": {"11005"}}, "Sucuri"},
		{"sucuri server", map[string][]string{"Server": {"Sucuri/Website Firewall"}}, "Sucuri"},
		{"varnish", map[string][]string{"X-Varnish": {"32770 3"}, "Via": {"1.1 varnish (Varnish/7.5)"}}, "Varnish"},
		{"two layers", map[string][]string{"Cf-Ray": {"x"}, "X-Varnish": {"1"}}, "Cloudflare,Varnish"},
		{"generic proxy", map[string][]string{"Via": {"1.1 proxy.example.net"}}, "a proxy"},
		{"origin only", map[string][]string{"Server": {"nginx"}}, ""},
	}
	for _, c := range cases {
		if got := strings.Join(frontLayers(response("/", c.headers)), ","); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestCheckNamesFrontLayer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Cf-Ray", "8d2f1c3b4a5e6f70-ARN")
		fmt.Fprint(w, "<html><body>hello</body></html>")
	}))
	defer srv.Close()
	in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL, false)
	if err != nil {
		t.Fatal(err)
	}
	got := verdict.Judge(in)
	if strings.Join(evidence.Passive.Front, ",") != "Cloudflare" || got.Verdict != verdict.NoPHPSignal || !strings.Contains(got.Summary, "Cloudflare answers in front of the site") {
		t.Errorf("%+v %+v", evidence.Passive.Front, got)
	}
}
