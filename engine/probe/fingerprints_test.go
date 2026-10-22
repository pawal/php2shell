package probe

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/pawal/php2shell/engine/verdict"
)

func TestFrameworkDiagnosticFamilies(t *testing.T) {
	cases := []struct{ technology, class string }{
		{"Laravel", `Illuminate\Database\QueryException`},
		{"Symfony", `Symfony\Component\HttpKernel\Exception\HttpException`},
		{"CodeIgniter", `CodeIgniter\Exceptions\FrameworkException`},
		{"CakePHP", `Cake\Http\Exception\HttpException`},
		{"Yii", `yii\web\HttpException`},
		{"Nette", `Nette\Application\BadRequestException`},
		{"Laminas", `Laminas\Mvc\Exception\RuntimeException`},
		{"Zend Framework", `Zend\Mvc\Exception\RuntimeException`},
		{"Phalcon", `Phalcon\Mvc\Dispatcher\Exception`},
		{"Slim", `Slim\Exception\HttpException`},
		{"FuelPHP", `Fuel\Core\HttpNotFoundException`},
		{"Kohana", `Kohana_Kohana_Exception`},
		{"ThinkPHP", `think\exception\HttpException`},
		{"Yaf", `Yaf_Exception`},
		{"Spiral", `Spiral\Http\Exception\ClientException`},
		{"Hyperf", `Hyperf\HttpMessage\Exception\HttpException`},
		{"Mezzio", `Mezzio\Exception\RuntimeException`},
		{"PHPixie", `PHPixie\ORM\Exception`},
		{"Flight", `flight\core\Dispatcher`},
		{"Neos Flow", `Neos\Flow\Exception`},
	}
	for _, c := range cases {
		t.Run(c.technology, func(t *testing.T) {
			resp := response("/", nil)
			resp.StatusCode = 500
			body := "<h1>Unhandled exception</h1><pre>Stack trace: " + c.class + " at /private/path.php:42</pre>"
			got := frameworkFingerprints(resp, body)
			if len(got) != 1 || got[0].Technology != c.technology || got[0].Scope != "component" || got[0].Confidence != "medium" || got[0].Signal != "diagnostic" {
				t.Fatalf("%+v", got)
			}
			if strings.Contains(fmt.Sprint(got), "/private/") {
				t.Fatal("diagnostic contents leaked into evidence")
			}
			resp.StatusCode = 200
			declared := frameworkFingerprints(response("/", map[string][]string{"X-Generator": {c.technology + " 1.2"}}), "")
			if len(declared) != 1 || declared[0].Technology != c.technology || declared[0].Scope != "declared" {
				t.Fatalf("declared identity: %+v", declared)
			}
			if got := frameworkFingerprints(resp, body); len(got) != 0 {
				t.Fatalf("ordinary page must not be identified by a quoted class: %+v", got)
			}
		})
	}
}

func TestFrameworkPassiveSignals(t *testing.T) {
	cases := []struct {
		name                    string
		headers                 map[string][]string
		body, technology, scope string
	}{
		{"laravel legacy cookie", map[string][]string{"Set-Cookie": {"laravel_session=secret; HttpOnly"}}, "", "Laravel", "default_cookie"},
		{"laravel current cookie", map[string][]string{"Set-Cookie": {"laravel-session=secret; HttpOnly"}}, "", "Laravel", "default_cookie"},
		{"codeigniter", map[string][]string{"Set-Cookie": {"ci_session=secret"}}, "", "CodeIgniter", "default_cookie"},
		{"legacy cakephp", map[string][]string{"Set-Cookie": {"CAKEPHP=secret"}}, "", "CakePHP", "default_cookie"},
		{"fuelphp", map[string][]string{"Set-Cookie": {"fuelcid=secret"}}, "", "FuelPHP", "default_cookie"},
		{"symfony profiler", map[string][]string{"X-Debug-Token": {"abc123"}, "X-Debug-Token-Link": {"https://example.com/_profiler/abc123"}}, "", "Symfony", "component"},
		{"nette declared", map[string][]string{"X-Powered-By": {"Nette Framework 3"}}, "", "Nette", "declared"},
		{"phalcon declared", map[string][]string{"X-Powered-By": {"Phalcon/5.9"}}, "", "Phalcon", "declared"},
		{"generator", nil, `<meta content="Slim 4" name=generator>`, "Slim", "declared"},
		{"yii asset pair", nil, `<script src="/assets/hash/yii.js?v=123"></script><script src="/assets/hash/yii.validation.js"></script>`, "Yii", "component"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matches := frameworkFingerprints(response("/", c.headers), c.body)
			if len(matches) != 1 || matches[0].Technology != c.technology || matches[0].Scope != c.scope {
				t.Fatalf("%+v", matches)
			}
			if !slices.Contains(applicationHints(response("/", c.headers), c.body), matches[0].hint()) {
				t.Fatal("fingerprint did not reach verdict hints")
			}
		})
	}
}

func TestFrameworkFalsePositives(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string][]string
		body    string
		status  int
	}{
		{"generic csrf", map[string][]string{"Set-Cookie": {"XSRF-TOKEN=x", "_csrf=y", "_identity=z"}}, "", 200},
		{"generic sessions", map[string][]string{"Set-Cookie": {"app_session=x", "PHPSESSID=y", "session=z"}}, "", 200},
		{"cookie suffix", map[string][]string{"Set-Cookie": {"laravel_session_fake=x", "ci_session_fake=x", "fuelcid_fake=x"}}, "", 200},
		{"header prefix", map[string][]string{"X-Powered-By": {"Symfonyish"}}, "", 200},
		{"zend engine", map[string][]string{"X-Powered-By": {"Zend Engine"}}, "", 200},
		{"profiler missing companion", map[string][]string{"X-Debug-Token-Link": {"https://example.com/_profiler/abc123"}}, "", 200},
		{"profiler wrong link", map[string][]string{"X-Debug-Token": {"abc"}, "X-Debug-Token-Link": {"https://example.com/debug"}}, "", 200},
		{"partial yii assets", nil, `<script src="/js/yii.js"></script>`, 200},
		{"assets in prose", nil, `<p>Load yii.js and yii.validation.js</p>`, 200},
		{"script containing fake generator", nil, `<script>const x='<meta name=generator content=Symfony>';</script>`, 200},
		{"generic exception", nil, `<h1>Exception</h1><p>Powered by an internal application</p>`, 500},
		{"class suffix", nil, `Exception: MySlim\Exception\HttpExceptionFake`, 500},
		{"namespace prefix", nil, `Exception: Fake\Slim\Exception\HttpException`, 500},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := response("/", c.headers)
			resp.StatusCode = c.status
			if got := frameworkFingerprints(resp, c.body); len(got) != 0 {
				t.Fatalf("%+v", got)
			}
		})
	}
}

func TestFrameworkEvidenceAndVersionSeparation(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("X-Powered-By", "Nette Framework 3.2.0")
	}))
	defer srv.Close()
	in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL, false)
	if err != nil {
		t.Fatal(err)
	}
	result := verdict.Judge(in)
	if requests != 1 || result.Version != nil || result.Verdict != verdict.Inconclusive {
		t.Fatalf("%d %+v", requests, result)
	}
	if len(evidence.Passive.Fingerprints) != 1 || evidence.Passive.Fingerprints[0].URL != srv.URL+"/" {
		t.Fatalf("%+v", evidence)
	}
}

func TestCatalogueMetadataAndCoverage(t *testing.T) {
	if len(frameworkCatalogue) != 20 {
		t.Fatalf("update coverage documentation for %d families", len(frameworkCatalogue))
	}
	seen := map[string]bool{}
	source := func(value string) {
		t.Helper()
		u, err := url.Parse(value)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			t.Fatalf("invalid source %q", value)
		}
	}
	for _, spec := range frameworkCatalogue {
		if spec.Technology == "" || seen[spec.Technology] || len(spec.Diagnostics) == 0 || len(spec.Aliases) == 0 || spec.Confidence != "medium" {
			t.Fatalf("incomplete or duplicate specification %+v", spec)
		}
		seen[spec.Technology] = true
		source(spec.Source)
		for _, cookie := range spec.Cookies {
			source(cookie.Source)
			if cookie.Name == "" || cookie.Confidence != "low" {
				t.Fatalf("invalid cookie rule %+v", cookie)
			}
		}
		for _, header := range spec.Headers {
			source(header.Source)
			if header.Name == "" || header.compiled == nil || header.Scope == "" || header.Confidence != "medium" {
				t.Fatalf("invalid header rule %+v", header)
			}
		}
		for _, asset := range spec.Assets {
			source(asset.Source)
			if len(asset.Names) < 2 || asset.Confidence != "low" {
				t.Fatalf("invalid asset rule %+v", asset)
			}
		}
	}
}

func TestFrameworkComponentDoesNotIdentifyWholeApplication(t *testing.T) {
	resp := response("/", nil)
	resp.StatusCode = 500
	matches := frameworkFingerprints(resp, `Unhandled exception: Symfony\Component\HttpFoundation\Request at line 42`)
	if len(matches) != 1 || matches[0].Technology != "Symfony" || matches[0].Scope != "component" {
		t.Fatalf("%+v", matches)
	}
}
