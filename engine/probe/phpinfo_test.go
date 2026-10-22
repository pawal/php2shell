package probe

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pawal/php2shell/engine/verdict"
)

const phpinfoPage = `<!DOCTYPE html><html><head><title>PHP 8.4.27 - phpinfo()</title></head>
<body><div class="center"><table><tr class="h"><td><h1 class="p">PHP Version 8.4.27</h1></td></tr></table>`

func TestPHPInfoVersion(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"phpinfo", phpinfoPage, "8.4.27"},
		{"older title", `<title>phpinfo()</title><h1 class="p">PHP Version 7.4.33</h1>`, "7.4.33"},
		{"distribution suffix", `<title>PHP 8.3.6 - phpinfo()</title><h1 class="p">PHP Version 8.3.6-0ubuntu0.24.04.13</h1>`, "8.3.6-0ubuntu0.24.04.13"},
		{"heading without phpinfo title", `<title>Server notes</title><h1 class="p">PHP Version 8.4.27</h1>`, ""},
		{"prose mention", `<title>Upgrade guide</title><p>PHP Version 8.4.27 is out.</p>`, ""},
	}
	for _, c := range cases {
		if got := phpinfoVersion(c.body); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestCheckReadsPHPInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		if r.URL.Path == "/phpinfo.php" {
			fmt.Fprint(w, phpinfoPage)
			return
		}
		fmt.Fprint(w, `<a href="/phpinfo.php">info</a>`)
	}))
	defer srv.Close()
	for _, address := range []string{srv.URL + "/phpinfo.php", srv.URL} {
		in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true}, address, false)
		if err != nil {
			t.Fatal(err)
		}
		if in.PHPInfo != "8.4.27" {
			t.Errorf("%s: phpinfo version %q, evidence %+v", address, in.PHPInfo, evidence)
		}
		if got := verdict.Judge(in).Verdict; got != verdict.LikelyPatched {
			t.Errorf("%s: verdict %s", address, got)
		}
	}
}
