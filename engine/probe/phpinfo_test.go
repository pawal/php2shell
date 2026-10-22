package probe

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestFindPHPInfoOnlyWhenAttested(t *testing.T) {
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		if r.Method != http.MethodGet {
			return
		}
		asked = append(asked, r.URL.Path)
		switch r.URL.Path {
		case "/info.php":
			fmt.Fprint(w, phpinfoPage)
		case "/phpinfo.php":
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	in, _, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL, false)
	if err != nil {
		t.Fatal(err)
	}
	if in.PHPInfo != "" || strings.Join(asked, ",") != "/" {
		t.Fatalf("passive check asked %v, version %q", asked, in.PHPInfo)
	}
	asked = nil
	in, evidence, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	if in.PHPInfo != "8.4.27" || len(evidence.PHPInfo) != 2 || evidence.PHPInfo[0].Status != http.StatusNotFound {
		t.Fatalf("attested check: version %q, evidence %+v", in.PHPInfo, evidence.PHPInfo)
	}
	if got := strings.Join(asked, ","); got != "/,/phpinfo.php,/info.php" {
		t.Errorf("asked %s", got)
	}
}

func TestFindPHPInfoSkippedWithAVersion(t *testing.T) {
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.4.27")
		if r.Method == http.MethodGet {
			asked = append(asked, r.URL.Path)
		}
	}))
	defer srv.Close()
	if _, _, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL, true); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(asked, ","); got != "/" {
		t.Errorf("asked %s", got)
	}
}

// phpinfoRow is one phpinfo() table row as PHP prints it.
func phpinfoRow(name string, values ...string) string {
	row := `<tr><td class="e">` + name + `</td>`
	for _, value := range values {
		row += `<td class="v">` + value + `</td>`
	}
	return row + "</tr>\n"
}

func TestPHPInfoSettings(t *testing.T) {
	body := phpinfoPage + phpinfoRow("Server API ", "FPM/FastCGI ") + phpinfoRow("display_errors", "Off", "Off") +
		phpinfoRow("session.save_handler", "files", "files") + phpinfoRow("session.upload_progress.enabled", "On", "Off") +
		phpinfoRow("session.save_path", "<i>no value</i>", "<i>no value</i>")
	got := phpinfoSettings(body)
	want := map[string]string{verdict.ServerAPI: "FPM/FastCGI", verdict.DisplayErrors: "Off", verdict.SaveHandler: "files", verdict.UploadProgress: "On"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if phpinfoSettings("<p>display_errors Off</p>") != nil {
		t.Error("settings outside phpinfo() rows")
	}
}

// The session section sits past the usual body cap on a large phpinfo() page.
func TestPHPInfoReadPastTheCap(t *testing.T) {
	padding := strings.Repeat(phpinfoRow("mysqlnd", "enabled"), (DefaultMaxBody/40)+1)
	body := phpinfoPage + phpinfoRow("Server API ", "Apache 2.0 Handler ") + padding + phpinfoRow("session.upload_progress.enabled", "Off", "Off")
	if len(body) < DefaultMaxBody+1000 || len(body) > maxPHPInfoBody {
		t.Fatalf("fixture is %d bytes", len(body))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, body)
		}
	}))
	defer srv.Close()
	in, _, err := checkURL(t, &Prober{AllowNonGlobal: true}, srv.URL+"/phpinfo.php", false)
	if err != nil {
		t.Fatal(err)
	}
	if in.PHPInfoSettings[verdict.UploadProgress] != "Off" || in.PHPInfoSettings[verdict.ServerAPI] != "Apache 2.0 Handler" {
		t.Errorf("settings %v", in.PHPInfoSettings)
	}
}
