package fingerprintdb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/pawal/php2shell/engine/probe"
)

func TestSelectPHPDependencyClosure(t *testing.T) {
	data := `{
		"PHP":{"cookies":{"PHPSESSID":""}},
		"CMS":{"implies":"PHP","meta":{"generator":"CMS ([\\d.]+)\\;version:\\1"}},
		"Plugin":{"implies":["CMS"],"scriptSrc":["/plugin\\.js\\;confidence:50"]},
		"Other":{"implies":["Python"],"cookies":{"other":""}},
		"CycleA":{"implies":["CycleB"],"cookies":{"a":""}},
		"CycleB":{"implies":["CycleA"],"cookies":{"b":""}},
		"RuntimeOnly":{"implies":["PHP"],"js":{"Example":""}},
		"Conditional":{"implies":["PHP"],"requires":"Other","headers":{"X-Test":""}},
		"Seed":{"cookies":{"seed":"","disabled":"\\;confidence:0"}}
	}`
	var apps map[string]upstreamApp
	if err := json.Unmarshal([]byte(data), &apps); err != nil {
		t.Fatal(err)
	}
	selected, skipped, unsupported := selectRules(apps, []string{"Seed"})
	if len(selected) != 3 || selected["CMS"].Meta["generator"] != `CMS ([\d.]+)` || !slices.Equal(selected["Plugin"].ScriptSrc, []string{`/plugin\.js`}) {
		t.Fatalf("unexpected selection: %+v", selected)
	}
	if len(selected["Seed"].Cookies) != 1 || !strings.Contains(selected["CMS"].Source, Revision) || !slices.Equal(skipped, []string{"Conditional", "RuntimeOnly"}) || len(unsupported) != 0 {
		t.Fatalf("unexpected metadata: %+v %+v %+v", selected, skipped, unsupported)
	}
}

func TestUnsupportedRulesAreNotBroadened(t *testing.T) {
	selected, _, unsupported := selectRules(map[string]upstreamApp{
		"PHPTool": {ScriptSrc: []string{"", "(?<!other)/tool.js", "["}},
	}, []string{"PHPTool"})
	if len(selected) != 0 || len(unsupported) != 2 || unsupported[0].Application != "PHPTool" {
		t.Fatalf("%+v %+v", selected, unsupported)
	}
}

func TestDownloadStatusAndBound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/missing":
			w.WriteHeader(404)
		case "/large":
			w.Write([]byte(strings.Repeat("x", (8<<20)+1)))
		default:
			w.Write([]byte("rules"))
		}
	}))
	defer srv.Close()
	for _, path := range []string{"/missing", "/large"} {
		if _, err := download(context.Background(), srv.Client(), srv.URL+path, ""); err == nil {
			t.Fatalf("accepted %s", path)
		}
	}
	got, err := download(context.Background(), srv.Client(), srv.URL, "")
	if err != nil || string(got) != "rules" {
		t.Fatalf("%s %v", got, err)
	}
}

func TestImportWritesLoadableDatabase(t *testing.T) {
	var mu sync.Mutex
	agents := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		agents[r.UserAgent()] = true
		mu.Unlock()
		switch r.URL.Path {
		case "/LICENSE":
			w.Write([]byte("GPL"))
		case "/src/technologies/e.json":
			w.Write([]byte(`{"Example CMS":{"implies":"PHP","meta":{"generator":"^Example CMS"}}}`))
		default:
			w.Write([]byte("{}"))
		}
	}))
	defer srv.Close()
	dir := filepath.Join(t.TempDir(), "fingerprints")
	count, err := importRules(context.Background(), srv.URL+"/", dir, "php2shell-check/test", nil)
	if err != nil || count != 1 || len(agents) != 1 || !agents["php2shell-check/test"] {
		t.Fatalf("%d %v %v", count, err, agents)
	}
	if _, err := probe.LoadFingerprintDatabase(filepath.Join(dir, "php.json")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"php.json", "manifest.json", "LICENSE", "NOTICE"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0644 {
			t.Fatalf("%s: %v %v", name, info, err)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 4 {
		t.Fatalf("temporary files left: %v", entries)
	}
}

func TestImportFailureKeepsPreviousDatabase(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{}"))
	}))
	defer srv.Close()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "php.json"), []byte("previous"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := importRules(context.Background(), srv.URL+"/", dir, "", nil); err == nil {
		t.Fatal("accepted an upstream without PHP rules")
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "php.json")); string(data) != "previous" {
		t.Fatalf("database replaced: %q", data)
	}
}
