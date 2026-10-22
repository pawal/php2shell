package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
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
	if len(selected["Seed"].Cookies) != 1 || !strings.Contains(selected["CMS"].Source, revision) || !slices.Equal(skipped, []string{"Conditional", "RuntimeOnly"}) || len(unsupported) != 0 {
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
		if _, err := download(context.Background(), srv.Client(), srv.URL+path); err == nil {
			t.Fatalf("accepted %s", path)
		}
	}
	got, err := download(context.Background(), srv.Client(), srv.URL)
	if err != nil || string(got) != "rules" {
		t.Fatalf("%s %v", got, err)
	}
}
