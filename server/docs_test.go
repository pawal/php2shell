package server

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The files the documents and the packages are held to.
const (
	deployPath = "../docs/deploy.md"
	specPath   = "../docs/openapi.yaml"
	unitPath   = "../packaging/systemd/php2shell.service"
	pkgConf    = "../packaging/config/config.json"
	caddyPath  = "../packaging/caddy/Caddyfile"
	nfpmPath   = "../packaging/nfpm/php2shell.yaml"
)

var (
	execStartLine  = regexp.MustCompile(`(?m)^ExecStart=.*$`)
	flagMention    = regexp.MustCompile(`\s-[a-z][a-z0-9-]*`)
	packageSource  = regexp.MustCompile(`(?m)^\s+(?:- src|postinstall|preremove|postremove): (.+)$`)
	specPathLine   = regexp.MustCompile(`^  (/[^\s:]*):\s*$`)
	specMethodLine = regexp.MustCompile(`^    (get|post|put|patch|delete):\s*$`)
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(data)
}

// fencedBlocks returns the bodies of the fenced blocks carrying one info string.
func fencedBlocks(doc, info string) []string {
	var blocks, current []string
	open := false
	for line := range strings.SplitSeq(doc, "\n") {
		switch {
		case open && strings.HasPrefix(line, "```"):
			blocks = append(blocks, strings.Join(current, "\n"))
			current, open = nil, false
		case open:
			current = append(current, line)
		case line == "```"+info:
			open = true
		}
	}
	return blocks
}

func shownInDeploy(t *testing.T, info, path string) {
	t.Helper()
	shipped := strings.TrimSpace(readFile(t, path))
	for _, block := range fencedBlocks(readFile(t, deployPath), info) {
		if strings.TrimSpace(block) == shipped {
			return
		}
	}
	t.Errorf("%s shows no %s block equal to %s", deployPath, info, path)
}

func TestUnitIsDocumented(t *testing.T)      { shownInDeploy(t, "ini", unitPath) }
func TestCaddyfileIsDocumented(t *testing.T) { shownInDeploy(t, "caddyfile", caddyPath) }

// Every configuration block of the document loads and validates.
func TestDeployConfigBlocksLoad(t *testing.T) {
	blocks := fencedBlocks(readFile(t, deployPath), "json")
	if len(blocks) == 0 {
		t.Fatal("no json block")
	}
	for i, block := range blocks {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(block), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := DefaultConfig()
		if err := cfg.ApplyFile(path); err != nil {
			t.Errorf("block %d: %v", i, err)
		} else if err := cfg.Validate(); err != nil {
			t.Errorf("block %d: %v", i, err)
		}
	}
}

// Every key the configuration has is described in the document.
func TestDeployDocumentsEveryKey(t *testing.T) {
	doc := readFile(t, deployPath)
	data, _ := json.Marshal(DefaultConfig())
	var keys map[string]any
	_ = json.Unmarshal(data, &keys)
	keys["allow_non_global_addresses"] = true
	for key := range keys {
		if !strings.Contains(doc, "`"+key+"`") && !strings.Contains(doc, `"`+key+`"`) {
			t.Errorf("%s does not describe %s", deployPath, key)
		}
	}
}

// The shipped configuration validates and logs where the unit may write.
func TestPackagedConfig(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.ApplyFile(pkgConf); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.AllowNonGlobalAddresses {
		t.Error("the packaged configuration sets allow_non_global_addresses")
	}
	var state string
	for line := range strings.SplitSeq(readFile(t, unitPath), "\n") {
		if value, ok := strings.CutPrefix(line, "StateDirectory="); ok {
			state = value
		}
	}
	if dir := "/var/lib/" + state + "/"; state == "" || !strings.HasPrefix(cfg.LogFile, dir) {
		t.Errorf("log_file %q lies outside the state directory %q", cfg.LogFile, state)
	}
}

// Every flag the unit passes exists, and the files it names are installed.
func TestPackagedUnit(t *testing.T) {
	exec := execStartLine.FindString(readFile(t, unitPath))
	set := flag.NewFlagSet("serve", flag.ContinueOnError)
	set.String("config", "", "")
	set.Bool("dump-config", false, "")
	cfg := DefaultConfig()
	bindFlags(set, &cfg)
	for _, mention := range flagMention.FindAllString(exec, -1) {
		if set.Lookup(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(mention), "-"))) == nil {
			t.Errorf("%q is not a serve flag", mention)
		}
	}
	installed := readFile(t, nfpmPath)
	fields := strings.Fields(strings.TrimPrefix(exec, "ExecStart="))
	for i, field := range fields {
		if i == 0 || fields[i-1] == "-config" {
			if !strings.Contains(installed, "dst: "+field+"\n") {
				t.Errorf("the unit names %s, which the package does not install", field)
			}
		}
	}
}

func TestPackageContents(t *testing.T) {
	for _, match := range packageSource.FindAllStringSubmatch(readFile(t, nfpmPath), -1) {
		path := strings.TrimSpace(match[1])
		if strings.Contains(path, "${") {
			continue
		}
		if _, err := os.Stat(filepath.Join("..", path)); err != nil {
			t.Error(err)
		}
	}
}

// The document's header table carries the policies the middleware sets.
func TestDeployDocumentsHeaders(t *testing.T) {
	doc := readFile(t, deployPath)
	for _, value := range []string{apiCSP, uiCSP, permissionsPolicy} {
		if !strings.Contains(doc, "`"+value+"`") {
			t.Errorf("%s does not show %q", deployPath, value)
		}
	}
}

// The contract and the API routes name the same methods and paths.
func TestOpenAPICoversTheAPI(t *testing.T) {
	spec := map[string][]string{}
	var current string
	inPaths := false
	for line := range strings.SplitSeq(readFile(t, specPath), "\n") {
		if line == "paths:" {
			inPaths = true
			continue
		}
		if !inPaths {
			continue
		}
		if line != "" && !strings.HasPrefix(line, " ") {
			break
		}
		if m := specPathLine.FindStringSubmatch(line); m != nil {
			current = m[1]
			spec[current] = nil
		} else if m := specMethodLine.FindStringSubmatch(line); m != nil && current != "" {
			spec[current] = append(spec[current], strings.ToUpper(m[1]))
		}
	}
	routes := map[string][]string{}
	for _, rt := range newTestServer(t, nil, nil).routes() {
		if strings.HasPrefix(rt.Path, apiPrefix) {
			routes[rt.Path] = append(routes[rt.Path], rt.Method)
		}
	}
	for path, methods := range routes {
		slices.Sort(methods)
		documented := slices.Sorted(slices.Values(spec[path]))
		if !slices.Equal(methods, documented) {
			t.Errorf("%s: registered %v, documented %v", path, methods, documented)
		}
	}
	for path := range spec {
		if _, ok := routes[path]; !ok {
			t.Errorf("%s is documented but not registered", path)
		}
	}
}
