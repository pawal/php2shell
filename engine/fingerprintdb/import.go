// Package fingerprintdb downloads a pinned passive PHP fingerprint subset.
package fingerprintdb

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pawal/php2shell/engine/probe"
)

// DefaultDir holds the database on a package install.
const DefaultDir = "/etc/php2shell/fingerprints"

// Revision is the pinned WebAppAnalyzer commit.
const Revision = "d91f7e510e93457041bea874e8a9ffb011e3e4fe"
const rawBase = "https://raw.githubusercontent.com/enthec/webappanalyzer/" + Revision + "/"
const source = "https://github.com/enthec/webappanalyzer/tree/" + Revision

type stringList []string

func (s *stringList) UnmarshalJSON(data []byte) error {
	var single string
	if json.Unmarshal(data, &single) == nil {
		*s = []string{single}
		return nil
	}
	return json.Unmarshal(data, (*[]string)(s))
}

type upstreamApp struct {
	Implies          stringList        `json:"implies"`
	Requires         json.RawMessage   `json:"requires"`
	RequiresCategory json.RawMessage   `json:"requiresCategory"`
	Cookies          map[string]string `json:"cookies"`
	Headers          map[string]string `json:"headers"`
	Meta             map[string]string `json:"meta"`
	ScriptSrc        stringList        `json:"scriptSrc"`
}

type appRules struct {
	Source    string            `json:"source"`
	Cookies   map[string]string `json:"cookies,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Meta      map[string]string `json:"meta,omitempty"`
	ScriptSrc []string          `json:"scriptSrc,omitempty"`
}

type unsupportedPattern struct {
	Application string `json:"application"`
	Pattern     string `json:"pattern"`
}

// Import writes php.json, manifest.json, LICENSE and NOTICE to dir and
// returns the number of selected technologies.
func Import(ctx context.Context, dir, userAgent string) (int, error) {
	return importRules(ctx, rawBase, dir, userAgent, probe.CatalogueTechnologies())
}

func importRules(ctx context.Context, base, dir, userAgent string, catalogue []string) (int, error) {
	paths := []string{"LICENSE"}
	for _, letter := range "_abcdefghijklmnopqrstuvwxyz" {
		paths = append(paths, "src/technologies/"+string(letter)+".json")
	}
	files, err := downloadFiles(ctx, base, userAgent, paths)
	if err != nil {
		return 0, err
	}
	apps := map[string]upstreamApp{}
	hashes := map[string]string{}
	for _, path := range paths {
		data := files[path]
		hashes[path] = fmt.Sprintf("%x", sha256.Sum256(data))
		if strings.HasSuffix(path, ".json") {
			if err := json.Unmarshal(data, &apps); err != nil {
				return 0, fmt.Errorf("%s: %w", path, err)
			}
		}
	}
	seeds := strings.Fields("Zen_Cart WordPress Drupal Joomla TYPO3 PrestaShop Magento Shopware OpenCart MediaWiki phpBB vBulletin Elementor WooCommerce Craft_CMS concrete5 Grav Kirby October_CMS SilverStripe Contao")
	for i := range seeds {
		seeds[i] = strings.ReplaceAll(seeds[i], "_", " ")
	}
	seeds = append(seeds, catalogue...)
	selected, skipped, unsupported := selectRules(apps, seeds)
	if len(selected) == 0 {
		return 0, fmt.Errorf("upstream supplied no supported PHP fingerprints")
	}
	encoded, err := encode(map[string]any{"source": source, "license": "GPL-3.0", "apps": selected})
	if err != nil {
		return 0, err
	}
	if _, err := probe.ParseFingerprintDatabase(encoded); err != nil {
		return 0, err
	}
	manifest, err := encode(map[string]any{
		"revision": Revision, "source": source, "license": "GPL-3.0", "applications": len(selected),
		"skipped_applications": skipped, "unsupported_patterns": unsupported,
		"sha256": hashes, "output_sha256": fmt.Sprintf("%x", sha256.Sum256(encoded)),
	})
	if err != nil {
		return 0, err
	}
	notice := "PHP subset adapted from Enthec WebAppAnalyzer and Wappalyzer contributors.\nSource: " + source + "\nLicense: GPL-3.0; see LICENSE.\nChanges: PHP dependency selection; only cookies, headers, meta and scriptSrc;\nversion/confidence annotations removed; conditional and incompatible rules omitted.\n"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return 0, err
	}
	// php.json last: a failed run keeps the previous database.
	for _, file := range []struct {
		name string
		data []byte
	}{{"LICENSE", files["LICENSE"]}, {"NOTICE", []byte(notice)}, {"manifest.json", manifest}, {"php.json", encoded}} {
		if err := writeFile(dir, file.name, file.data); err != nil {
			return 0, err
		}
	}
	return len(selected), nil
}

// writeFile replaces name atomically, readable by the service's dynamic user.
func writeFile(dir, name string, data []byte) error {
	f, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0644); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(dir, name))
}

func encode(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	return append(data, '\n'), err
}

func downloadFiles(ctx context.Context, base, userAgent string, paths []string) (map[string][]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	files := map[string][]byte{}
	var mu sync.Mutex
	var firstError error
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, path := range paths {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			data, err := download(ctx, client, base+path, userAgent)
			mu.Lock()
			defer mu.Unlock()
			if err != nil && firstError == nil {
				firstError = fmt.Errorf("download %s: %w", path, err)
			}
			files[path] = data
		})
	}
	wg.Wait()
	return files, firstError
}

func download(ctx context.Context, client *http.Client, address, userAgent string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (8<<20)+1))
	if len(data) > 8<<20 {
		return nil, fmt.Errorf("response larger than 8 MiB")
	}
	return data, err
}

func selectRules(apps map[string]upstreamApp, seeds []string) (map[string]appRules, []string, []unsupportedPattern) {
	related := map[string]bool{"PHP": true}
	for _, name := range seeds {
		related[name] = true
	}
	for changed := true; changed; {
		changed = false
		for name, app := range apps {
			for _, dependency := range app.Implies {
				if related[strings.Split(dependency, `\;`)[0]] && !related[name] {
					related[name], changed = true, true
				}
			}
		}
	}
	selected := map[string]appRules{}
	skipped := []string{}
	unsupported := []unsupportedPattern{}
	names := []string{}
	for name := range related {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		app, ok := apps[name]
		if !ok || name == "PHP" {
			continue
		}
		if condition(app.Requires) || condition(app.RequiresCategory) {
			skipped = append(skipped, name)
			continue
		}
		convert := func(pattern string) (string, bool) {
			parts := strings.Split(pattern, `\;`)
			for _, part := range parts[1:] {
				if value, ok := strings.CutPrefix(part, "confidence:"); ok {
					confidence, err := strconv.Atoi(value)
					if err != nil || confidence <= 0 {
						return "", false
					}
				}
			}
			if _, err := regexp.Compile("(?i)" + parts[0]); err != nil {
				unsupported = append(unsupported, unsupportedPattern{name, parts[0]})
				return "", false
			}
			return parts[0], true
		}
		convertMap := func(input map[string]string) map[string]string {
			out := map[string]string{}
			keys := []string{}
			for key := range input {
				keys = append(keys, key)
			}
			slices.Sort(keys)
			for _, key := range keys {
				if pattern, ok := convert(input[key]); ok {
					out[key] = pattern
				}
			}
			return out
		}
		rules := appRules{Cookies: convertMap(app.Cookies), Headers: convertMap(app.Headers), Meta: convertMap(app.Meta)}
		for _, pattern := range app.ScriptSrc {
			if pattern, ok := convert(pattern); ok && pattern != "" {
				rules.ScriptSrc = append(rules.ScriptSrc, pattern)
			}
		}
		if len(rules.Cookies)+len(rules.Headers)+len(rules.Meta)+len(rules.ScriptSrc) == 0 {
			skipped = append(skipped, name)
			continue
		}
		letter := strings.ToLower(name[:1])
		if letter < "a" || letter > "z" {
			letter = "_"
		}
		rules.Source = "https://github.com/enthec/webappanalyzer/blob/" + Revision + "/src/technologies/" + letter + ".json"
		selected[name] = rules
	}
	return selected, skipped, unsupported
}

func condition(value json.RawMessage) bool {
	switch strings.TrimSpace(string(value)) {
	case "", "null", "[]", `""`:
		return false
	}
	return true
}
