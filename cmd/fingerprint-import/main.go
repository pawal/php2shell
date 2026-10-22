// Command fingerprint-import downloads a pinned passive PHP fingerprint subset.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
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
)

const revision = "d91f7e510e93457041bea874e8a9ffb011e3e4fe"
const rawBase = "https://raw.githubusercontent.com/enthec/webappanalyzer/" + revision + "/"
const source = "https://github.com/enthec/webappanalyzer/tree/" + revision

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

func main() {
	output := flag.String("output", "local/fingerprints", "directory for external rules, licence and manifest")
	flag.Parse()
	if err := importRules(*output); err != nil {
		fmt.Fprintln(os.Stderr, "fingerprint-import:", err)
		os.Exit(1)
	}
}

func importRules(output string) error {
	paths := []string{"LICENSE"}
	for _, letter := range "_abcdefghijklmnopqrstuvwxyz" {
		paths = append(paths, "src/technologies/"+string(letter)+".json")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	files, err := downloadFiles(ctx, paths)
	if err != nil {
		return err
	}
	apps := map[string]upstreamApp{}
	hashes := map[string]string{}
	for _, path := range paths {
		data := files[path]
		hashes[path] = fmt.Sprintf("%x", sha256.Sum256(data))
		if strings.HasSuffix(path, ".json") {
			if err := json.Unmarshal(data, &apps); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
		}
	}
	seeds := strings.Fields("Zen_Cart WordPress Drupal Joomla TYPO3 PrestaShop Magento Shopware OpenCart MediaWiki phpBB vBulletin Elementor WooCommerce Craft_CMS concrete5 Grav Kirby October_CMS SilverStripe Contao")
	for i := range seeds {
		seeds[i] = strings.ReplaceAll(seeds[i], "_", " ")
	}
	for _, file := range []string{"engine/probe/applications.json", "engine/probe/frameworks.json"} {
		data, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("run from the source checkout: %w", err)
		}
		var specs []struct{ Technology string }
		if err := json.Unmarshal(data, &specs); err != nil {
			return err
		}
		for _, spec := range specs {
			seeds = append(seeds, spec.Technology)
		}
	}
	selected, skipped, unsupported := selectRules(apps, seeds)
	if len(selected) == 0 {
		return fmt.Errorf("upstream supplied no supported PHP fingerprints")
	}
	encoded, err := encode(map[string]any{"source": source, "license": "GPL-3.0", "apps": selected})
	if err != nil {
		return err
	}
	manifest, err := encode(map[string]any{
		"revision": revision, "source": source, "license": "GPL-3.0", "applications": len(selected),
		"skipped_applications": skipped, "unsupported_patterns": unsupported,
		"sha256": hashes, "output_sha256": fmt.Sprintf("%x", sha256.Sum256(encoded)),
	})
	if err != nil {
		return err
	}
	notice := "PHP subset adapted from Enthec WebAppAnalyzer and Wappalyzer contributors.\nSource: " + source + "\nLicense: GPL-3.0; see LICENSE.\nChanges: PHP dependency selection; only cookies, headers, meta and scriptSrc;\nversion/confidence annotations removed; conditional and incompatible rules omitted.\n"
	if err := os.MkdirAll(output, 0755); err != nil {
		return err
	}
	for name, data := range map[string][]byte{"php.json": encoded, "manifest.json": manifest, "LICENSE": files["LICENSE"], "NOTICE": []byte(notice)} {
		if err := os.WriteFile(filepath.Join(output, name), data, 0644); err != nil {
			return err
		}
	}
	fmt.Printf("Downloaded %d PHP-related technologies to %s\nPinned revision: %s; external rules remain GPL-3.0.\n", len(selected), filepath.Join(output, "php.json"), revision)
	return nil
}

func encode(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	return append(data, '\n'), err
}

func downloadFiles(ctx context.Context, paths []string) (map[string][]byte, error) {
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
			data, err := download(ctx, client, rawBase+path)
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

func download(ctx context.Context, client *http.Client, address string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
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
		rules.Source = "https://github.com/enthec/webappanalyzer/blob/" + revision + "/src/technologies/" + letter + ".json"
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
