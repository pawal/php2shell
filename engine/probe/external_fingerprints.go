package probe

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
)

// FingerprintDatabase holds immutable, separately supplied passive rules.
type FingerprintDatabase struct {
	rules []externalRule
}

type externalRule struct {
	technology, signal, key, source string
	pattern                         *regexp.Regexp
}

type externalDatabase struct {
	Source  string                 `json:"source"`
	License string                 `json:"license"`
	Apps    map[string]externalApp `json:"apps"`
}

type externalApp struct {
	Source    string            `json:"source"`
	Cookies   map[string]string `json:"cookies"`
	Headers   map[string]string `json:"headers"`
	Meta      map[string]string `json:"meta"`
	ScriptSrc []string          `json:"scriptSrc"`
}

// LoadFingerprintDatabase reads the PHP-only output of cmd/fingerprint-import.
func LoadFingerprintDatabase(filename string) (*FingerprintDatabase, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("fingerprint database: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (8<<20)+1))
	if err != nil || len(data) > 8<<20 {
		return nil, fmt.Errorf("fingerprint database unreadable or larger than 8 MiB")
	}
	var input externalDatabase
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, fmt.Errorf("fingerprint database: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("fingerprint database contains trailing data")
	}
	if input.Source == "" || input.License == "" || len(input.Apps) == 0 {
		return nil, fmt.Errorf("fingerprint database requires source, license and apps")
	}
	db := &FingerprintDatabase{}
	for _, name := range sortedKeys(input.Apps) {
		app := input.Apps[name]
		if name == "" || app.Source == "" {
			return nil, fmt.Errorf("fingerprint database: missing application name or source")
		}
		add := func(signal, key, pattern string) error {
			re, err := regexp.Compile("(?i)" + pattern)
			if err != nil {
				return fmt.Errorf("fingerprint database: %s %s: %w", name, signal, err)
			}
			db.rules = append(db.rules, externalRule{name, signal, key, app.Source, re})
			return nil
		}
		for _, channel := range []struct {
			name  string
			rules map[string]string
		}{{"cookie", app.Cookies}, {"header", app.Headers}, {"meta", app.Meta}} {
			for _, key := range sortedKeys(channel.rules) {
				if key == "" {
					return nil, fmt.Errorf("fingerprint database: empty %s key", channel.name)
				}
				if err := add(channel.name, key, channel.rules[key]); err != nil {
					return nil, err
				}
			}
		}
		for _, pattern := range app.ScriptSrc {
			if pattern == "" {
				return nil, fmt.Errorf("fingerprint database: empty scriptSrc pattern")
			}
			if err := add("scriptSrc", "", pattern); err != nil {
				return nil, err
			}
		}
	}
	if len(db.rules) == 0 {
		return nil, fmt.Errorf("fingerprint database contains no supported rules")
	}
	return db, nil
}

// Match evaluates already fetched responses and never retains their contents.
func (db *FingerprintDatabase) Match(resp *http.Response, body string) []Fingerprint {
	if db == nil || inspectionBlock(resp, body) != "" {
		return nil
	}
	cookies := map[string][]string{}
	for _, cookie := range resp.Cookies() {
		cookies[cookie.Name] = append(cookies[cookie.Name], cookie.Value)
	}
	meta := map[string][]string{}
	var scripts []string
	for _, tag := range pageTags(body) {
		if tag.name == "meta" {
			if content, ok := tag.attrs["content"]; ok {
				name := strings.ToLower(tag.attrs["name"])
				meta[name] = append(meta[name], content)
			}
		}
		if tag.name == "script" && tag.attrs["src"] != "" {
			if src, err := url.Parse(tag.attrs["src"]); err == nil && (src.Scheme == "" || src.Scheme == "http" || src.Scheme == "https") {
				scripts = append(scripts, tag.attrs["src"])
			}
		}
	}
	var out []Fingerprint
	for _, rule := range db.rules {
		var values []string
		switch rule.signal {
		case "cookie":
			values = cookies[rule.key]
		case "header":
			values = resp.Header.Values(rule.key)
		case "meta":
			values = meta[strings.ToLower(rule.key)]
		case "scriptSrc":
			values = scripts
		}
		for _, value := range values {
			if rule.pattern.MatchString(value) {
				out = append(out, Fingerprint{
					Technology: rule.technology, Signal: "database_" + rule.signal,
					Scope: "component", Confidence: "low", Source: rule.source,
					URL: resp.Request.URL.String(),
				})
				break
			}
		}
	}
	return mergeFingerprints(nil, out)
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
