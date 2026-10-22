package probe

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
)

//go:embed frameworks.json
var frameworkCatalogueJSON []byte

// Fingerprint is a sourced indication of a framework or one of its components.
type Fingerprint struct {
	Technology string `json:"technology"`
	Signal     string `json:"signal"`
	Scope      string `json:"scope"`
	Confidence string `json:"confidence"`
	Source     string `json:"source"`
	URL        string `json:"url"`
}

type frameworkSpec struct {
	Technology  string              `json:"technology"`
	Aliases     []string            `json:"aliases"`
	Diagnostics []string            `json:"diagnostics"`
	Confidence  string              `json:"confidence"`
	Source      string              `json:"source"`
	Cookies     []cookieFingerprint `json:"cookies,omitempty"`
	Assets      []assetFingerprint  `json:"assets,omitempty"`
	Headers     []headerFingerprint `json:"headers,omitempty"`
}

type cookieFingerprint struct {
	Name       string `json:"name"`
	Confidence string `json:"confidence"`
	Source     string `json:"source"`
}

type headerFingerprint struct {
	Name       string   `json:"name"`
	Pattern    string   `json:"pattern"`
	Requires   []string `json:"requires"`
	Scope      string   `json:"scope"`
	Confidence string   `json:"confidence"`
	Source     string   `json:"source"`
	compiled   *regexp.Regexp
}

type assetFingerprint struct {
	Names      []string `json:"names"`
	Confidence string   `json:"confidence"`
	Source     string   `json:"source"`
}

var frameworkCatalogue = loadFrameworkCatalogue()

func loadFrameworkCatalogue() []frameworkSpec {
	var specs []frameworkSpec
	if err := json.Unmarshal(frameworkCatalogueJSON, &specs); err != nil {
		panic(fmt.Sprintf("invalid framework catalogue: %v", err))
	}
	for i := range specs {
		for j := range specs[i].Headers {
			specs[i].Headers[j].compiled = regexp.MustCompile(specs[i].Headers[j].Pattern)
		}
	}
	return specs
}

func declaredTechnology(value, alias string) bool {
	rest, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(value)), strings.ToLower(alias))
	return ok && (rest == "" || strings.ContainsAny(rest[:1], " /;(-+0123456789"))
}

// frameworkFingerprints inspect existing responses without requesting diagnostic URLs.
func frameworkFingerprints(resp *http.Response, body string) []Fingerprint {
	if inspectionBlock(resp, body) != "" {
		return nil
	}
	var matches []Fingerprint
	address := resp.Request.URL.String()
	cookies := map[string]bool{}
	for _, cookie := range resp.Cookies() {
		cookies[cookie.Name] = true
	}
	assets := map[string]bool{}
	var generators []string
	for _, tag := range pageTags(body) {
		if tag.name == "script" {
			if address, err := url.Parse(tag.attrs["src"]); err == nil && (address.Scheme == "" || address.Scheme == "http" || address.Scheme == "https") {
				assets[path.Base(address.Path)] = true
			}
		}
		if tag.name == "meta" && strings.EqualFold(tag.attrs["name"], "generator") {
			generators = append(generators, tag.attrs["content"])
		}
	}
	diagnostic := strings.ReplaceAll(html.UnescapeString(body), `\\`, `\`)
	lower := strings.ToLower(diagnostic)
	errorPage := resp.StatusCode >= 500 && resp.StatusCode <= 599 && (strings.Contains(lower, "exception") || strings.Contains(lower, "stack trace") || strings.Contains(lower, "fatal error"))
	for _, spec := range frameworkCatalogue {
		add := func(signal, scope, confidence, source string) {
			matches = append(matches, Fingerprint{Technology: spec.Technology, Signal: signal, Scope: scope, Confidence: confidence, Source: source, URL: address})
		}
		for _, key := range []string{"X-Powered-By", "X-Generator"} {
			for _, alias := range spec.Aliases {
				if declaredTechnology(resp.Header.Get(key), alias) {
					add(key, "declared", spec.Confidence, spec.Source)
					break
				}
			}
		}
		for _, generator := range generators {
			for _, alias := range spec.Aliases {
				if declaredTechnology(generator, alias) {
					add("generator", "declared", spec.Confidence, spec.Source)
					break
				}
			}
		}
		for _, rule := range spec.Cookies {
			if cookies[rule.Name] {
				add("cookie", "default_cookie", rule.Confidence, rule.Source)
			}
		}
		for _, rule := range spec.Headers {
			matched := rule.compiled.MatchString(resp.Header.Get(rule.Name))
			for _, key := range rule.Requires {
				matched = matched && resp.Header.Get(key) != ""
			}
			if matched {
				add(rule.Name, rule.Scope, rule.Confidence, rule.Source)
			}
		}
		for _, rule := range spec.Assets {
			matched := len(rule.Names) > 0
			for _, name := range rule.Names {
				matched = matched && assets[name]
			}
			if matched {
				add("assets", "component", rule.Confidence, rule.Source)
			}
		}
		if errorPage {
			for _, name := range spec.Diagnostics {
				if containsClass(diagnostic, name) {
					add("diagnostic", "component", spec.Confidence, spec.Source)
					break
				}
			}
		}
	}
	return mergeFingerprints(nil, matches)
}

func containsClass(body, name string) bool {
	for offset := 0; offset < len(body); {
		index := strings.Index(body[offset:], name)
		if index < 0 {
			return false
		}
		index += offset
		end := index + len(name)
		boundary := func(c byte) bool {
			return !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '\\')
		}
		before := index == 0 || boundary(body[index-1])
		prefix := strings.HasSuffix(name, `\`) || strings.HasSuffix(name, "_")
		if prefix {
			if before && end < len(body) && ((body[end] >= 'a' && body[end] <= 'z') || (body[end] >= 'A' && body[end] <= 'Z') || body[end] == '_') {
				return true
			}
		} else if before && (end == len(body) || boundary(body[end])) {
			return true
		}

		offset = end
	}
	return false
}

func (f Fingerprint) hint() string {
	if f.Signal == "generator" {
		return "generator " + f.Technology
	}
	if f.Signal == "diagnostic" {
		return f.Technology + " diagnostic component"
	}
	if f.Signal == "cookie" {
		return f.Technology + " cookie"
	}
	return f.Technology + " " + f.Signal
}

func mergeFingerprints(existing, added []Fingerprint) []Fingerprint {
	seen := map[Fingerprint]bool{}
	var out []Fingerprint
	for _, list := range [][]Fingerprint{existing, added} {
		for _, fingerprint := range list {
			if !seen[fingerprint] {
				seen[fingerprint] = true
				out = append(out, fingerprint)
			}
		}
	}
	return out
}
