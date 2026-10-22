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

//go:embed applications.json
var applicationCatalogueJSON []byte

// Fingerprint is a sourced indication of an application, framework or component.
type Fingerprint struct {
	Technology string `json:"technology"`
	Signal     string `json:"signal"`
	Scope      string `json:"scope"`
	Confidence string `json:"confidence"`
	Source     string `json:"source"`
	URL        string `json:"url"`
}

type technologySpec struct {
	Category       string              `json:"category,omitempty"`
	Technology     string              `json:"technology"`
	References     []string            `json:"references,omitempty"`
	EmitsGenerator bool                `json:"emits_generator,omitempty"`
	Aliases        []string            `json:"aliases"`
	Diagnostics    []string            `json:"diagnostics"`
	Confidence     string              `json:"confidence"`
	Source         string              `json:"source"`
	Cookies        []cookieFingerprint `json:"cookies,omitempty"`
	Assets         []assetFingerprint  `json:"assets,omitempty"`
	Markup         []markupFingerprint `json:"markup,omitempty"`
	Headers        []headerFingerprint `json:"headers,omitempty"`
}

type cookieFingerprint struct {
	Pattern    string `json:"pattern,omitempty"`
	compiled   *regexp.Regexp
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
	Tag        string   `json:"tag,omitempty"`
	Names      []string `json:"names"`
	Confidence string   `json:"confidence"`
	Source     string   `json:"source"`
}

type markupFingerprint struct {
	Container  *elementFingerprint `json:"container,omitempty"`
	closing    *regexp.Regexp
	Elements   []elementFingerprint `json:"elements"`
	Confidence string               `json:"confidence"`
	Source     string               `json:"source"`
}

type elementFingerprint struct {
	Tag        string            `json:"tag"`
	Attributes map[string]string `json:"attributes"`
	compiled   map[string]*regexp.Regexp
}

var frameworkCatalogue = loadCatalogue(frameworkCatalogueJSON)
var applicationCatalogue = loadCatalogue(applicationCatalogueJSON)
var fingerprintCatalogue = append(append([]technologySpec(nil), frameworkCatalogue...), applicationCatalogue...)

// CatalogueTechnologies names the built-in applications and frameworks.
func CatalogueTechnologies() []string {
	names := make([]string, 0, len(fingerprintCatalogue))
	for _, spec := range fingerprintCatalogue {
		names = append(names, spec.Technology)
	}
	return names
}

func loadCatalogue(data []byte) []technologySpec {
	var specs []technologySpec
	if err := json.Unmarshal(data, &specs); err != nil {
		panic(fmt.Sprintf("invalid fingerprint catalogue: %v", err))
	}
	for i := range specs {
		for j := range specs[i].Cookies {
			rule := &specs[i].Cookies[j]
			if rule.Pattern != "" {
				rule.compiled = regexp.MustCompile(rule.Pattern)
			}
		}
		for j := range specs[i].Markup {
			rule := &specs[i].Markup[j]
			if rule.Container != nil {
				compileElement(rule.Container)
				rule.closing = regexp.MustCompile(`(?i)</` + regexp.QuoteMeta(rule.Container.Tag) + `\s*>`)
			}
			for k := range rule.Elements {
				compileElement(&rule.Elements[k])
			}
		}
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
	return matchFingerprints(resp, body, frameworkCatalogue)
}

func applicationFingerprints(resp *http.Response, body string) []Fingerprint {
	return matchFingerprints(resp, body, fingerprintCatalogue)
}

func matchFingerprints(resp *http.Response, body string, catalogue []technologySpec) []Fingerprint {
	if inspectionBlock(resp, body) != "" {
		return nil
	}
	var matches []Fingerprint
	address := resp.Request.URL.String()
	cookies := map[string]bool{}
	for _, cookie := range resp.Cookies() {
		cookies[cookie.Name] = true
	}
	assets := map[string]map[string]bool{"script": {}, "link": {}}
	var generators []string
	tags := pageTags(body)
	for _, tag := range tags {
		attribute := ""
		if tag.name == "script" {
			attribute = "src"
		}
		if tag.name == "link" && strings.EqualFold(tag.attrs["rel"], "stylesheet") {
			attribute = "href"
		}
		if attribute != "" {
			if address, err := url.Parse(tag.attrs[attribute]); err == nil && (address.Scheme == "" || address.Scheme == "http" || address.Scheme == "https") {
				assets[tag.name][address.Path] = true
			}
		}
		if tag.name == "meta" && strings.EqualFold(tag.attrs["name"], "generator") {
			generators = append(generators, tag.attrs["content"])
		}
	}
	diagnostic := strings.ReplaceAll(html.UnescapeString(body), `\\`, `\`)
	lower := strings.ToLower(diagnostic)
	errorPage := resp.StatusCode >= 500 && resp.StatusCode <= 599 && (strings.Contains(lower, "exception") || strings.Contains(lower, "stack trace") || strings.Contains(lower, "fatal error"))
	for _, spec := range catalogue {
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
			matched := rule.Name != "" && cookies[rule.Name]
			if rule.compiled != nil {
				for name := range cookies {
					matched = matched || rule.compiled.MatchString(name)
				}
			}
			if matched {
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
			tag := rule.Tag
			if tag == "" {
				tag = "script"
			}
			matched := len(rule.Names) > 0
			for _, name := range rule.Names {
				found := false
				for asset := range assets[tag] {
					if !strings.Contains(name, "/") {
						found = found || path.Base(asset) == name
					} else {
						found = found || asset == name || strings.HasSuffix(asset, "/"+name)
					}
				}
				matched = matched && found
			}
			if matched {
				add("assets", "component", rule.Confidence, rule.Source)
			}
		}
		for _, rule := range spec.Markup {
			if matchesMarkup(rule, tags, body) {
				add("markup", "component", rule.Confidence, rule.Source)
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

func compileElement(element *elementFingerprint) {
	element.compiled = map[string]*regexp.Regexp{}
	for name, pattern := range element.Attributes {
		element.compiled[name] = regexp.MustCompile(pattern)
	}
}

func matchesElement(element elementFingerprint, tag htmlTag) bool {
	if tag.name != element.Tag {
		return false
	}
	for name, pattern := range element.compiled {
		value, present := tag.attrs[name]
		if !present || !pattern.MatchString(value) {
			return false
		}
	}
	return true
}

func matchesMarkup(rule markupFingerprint, tags []htmlTag, body string) bool {
	groups := [][]htmlTag{tags}
	if rule.Container != nil {
		groups = nil
		for _, tag := range tags {
			if !matchesElement(*rule.Container, tag) {
				continue
			}
			if end := rule.closing.FindStringIndex(body[tag.end:]); end != nil {
				groups = append(groups, pageTags(body[tag.start:tag.end+end[1]]))
			}
		}
	}
	for _, group := range groups {
		matched := len(rule.Elements) > 0
		for _, element := range rule.Elements {
			found := false
			for _, tag := range group {
				found = found || matchesElement(element, tag)
			}
			matched = matched && found
		}
		if matched {
			return true
		}
	}
	return false
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
