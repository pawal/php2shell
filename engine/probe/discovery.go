package probe

import (
	"context"
	"net/url"
	"path"
	"strings"
	"time"
)

const maxDiscoveryPages = 2
const discoveryTimeout = 3 * time.Second

func phpPath(value string) bool {
	switch strings.ToLower(path.Ext(value)) {
	case ".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml":
		return true
	}
	return false
}

// discoveredPaths selects query-free PHP navigation and form endpoints on one origin.
func discoveredPaths(finalURL, body string) []string {
	base, err := url.Parse(finalURL)
	if err != nil || base.Host == "" {
		return nil
	}
	var paths []string
	seen := map[string]bool{finalURL: true}
	for _, tag := range pageTags(body) {
		attribute := ""
		switch tag.name {
		case "a":
			attribute = "href"
		case "form":
			attribute = "action"
		default:
			continue
		}
		reference, err := url.Parse(strings.TrimSpace(tag.attrs[attribute]))
		if err != nil || reference.String() == "" {
			continue
		}
		candidate := base.ResolveReference(reference)
		if candidate.User != nil || !strings.EqualFold(candidate.Scheme, base.Scheme) || !strings.EqualFold(candidate.Host, base.Host) || candidate.RawQuery != "" || candidate.ForceQuery || !phpPath(candidate.Path) {
			continue
		}
		lower := strings.ToLower(candidate.Path)
		unsafe := false
		for _, word := range []string{"logout", "logoff", "signout", "delete", "remove", "unsubscribe", "activate", "confirm", "install", "upgrade", "reset", "download", "export"} {
			if strings.Contains(lower, word) {
				unsafe = true
				break
			}
		}
		if unsafe {
			continue
		}
		candidate.Fragment, candidate.RawFragment = "", ""
		address := candidate.String()
		if !seen[address] {
			seen[address] = true
			paths = append(paths, address)
			if len(paths) == maxDiscoveryPages {
				break
			}
		}
	}
	return paths
}

// discover reads a bounded, non-recursive set of same-origin endpoints.
func (s *session) discover(ctx context.Context, passive Passive) []Passive {
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	var pages []Passive
	for _, address := range passive.Paths {
		if ctx.Err() != nil {
			break
		}
		target, err := ParseTarget(address)
		if err != nil {
			continue
		}
		page, err := s.fetchPage(ctx, target, false)
		if err != nil {
			page.Error = err.Error()
		}
		pages = append(pages, page)
	}
	return pages
}
