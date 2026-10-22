package probe

import (
	"context"
	"net/url"
	"regexp"
)

var (
	phpinfoTitle   = regexp.MustCompile(`<title>[^<]*phpinfo\(\)\s*</title>`)
	phpinfoHeading = regexp.MustCompile(`<h1 class="p">PHP Version (\d+\.\d+\.\d+[^\s<]*)\s*</h1>`)
)

// phpinfoPaths are the conventional names of a phpinfo() page, asked for only on attestation.
var phpinfoPaths = []string{"/phpinfo.php", "/info.php"}

// phpinfoVersion reads the version phpinfo() output shows, which expose_php does not hide.
func phpinfoVersion(body string) string {
	if !phpinfoTitle.MatchString(body) {
		return ""
	}
	if m := phpinfoHeading.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	return ""
}

// findPHPInfo asks for the conventional pages on the final origin until one is phpinfo() or blocked.
func (s *session) findPHPInfo(ctx context.Context, passive Passive) []Passive {
	base, err := url.Parse(passive.FinalURL)
	if err != nil || base.Host == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	var pages []Passive
	for _, name := range phpinfoPaths {
		if ctx.Err() != nil {
			break
		}
		target, err := ParseTarget(base.ResolveReference(&url.URL{Path: name}).String())
		if err != nil {
			continue
		}
		page, err := s.fetchPage(ctx, target, false)
		if err != nil {
			page.Error = err.Error()
		}
		pages = append(pages, page)
		if page.PHPInfo != "" || page.Blocked != "" {
			break
		}
	}
	return pages
}
