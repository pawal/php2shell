package probe

import (
	"context"
	"html"
	"net/url"
	"regexp"
	"strings"

	"github.com/pawal/php2shell/engine/verdict"
)

// maxPHPInfoBody reaches the session section, which phpinfo() prints late.
const maxPHPInfoBody = 256 << 10

var (
	phpinfoTitle   = regexp.MustCompile(`<title>[^<]*phpinfo\(\)\s*</title>`)
	phpinfoHeading = regexp.MustCompile(`<h1 class="p">PHP Version (\d+\.\d+\.\d+[^\s<]*)\s*</h1>`)
)

// phpinfoRows match the local value of each kept setting.
var phpinfoRows = func() map[string]*regexp.Regexp {
	rows := map[string]*regexp.Regexp{}
	for _, name := range verdict.PHPInfoSettings {
		rows[name] = regexp.MustCompile(`<tr><td class="e">` + regexp.QuoteMeta(name) + `\s*</td><td class="v">([^<]*)</td>`)
	}
	return rows
}()

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

// phpinfoSettings reads the kept settings from phpinfo() output.
func phpinfoSettings(body string) map[string]string {
	settings := map[string]string{}
	for name, row := range phpinfoRows {
		if m := row.FindStringSubmatch(body); m != nil {
			settings[name] = strings.TrimSpace(html.UnescapeString(m[1]))
		}
	}
	if len(settings) == 0 {
		return nil
	}
	return settings
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
