package probe

import "regexp"

var (
	phpinfoTitle   = regexp.MustCompile(`<title>[^<]*phpinfo\(\)\s*</title>`)
	phpinfoHeading = regexp.MustCompile(`<h1 class="p">PHP Version (\d+\.\d+\.\d+[^\s<]*)\s*</h1>`)
)

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
