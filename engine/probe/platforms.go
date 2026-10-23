package probe

import "strings"

// platformSignals are other platforms' documented defaults, cookie names or X-Powered-By prefixes.
var platformSignals = []struct{ platform, cookie, poweredBy string }{
	{platform: "Java", cookie: "JSESSIONID"},
	{platform: "Play Framework", cookie: "PLAY_SESSION"},
	{platform: "Play Framework", cookie: "PLAY_FLASH"},
	{platform: "ASP.NET", cookie: "ASP.NET_SessionId"},
	{platform: "Express", cookie: "connect.sid"},
	{platform: "Express", poweredBy: "Express"},
	{platform: "Next.js", poweredBy: "Next.js"},
	{platform: "Django", cookie: "csrftoken"},
}

// otherPlatforms names the non-PHP platforms whose defaults the answers carry, with the first signal of each.
func otherPlatforms(cookies, poweredBy []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, signal := range platformSignals {
		if seen[signal.platform] {
			continue
		}
		found := ""
		for _, name := range cookies {
			if signal.cookie != "" && name == signal.cookie {
				found = signal.cookie + " cookie"
			}
		}
		for _, value := range poweredBy {
			if signal.poweredBy != "" && strings.HasPrefix(value, signal.poweredBy) {
				found = "X-Powered-By " + signal.poweredBy
			}
		}
		if found != "" {
			seen[signal.platform] = true
			out = append(out, signal.platform+" ("+found+")")
		}
	}
	return out
}
