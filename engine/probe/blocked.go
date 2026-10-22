package probe

import (
	"net/http"
	"regexp"
	"strings"
)

var pageTitle = regexp.MustCompile(`(?is)<title\b[^>]*>\s*([^<]*)\s*</title>`)

// inspectionBlock identifies an intercepted response without treating it as PHP evidence.
func inspectionBlock(resp *http.Response, body string) string {
	if strings.EqualFold(resp.Header.Get("Cf-Mitigated"), "challenge") {
		return "Cloudflare challenge"
	}
	lower := strings.ToLower(body)
	title := ""
	if match := pageTitle.FindStringSubmatch(body); match != nil {
		title = strings.ToLower(strings.TrimSpace(match[1]))
	}
	if (title == "just a moment..." || title == "attention required! | cloudflare") && strings.Contains(lower, "/cdn-cgi/challenge-platform/") {
		return "Cloudflare challenge"
	}
	if title == "one moment, please..." && strings.Contains(lower, "wsidchk") && strings.Contains(lower, "<script") {
		return "JavaScript bot challenge"
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return "HTTP 401 authentication required"
	case http.StatusForbidden:
		return "HTTP 403 access denied"
	case http.StatusTooManyRequests:
		return "HTTP 429 rate limited"
	}
	return ""
}
