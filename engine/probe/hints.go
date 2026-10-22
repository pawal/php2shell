package probe

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Application artifacts are hints, not proof of the runtime serving a path.
var bodyMarkers = []struct{ needle, hint string }{
	{"/wp-content/", "WordPress assets"},
	{"/wp-includes/", "WordPress assets"},
	{"/wp-json/", "WordPress REST API"},
	{"/vbulletin-core.js", "vBulletin assets"},
	{"/vbulletin_global.js", "vBulletin assets"},
	{"/sites/default/files/", "Drupal assets"},
	{"drupal-settings-json", "Drupal settings"},
	{"/media/system/js/", "Joomla assets"},
	{"/typo3conf/", "TYPO3 assets"},
	{"/typo3temp/", "TYPO3 assets"},
	{"/modules/prestashop", "PrestaShop assets"},
	{"/static/frontend/Magento", "Magento assets"},
}

// Generators that are PHP applications, matched at the start of the content.
var generatorApps = []string{
	"WordPress", "Drupal", "Joomla", "TYPO3", "PrestaShop", "Magento", "Shopware",
	"OpenCart", "MediaWiki", "phpBB", "vBulletin", "Elementor", "WooCommerce", "Craft CMS",
	"concrete5", "Grav", "Kirby", "October CMS", "SilverStripe", "Contao",
}

// Default session cookie names used by PHP applications.
var cookieHints = []struct{ name, hint string }{
	{"phpsessid", "PHPSESSID cookie"},
	{"bb_sessionhash", "vBulletin cookie"},
	{"wordpress_test_cookie", "WordPress cookie"},
	{"wp-settings-", "WordPress cookie"},
	{"wordpress_logged_in_", "WordPress cookie"},
	{"fe_typo_user", "TYPO3 cookie"},
	{"prestashop-", "PrestaShop cookie"},
}

var (
	drupalSession = regexp.MustCompile(`^S?SESS[0-9a-f]{32}$`)
	// PHP hosts that name themselves in X-Powered-By instead of PHP.
	poweredByHosts = []string{"wp engine", "pressable", "kinsta"}
)

// applicationHints reads the headers, the cookies and the body for signs of
// a PHP application, so a site that hides its version is still recognised.
func applicationHints(resp *http.Response, body string) []string {
	var hints []string
	lower := strings.ToLower(resp.Header.Get("Server") + " " + resp.Header.Get("X-Powered-By"))
	if strings.Contains(lower, "php") {
		hints = append(hints, "PHP header")
	}
	for _, host := range poweredByHosts {
		if strings.Contains(lower, host) {
			hints = append(hints, "PHP host header")
		}
	}
	for _, link := range resp.Header.Values("Link") {
		if strings.Contains(link, "api.w.org") {
			hints = append(hints, "WordPress REST API link")
		}
	}
	for _, cookie := range resp.Cookies() {
		name := strings.ToLower(cookie.Name)
		for _, c := range cookieHints {
			if name == c.name || (strings.HasSuffix(c.name, "_") || strings.HasSuffix(c.name, "-")) && strings.HasPrefix(name, c.name) {
				hints = append(hints, c.hint)
			}
		}
		if drupalSession.MatchString(cookie.Name) {
			hints = append(hints, "Drupal cookie")
		}
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && phpPath(resp.Request.URL.Path) {
		hints = append(hints, "PHP extension in final URL")
	}
	for _, m := range bodyMarkers {
		if strings.Contains(body, m.needle) {
			hints = append(hints, m.hint)
		}
	}
	for _, key := range []string{"X-Generator", "X-Powered-By"} {
		if app := generatorApp(resp.Header.Get(key)); app != "" {
			hints = append(hints, key+" "+app)
		}
	}
	for _, tag := range pageTags(body) {
		attribute := ""
		if tag.name == "a" {
			attribute = "href"
		}
		if tag.name == "form" {
			attribute = "action"
		}
		if attribute != "" {
			if reference, err := url.Parse(strings.TrimSpace(tag.attrs[attribute])); err == nil && reference.String() != "" {
				endpoint := resp.Request.URL.ResolveReference(reference)
				if endpoint.User == nil && strings.EqualFold(endpoint.Scheme, resp.Request.URL.Scheme) && strings.EqualFold(endpoint.Host, resp.Request.URL.Host) && phpPath(endpoint.Path) {
					hints = append(hints, "PHP endpoint in page")
				}
			}
		}

		if tag.name == "meta" && strings.EqualFold(tag.attrs["name"], "generator") {
			if app := generatorApp(tag.attrs["content"]); app != "" {
				hints = append(hints, "generator "+app)
			}
		}
	}
	if phpDiagnostic.MatchString(body) {
		hints = append(hints, "PHP diagnostic")
	}
	if resp.Header.Get("Php-Warning") != "" {
		hints = append(hints, "PHP warning header")
	}

	for _, fingerprint := range applicationFingerprints(resp, body) {
		hints = append(hints, fingerprint.hint())
	}
	return dedupe(hints)
}

func dedupe(items []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}

var phpDiagnostic = regexp.MustCompile(`(?is)(?:PHP (?:Warning|Fatal error|Parse error|Notice):|<(?:b|strong)>(?:Warning|Fatal error|Parse error|Notice)</(?:b|strong)>:)[^\r\n]{0,1000}\.php(?:</b>)? (?:on line|:)[^\r\n]{0,32}[0-9]`)

func generatorApp(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, app := range generatorApps {
		if rest, ok := strings.CutPrefix(value, strings.ToLower(app)); ok {
			if rest == "" || strings.ContainsAny(rest[:1], " /;(-0123456789") {
				return app
			}
		}
	}
	return ""
}
