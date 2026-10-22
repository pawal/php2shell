package probe

import (
	"net/http"
	"regexp"
	"strings"
)

// Markers only PHP applications leave in a page.
var bodyMarkers = []struct{ needle, hint string }{
	{"/wp-content/", "WordPress assets"},
	{"/wp-includes/", "WordPress assets"},
	{"/wp-json/", "WordPress REST API"},
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
	"OpenCart", "MediaWiki", "phpBB", "Elementor", "WooCommerce", "Craft CMS",
	"concrete5", "Grav", "Kirby", "October CMS", "SilverStripe", "Contao",
}

// Session cookie names only PHP applications set.
var cookieHints = []struct{ name, hint string }{
	{"phpsessid", "PHPSESSID cookie"},
	{"wordpress_test_cookie", "WordPress cookie"},
	{"wp-settings-", "WordPress cookie"},
	{"wordpress_logged_in_", "WordPress cookie"},
	{"laravel_session", "Laravel cookie"},
	{"ci_session", "CodeIgniter cookie"},
	{"fe_typo_user", "TYPO3 cookie"},
	{"prestashop-", "PrestaShop cookie"},
}

var (
	drupalSession = regexp.MustCompile(`^S?SESS[0-9a-f]{32}$`)
	generatorMeta = regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']([^"']+)["']`)
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
			if strings.HasPrefix(name, c.name) {
				hints = append(hints, c.hint)
			}
		}
		if drupalSession.MatchString(cookie.Name) {
			hints = append(hints, "Drupal cookie")
		}
	}
	if strings.HasSuffix(strings.ToLower(resp.Request.URL.Path), ".php") {
		hints = append(hints, ".php final URL")
	}
	for _, m := range bodyMarkers {
		if strings.Contains(body, m.needle) {
			hints = append(hints, m.hint)
		}
	}
	if m := generatorMeta.FindStringSubmatch(body); m != nil {
		for _, app := range generatorApps {
			if strings.HasPrefix(strings.ToLower(m[1]), strings.ToLower(app)) {
				hints = append(hints, "generator "+app)
				break
			}
		}
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
