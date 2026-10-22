package probe

import (
	"net/http"
	"regexp"
	"strings"
)

// fastlyNode is one X-Served-By entry in the format Fastly documents.
var fastlyNode = regexp.MustCompile(`(?:^|,\s*)cache-[a-z]+[0-9]+-[A-Z]+\b`)

// frontLayers names the CDNs, firewalls and caches that show themselves in a response.
func frontLayers(resp *http.Response) []string {
	h := resp.Header
	via := strings.Join(h.Values("Via"), ", ")
	server := h.Get("Server")
	fastly := fastlyNode.MatchString(strings.Join(h.Values("X-Served-By"), ", "))
	var layers []string
	add := func(seen bool, name string) {
		if seen {
			layers = append(layers, name)
		}
	}
	add(h.Get("Cf-Ray") != "", "Cloudflare")
	add(h.Get("X-Amz-Cf-Id") != "" || strings.Contains(via, "(CloudFront)"), "Amazon CloudFront")
	add(fastly, "Fastly")
	add(strings.Contains(server, "AkamaiGHost") || h.Get("Akamai-Grn") != "", "Akamai")
	add(h.Get("X-Azure-Ref") != "", "Azure Front Door")
	add(h.Get("X-Sucuri-Id") != "" || strings.HasPrefix(server, "Sucuri/"), "Sucuri")
	// Fastly runs on Varnish and sends X-Varnish too.
	add(h.Get("X-Varnish") != "" && !fastly, "Varnish")
	if len(layers) == 0 && via != "" {
		layers = append(layers, "a proxy")
	}
	return layers
}
