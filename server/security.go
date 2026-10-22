package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// Content security policies. An API response is not a document, so nothing may
// load from it at all; the UI loads its own assets and nothing else.
const (
	apiCSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
	uiCSP  = "default-src 'self'; script-src 'self'; style-src 'self'; " +
		"img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; " +
		"base-uri 'none'; form-action 'self'"
)

// forwardedHeaders are the hop claims an untrusted peer may not make.
var forwardedHeaders = []string{
	"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-Ip",
}

// errCSRFOrigin is returned when a state-changing request comes from elsewhere.
var errCSRFOrigin = errors.New("the origin must match the request host")

// parsePrefixes reads the trusted-proxy list.
func parsePrefixes(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, text := range list {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(text))
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %w", text, err)
		}
		out = append(out, prefix)
	}
	return out, nil
}

func inPrefixes(addr netip.Addr, prefixes []netip.Prefix) bool {
	addr = addr.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// peerAddress is the transport peer, whatever it claims to forward for.
func peerAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return host
}

// clientAddress is the address a limit is counted against: the peer, unless it
// is a trusted proxy, in which case the rightmost untrusted forwarded hop.
func clientAddress(r *http.Request, trusted []netip.Prefix) string {
	host := peerAddress(r)
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	if !inPrefixes(peer, trusted) {
		return peer.Unmap().String()
	}
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if hop == "" {
			continue
		}
		addr, err := netip.ParseAddr(hop)
		if err != nil {
			return hop
		}
		if !inPrefixes(addr, trusted) {
			return addr.Unmap().String()
		}
	}
	return peer.Unmap().String()
}

// requestScheme honours a forwarded protocol only from a trusted proxy.
func requestScheme(r *http.Request, trusted []netip.Prefix) string {
	if r.TLS != nil {
		return "https"
	}
	peer, err := netip.ParseAddr(peerAddress(r))
	if err == nil && inPrefixes(peer, trusted) {
		if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
			return "https"
		}
	}
	return "http"
}

// checkOrigin compares Origin against the request's own host. A client that
// sends no Origin is not a browser and is left alone.
func checkOrigin(r *http.Request, trusted []netip.Prefix) error {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return nil
	}
	if strings.EqualFold(origin, "null") {
		return errCSRFOrigin
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return errCSRFOrigin
	}
	originHost, originPort := hostPort(parsed.Host, parsed.Scheme)
	requestHost, requestPort := hostPort(r.Host, requestScheme(r, trusted))
	if originHost == "" || requestHost == "" {
		return errCSRFOrigin
	}
	if !strings.EqualFold(originHost, requestHost) || originPort != requestPort {
		return errCSRFOrigin
	}
	return nil
}

// hostPort splits an authority, filling in the scheme's default port.
func hostPort(authority, scheme string) (string, string) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(authority))
	if err != nil {
		host, port = strings.TrimSpace(authority), ""
	}
	host = strings.Trim(host, "[]")
	if addr, err := netip.ParseAddr(host); err == nil {
		host = addr.Unmap().String()
	}
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return strings.ToLower(host), port
}
