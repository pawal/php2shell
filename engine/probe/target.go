package probe

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Target is a normalised website address.
type Target struct {
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Port   string `json:"port"`
	Path   string `json:"path"`
}

// ErrInvalidTarget wraps every refusal of the input grammar.
var ErrInvalidTarget = errors.New("invalid target")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidTarget, fmt.Sprintf(format, args...))
}

// ParseTarget reads a host name, an address or an http(s) URL; https is the
// default scheme and the path defaults to /.
func ParseTarget(input string) (Target, error) {
	text := strings.TrimSpace(input)
	if text == "" {
		return Target{}, invalid("empty")
	}
	if len(text) > 2048 {
		return Target{}, invalid("longer than 2048 characters")
	}
	if !strings.Contains(text, "://") {
		text = "https://" + text
	}
	u, err := url.Parse(text)
	if err != nil {
		return Target{}, invalid("not a URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return Target{}, invalid("scheme %q is not http or https", u.Scheme)
	}
	if u.User != nil {
		return Target{}, invalid("user information is not accepted")
	}
	if u.Opaque != "" {
		return Target{}, invalid("not a URL")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if err := checkHost(host); err != nil {
		return Target{}, err
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[scheme]
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return Target{}, invalid("port %q is not a port number", port)
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return Target{Scheme: scheme, Host: host, Port: port, Path: path}, nil
}

// checkHost admits an IP literal or a multi-label LDH name whose last label
// is not numeric, so no integer or dotted shorthand passes as a name.
func checkHost(host string) error {
	if host == "" {
		return invalid("no host")
	}
	if strings.Contains(host, "%") {
		return invalid("scoped addresses are not accepted")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	if len(host) > 253 {
		return invalid("host name longer than 253 characters")
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return invalid("%q is not a public domain name", host)
	}
	for _, label := range labels {
		if err := checkLabel(label); err != nil {
			return err
		}
	}
	if numeric(labels[len(labels)-1]) {
		return invalid("%q is not a public domain name", host)
	}
	return nil
}

// numeric reports a decimal or 0x label, which no top-level domain is.
func numeric(label string) bool {
	if _, err := strconv.ParseUint(label, 10, 64); err == nil {
		return true
	}
	return strings.HasPrefix(label, "0x")
}

func checkLabel(label string) error {
	if label == "" || len(label) > 63 {
		return invalid("a label is empty or longer than 63 characters")
	}
	for _, c := range label {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		case c > 127:
			return invalid("non-ASCII names must be given in their xn-- form")
		default:
			return invalid("%q is not a valid host name character", c)
		}
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return invalid("a label starts or ends with a hyphen")
	}
	return nil
}

// Origin is scheme, host and port as a URL prefix.
func (t Target) Origin() string {
	host := t.Host
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
		host = "[" + host + "]"
	}
	if (t.Scheme == "https" && t.Port == "443") || (t.Scheme == "http" && t.Port == "80") {
		return t.Scheme + "://" + host
	}
	return t.Scheme + "://" + net.JoinHostPort(t.Host, t.Port)
}

// URL is the target's start address.
func (t Target) URL() string {
	return t.Origin() + t.Path
}
