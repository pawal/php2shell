package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Defaults of a Prober left at its zero value.
const (
	DefaultRequestTimeout = 8 * time.Second
	DefaultMaxBody        = 64 << 10
	DefaultMaxRedirects   = 3
	DefaultUserAgent      = "php2shell-check"
)

// Prober performs the network side of a check.
type Prober struct {
	// Resolver looks up host names; nil is the pure Go resolver.
	Resolver Resolver
	// AllowNonGlobal lifts the address and port policy, for a lab.
	AllowNonGlobal bool
	UserAgent      string
	RequestTimeout time.Duration
	MaxBody        int64
	MaxRedirects   int
	Fingerprints   *FingerprintDatabase
}

func (p *Prober) resolver() Resolver {
	if p.Resolver != nil {
		return p.Resolver
	}
	return &net.Resolver{PreferGo: true}
}

func (p *Prober) requestTimeout() time.Duration {
	if p.RequestTimeout > 0 {
		return p.RequestTimeout
	}
	return DefaultRequestTimeout
}

func (p *Prober) maxBody() int64 {
	if p.MaxBody > 0 {
		return p.MaxBody
	}
	return DefaultMaxBody
}

func (p *Prober) maxRedirects() int {
	if p.MaxRedirects > 0 {
		return p.MaxRedirects
	}
	return DefaultMaxRedirects
}

func (p *Prober) userAgent() string {
	if p.UserAgent != "" {
		return p.UserAgent
	}
	return DefaultUserAgent
}

// session is one check's transport, bound to its pinned addresses.
type session struct {
	prober    *Prober
	pins      *pins
	transport *http.Transport
}

func (p *Prober) newSession() *session {
	pinned := newPins(p.resolver(), p.AllowNonGlobal)
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &session{
		prober: p,
		pins:   pinned,
		transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            pinned.dial(dialer),
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:    5 * time.Second,
			ResponseHeaderTimeout:  p.requestTimeout(),
			MaxResponseHeaderBytes: 64 << 10,
			MaxIdleConnsPerHost:    1,
		},
	}
}

func (s *session) close() { s.transport.CloseIdleConnections() }

// do sends one request under the per-request timeout and reads a bounded body.
func (s *session) do(ctx context.Context, client *http.Client, req *http.Request) (*http.Response, string, error) {
	ctx, cancel := context.WithTimeout(ctx, s.prober.requestTimeout())
	defer cancel()
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", s.prober.userAgent())
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", unwrapURLError(err)
	}
	defer resp.Body.Close()
	limit := s.prober.maxBody()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	// phpinfo() output may pass the cap before its session section.
	if err == nil && int64(len(body)) == limit && limit < maxPHPInfoBody && phpinfoVersion(string(body)) != "" {
		rest, _ := io.ReadAll(io.LimitReader(resp.Body, maxPHPInfoBody-limit))
		body = append(body, rest...)
	}
	if err != nil && len(body) == 0 {
		return resp, "", unwrapURLError(err)
	}
	return resp, string(body), nil
}

// unwrapURLError surfaces a policy refusal from inside the transport.
func unwrapURLError(err error) error {
	var policy *PolicyError
	if errors.As(err, &policy) {
		return policy
	}
	if errors.Is(err, ErrUnresolvable) {
		return err
	}
	var urlErr interface{ Unwrap() error }
	if errors.As(err, &urlErr) {
		if inner := urlErr.Unwrap(); inner != nil {
			return inner
		}
	}
	return err
}

// sameSite admits a redirect within the target's host, a parent or a child of it.
func sameSite(from, to string) bool {
	from, to = strings.ToLower(from), strings.ToLower(to)
	if from == to {
		return true
	}
	if !strings.Contains(from, ".") || !strings.Contains(to, ".") {
		return false
	}
	return strings.HasSuffix(from, "."+to) || strings.HasSuffix(to, "."+from)
}
