package probe

import (
	"context"
	"net/http"
	"strings"
)

// Passive is what one GET of the start URL shows.
type Passive struct {
	Fingerprints   []Fingerprint     `json:"fingerprints,omitempty"`
	Paths          []string          `json:"discovered_paths,omitempty"`
	Blocked        string            `json:"inspection_blocked,omitempty"`
	Error          string            `json:"error,omitempty"`
	BodyIncomplete bool              `json:"body_incomplete,omitempty"`
	ReadError      string            `json:"read_error,omitempty"`
	FinalURL       string            `json:"final_url"`
	Status         int               `json:"status"`
	Server         string            `json:"server,omitempty"`
	PoweredBy      string            `json:"x_powered_by,omitempty"`
	PHPInfo        string            `json:"phpinfo_version,omitempty"`
	Settings       map[string]string `json:"phpinfo_settings,omitempty"`
	Signature      string            `json:"server_signature,omitempty"`
	Front          []string          `json:"front_layers,omitempty"`
	Platforms      []string          `json:"other_platforms,omitempty"`
	Cookies        []string          `json:"cookies,omitempty"`
	Redirects      []string          `json:"redirects,omitempty"`
	// Stopped is a redirect left unfollowed, off the site or past the limit.
	Stopped string   `json:"redirect_not_followed,omitempty"`
	Hints   []string `json:"php_hints,omitempty"`
}

// fetch follows admitted redirects and collects only passive evidence.
func (s *session) fetch(ctx context.Context, target Target) (Passive, error) {
	return s.fetchPage(ctx, target, true)
}

// fetchPage can stop redirects to keep discovery to one request per endpoint.
func (s *session) fetchPage(ctx context.Context, target Target, follow bool) (Passive, error) {
	out := Passive{FinalURL: target.URL()}
	var poweredBy []string
	client := &http.Client{Transport: s.transport}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.Response != nil {
			out.Hints = append(out.Hints, applicationHints(req.Response, "")...)
			out.Fingerprints = mergeFingerprints(out.Fingerprints, applicationFingerprints(req.Response, ""))
			out.addExternal(s.prober.Fingerprints.Match(req.Response, ""))
			for _, cookie := range req.Response.Cookies() {
				out.Cookies = append(out.Cookies, cookie.Name)
			}
			poweredBy = append(poweredBy, req.Response.Header.Values("X-Powered-By")...)
		}
		stop := func() error { out.Stopped = req.URL.String(); return http.ErrUseLastResponse }
		if len(via) > s.prober.maxRedirects() || !sameSite(target.Host, strings.ToLower(strings.TrimSuffix(req.URL.Hostname(), "."))) {
			return stop()
		}
		if !follow {
			return stop()
		}
		next, err := ParseTarget(req.URL.String())
		if err != nil {
			return stop()
		}
		if err := s.pins.admitPort(next.Host, next.Port); err != nil {
			return err
		}
		if _, err := s.pins.addresses(req.Context(), next.Host); err != nil {
			return err
		}
		out.Redirects = append(out.Redirects, req.URL.String())
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL(), nil)
	if err != nil {
		return out, err
	}
	got, err := s.do(ctx, client, req)
	if err != nil {
		return out, err
	}
	resp, text := got.resp, got.text
	out.BodyIncomplete = !got.complete
	if got.readErr != nil {
		out.ReadError = got.readErr.Error()
	}
	out.FinalURL, out.Status = resp.Request.URL.String(), resp.StatusCode
	out.Server, out.PoweredBy = resp.Header.Get("Server"), resp.Header.Get("X-Powered-By")
	out.Front = frontLayers(resp)
	for _, cookie := range resp.Cookies() {
		out.Cookies = append(out.Cookies, cookie.Name)
	}
	out.Cookies = dedupe(out.Cookies)
	out.Platforms = otherPlatforms(out.Cookies, append(poweredBy, resp.Header.Values("X-Powered-By")...))
	out.Blocked = inspectionBlock(resp, text)
	if out.Blocked == "" {
		out.Hints = dedupe(append(out.Hints, applicationHints(resp, text)...))
		out.Fingerprints = mergeFingerprints(out.Fingerprints, applicationFingerprints(resp, text))
		out.addExternal(s.prober.Fingerprints.Match(resp, text))
		out.Signature = signature(text)
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			out.Paths = discoveredPaths(out.FinalURL, text)
			if out.PHPInfo = phpinfoVersion(text); out.PHPInfo != "" {
				out.Settings = phpinfoSettings(text)
			}
		}
	}
	return out, nil
}

func (p *Passive) addExternal(matches []Fingerprint) {
	p.Fingerprints = mergeFingerprints(p.Fingerprints, matches)
	for _, match := range matches {
		p.Hints = append(p.Hints, match.hint())
	}
	p.Hints = dedupe(p.Hints)
}
