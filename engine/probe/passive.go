package probe

import (
	"context"
	"net/http"
	"strings"
)

// Passive is what one GET of the start URL shows.
type Passive struct {
	FinalURL  string   `json:"final_url"`
	Status    int      `json:"status"`
	Server    string   `json:"server,omitempty"`
	PoweredBy string   `json:"x_powered_by,omitempty"`
	Cookies   []string `json:"cookies,omitempty"`
	Redirects []string `json:"redirects,omitempty"`
	// Stopped is a redirect left unfollowed, off the site or past the limit.
	Stopped string   `json:"redirect_not_followed,omitempty"`
	Hints   []string `json:"php_hints,omitempty"`
}

// fetch follows admitted redirects and collects only passive evidence.
func (s *session) fetch(ctx context.Context, target Target) (Passive, error) {
	out := Passive{FinalURL: target.URL()}
	client := &http.Client{Transport: s.transport}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		stop := func() error { out.Stopped = req.URL.String(); return http.ErrUseLastResponse }
		if len(via) > s.prober.maxRedirects() || !sameSite(target.Host, strings.ToLower(strings.TrimSuffix(req.URL.Hostname(), "."))) {
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
	resp, text, err := s.do(ctx, client, req)
	if err != nil {
		return out, err
	}
	out.FinalURL, out.Status = resp.Request.URL.String(), resp.StatusCode
	out.Server, out.PoweredBy = resp.Header.Get("Server"), resp.Header.Get("X-Powered-By")
	for _, cookie := range resp.Cookies() {
		out.Cookies = append(out.Cookies, cookie.Name)
	}
	out.Hints = applicationHints(resp, text)
	return out, nil
}
