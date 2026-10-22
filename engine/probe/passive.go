package probe

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
