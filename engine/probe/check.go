package probe

import (
	"context"
	"errors"
	"net/url"

	"github.com/pawal/php2shell/engine/verdict"
)

// Evidence records the observations behind a check.
type Evidence struct {
	Passive  Passive             `json:"passive"`
	Pages    []Passive           `json:"discovery,omitempty"`
	PHPInfo  []Passive           `json:"phpinfo_requests,omitempty"`
	Requests []OracleObservation `json:"oracle_requests,omitempty"`
}

// Check admits the target under the address policy, then runs the checks.
func (p *Prober) Check(ctx context.Context, target Target, oracle bool) (verdict.Input, any, error) {
	s := p.newSession()
	defer s.close()
	in := verdict.Input{Oracle: verdict.OracleNotRun}
	evidence := Evidence{}
	if err := s.pins.admitPort(target.Host, target.Port); err != nil {
		return in, evidence, err
	}
	if _, err := s.pins.addresses(ctx, target.Host); err != nil {
		return in, evidence, err
	}
	passive, err := s.fetch(ctx, target)
	evidence.Passive = passive
	if err != nil {
		var policy *PolicyError
		if errors.As(err, &policy) || errors.Is(err, ErrUnresolvable) || ctx.Err() != nil {
			return in, evidence, err
		}
		return in, evidence, nil
	}
	in.Reachable = true
	in.PoweredBy, in.Server, in.Hints = passive.PoweredBy, passive.Server, passive.Hints
	in.PHPInfo, in.PHPInfoSettings = passive.PHPInfo, passive.Settings
	in.Sightings = pageSightings(passive)
	in.Front = passive.Front
	in.InspectionBlocked = passive.Blocked
	if passive.Blocked != "" {
		return in, evidence, nil
	}
	evidence.Pages = s.discover(ctx, passive)
	oraclePage := passive
	oraclePage.Paths = nil
	discoveryBlocked := ""
	for _, page := range evidence.Pages {
		if page.Blocked != "" {
			discoveryBlocked = page.Blocked
		}
		if page.Error != "" || page.Blocked != "" {
			continue
		}
		in.Hints = dedupe(append(in.Hints, page.Hints...))
		if _, exists := verdict.ParseVersion(in.PoweredBy, in.Server); !exists {
			if _, found := verdict.ParseVersion(page.PoweredBy, page.Server); found {
				in.PoweredBy, in.Server = page.PoweredBy, page.Server
			}
		}
		if in.PHPInfo == "" {
			in.PHPInfo, in.PHPInfoSettings = page.PHPInfo, page.Settings
		}
		in.Sightings = append(in.Sightings, pageSightings(page)...)
		if page.Status >= 200 && page.Status < 300 && page.Stopped == "" {
			oraclePage.Paths = append(oraclePage.Paths, page.FinalURL)
		}
	}
	if _, versioned := verdict.ParseVersion(in.PoweredBy, in.Server); oracle && !versioned && in.PHPInfo == "" && len(in.Sightings) == 0 {
		evidence.PHPInfo = s.findPHPInfo(ctx, passive)
		for _, page := range evidence.PHPInfo {
			in.Sightings = append(in.Sightings, pageSightings(page)...)
			if page.Signature != "" && page.Blocked == "" {
				in.Hints = dedupe(append(in.Hints, "PHP server signature"))
			}
			if page.PHPInfo != "" {
				in.PHPInfo, in.PHPInfoSettings = page.PHPInfo, page.Settings
				in.Hints = dedupe(append(in.Hints, "phpinfo() page"))
			}
		}
	}
	if _, versioned := verdict.ParseVersion(in.PoweredBy, in.Server); !versioned && len(in.Hints) == 0 {
		in.InspectionBlocked = discoveryBlocked
	}
	if ctx.Err() != nil {
		return in, evidence, ctx.Err()
	}
	if oracle {
		in.Oracle, evidence.Requests, err = s.oracle(ctx, target, oraclePage)
		for _, request := range evidence.Requests {
			if request.Blocked != "" {
				in.InspectionBlocked = request.Blocked
			}
		}
	}
	return in, evidence, err
}

// pageSightings names each version a page showed with the page's path.
func pageSightings(page Passive) []verdict.Sighting {
	if page.Error != "" || page.Blocked != "" {
		return nil
	}
	at := page.FinalURL
	if u, err := url.Parse(page.FinalURL); err == nil && u.Path != "" {
		at = u.Path
	}
	var out []verdict.Sighting
	if v, ok := verdict.ParseVersion(page.PoweredBy, page.Server); ok {
		out = append(out, verdict.Sighting{Source: "header on " + at, Version: v})
	}
	if v, ok := verdict.ParseVersion("PHP/"+page.PHPInfo, page.Server); ok && page.PHPInfo != "" {
		out = append(out, verdict.Sighting{Source: "phpinfo() page at " + at, Version: v})
	}
	if v, ok := verdict.ParseVersion(page.Signature, page.Signature); ok {
		out = append(out, verdict.Sighting{Source: "server signature on " + at, Version: v})
	}
	return out
}
