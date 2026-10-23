package probe

import (
	"maps"
	"strings"
)

// Bounds on what evidence keeps of a site's own text, so a hostile site cannot inflate a report.
const (
	maxValue        = 256  // a header value or a server signature
	maxURL          = 1024 // a URL
	maxText         = 512  // an error message
	maxSetting      = 128  // a phpinfo() setting or version
	maxCookies      = 32   // cookie names per page
	maxCookieName   = 64   // one cookie name
	maxFingerprints = 16   // fingerprints per page
)

// clip cuts s to n bytes on a character boundary and marks the cut.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "..."
}

// clipAll keeps at most most items of list, each cut to n bytes.
func clipAll(list []string, n, most int) []string {
	if len(list) == 0 {
		return nil
	}
	out := make([]string, 0, min(len(list), most))
	for _, item := range list[:min(len(list), most)] {
		out = append(out, clip(item, n))
	}
	return out
}

// bounded is a copy of the page evidence cut to the bounds.
func (p Passive) bounded() Passive {
	p.Error, p.ReadError = clip(p.Error, maxText), clip(p.ReadError, maxText)
	p.FinalURL, p.Stopped = clip(p.FinalURL, maxURL), clip(p.Stopped, maxURL)
	p.Server, p.PoweredBy, p.Signature = clip(p.Server, maxValue), clip(p.PoweredBy, maxValue), clip(p.Signature, maxValue)
	p.PHPInfo = clip(p.PHPInfo, maxSetting)
	if p.Settings != nil {
		settings := maps.Clone(p.Settings)
		for name, value := range settings {
			settings[name] = clip(value, maxSetting)
		}
		p.Settings = settings
	}
	p.Paths = clipAll(p.Paths, maxURL, len(p.Paths))
	p.Redirects = clipAll(p.Redirects, maxURL, len(p.Redirects))
	p.Cookies = clipAll(p.Cookies, maxCookieName, maxCookies)
	if len(p.Fingerprints) > 0 {
		fingerprints := make([]Fingerprint, 0, min(len(p.Fingerprints), maxFingerprints))
		for _, fingerprint := range p.Fingerprints[:min(len(p.Fingerprints), maxFingerprints)] {
			fingerprint.URL = clip(fingerprint.URL, maxURL)
			fingerprints = append(fingerprints, fingerprint)
		}
		p.Fingerprints = fingerprints
	}
	return p
}

// bounded is a copy of the evidence cut to the bounds.
func (e Evidence) bounded() Evidence {
	e.Passive = e.Passive.bounded()
	pages := func(list []Passive) []Passive {
		if len(list) == 0 {
			return nil
		}
		out := make([]Passive, len(list))
		for i, page := range list {
			out[i] = page.bounded()
		}
		return out
	}
	e.Pages, e.PHPInfo = pages(e.Pages), pages(e.PHPInfo)
	if len(e.Requests) > 0 {
		requests := make([]OracleObservation, len(e.Requests))
		for i, request := range e.Requests {
			request.URL, request.Error = clip(request.URL, maxURL), clip(request.Error, maxText)
			requests[i] = request
		}
		e.Requests = requests
	}
	e.HTTPSError = clip(e.HTTPSError, maxText)
	return e
}
