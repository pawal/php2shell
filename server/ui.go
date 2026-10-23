package server

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed public
var public embed.FS

// page is what a document template is rendered with.
type page struct {
	Title          string
	Description    string
	Origin         string
	Canonical      string
	Path           string
	Version        string
	Provider       string
	ProviderURL    string
	SourceURL      string
	Contact        string
	Sources        []string
	StructuredData template.JS
}

// documents are the indexable pages, by path.
var documents = []struct{ path, file, title, description string }{
	{"/", "index.html", "PHP2Shell check",
		"Check whether your website runs a PHP release still exposed to PHP2Shell, CVE-2026-109618 and CVE-2026-109619."},
	{"/about", "about.html", "About the PHP2Shell check",
		"How the PHP2Shell check works, what it cannot see, and what it records."},
}

// renderDocuments executes every page template once.
func (s *Server) renderDocuments() (map[string][]byte, error) {
	templates, err := template.ParseFS(public, "public/*.html")
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, doc := range documents {
		data := page{
			Title: doc.title, Description: doc.description, Path: doc.path, Version: s.version,
			Provider: s.cfg.Provider, ProviderURL: s.cfg.ProviderURL, SourceURL: s.cfg.SourceURL, Contact: s.cfg.Contact,
			Sources: s.cfg.SourceAddresses,
		}
		if origin := s.cfg.Origin(); origin != "" {
			data.Origin = origin
			data.Canonical = origin + doc.path
			if doc.path == "/" {
				if data.StructuredData, err = s.structuredData(doc.title, doc.description); err != nil {
					return nil, err
				}
			}
		}
		var buf bytes.Buffer
		if err := templates.ExecuteTemplate(&buf, doc.file, data); err != nil {
			return nil, fmt.Errorf("render %s: %w", doc.file, err)
		}
		out[doc.path] = buf.Bytes()
	}
	return out, nil
}

// structuredData describes the service to search engines, as JSON-LD.
func (s *Server) structuredData(name, description string) (template.JS, error) {
	home := s.cfg.Origin() + "/"
	provider := map[string]any{"@type": "Organization", "name": s.cfg.Provider}
	if s.cfg.ProviderURL != "" {
		provider["url"] = s.cfg.ProviderURL
	}
	data, err := json.Marshal(map[string]any{
		"@context": "https://schema.org",
		"@graph": []any{
			map[string]any{"@type": "WebSite", "name": name, "url": home},
			map[string]any{
				"@type": "WebApplication", "name": name, "url": home, "description": description,
				"applicationCategory": "SecurityApplication", "operatingSystem": "Any",
				"isAccessibleForFree": true, "provider": provider,
			},
		},
	})
	return template.JS(data), err
}

func (s *Server) serveDocument(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(s.pages[path])
	}
}

// staticHandler serves the embedded assets, cached for a day.
func staticHandler() http.Handler {
	sub, err := fs.Sub(public, "public/static")
	if err != nil {
		panic(err)
	}
	files := http.StripPrefix("/static/", http.FileServerFS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=86400")
		files.ServeHTTP(w, r)
	})
}

func (s *Server) handleRobots(w http.ResponseWriter, _ *http.Request) {
	text := "User-agent: *\nAllow: /$\nAllow: /about\nAllow: /static/\nDisallow: /api/\n"
	if origin := s.cfg.Origin(); origin != "" {
		text += "Sitemap: " + origin + "/sitemap.xml\n"
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(text))
}

func (s *Server) handleSitemap(w http.ResponseWriter, r *http.Request) {
	origin := s.cfg.Origin()
	if origin == "" {
		http.NotFound(w, r)
		return
	}
	var buf strings.Builder
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	buf.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")
	for _, doc := range documents {
		buf.WriteString("  <url><loc>" + template.HTMLEscapeString(origin+doc.path) + "</loc></url>\n")
	}
	buf.WriteString("</urlset>\n")
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	_, _ = w.Write([]byte(buf.String()))
}

func handlePageNotFound(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("not found\n"))
}
