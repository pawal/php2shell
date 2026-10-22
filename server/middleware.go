package server

import (
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// apiPrefix is where every JSON route lives.
const apiPrefix = "/api/"

// permissionsPolicy denies the browser features the page never uses.
const permissionsPolicy = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"

// recorder captures the status an inner handler produced.
type recorder struct {
	http.ResponseWriter
	status int
}

func (r *recorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *recorder) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(data)
}

// securityHeaders sets the headers every route shares, with the content
// policy and cache rule the path calls for.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("Content-Security-Policy", policyFor(r.URL.Path))
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("X-Frame-Options", "DENY")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("Cross-Origin-Opener-Policy", "same-origin")
		header.Set("Cross-Origin-Resource-Policy", "same-origin")
		header.Set("Permissions-Policy", permissionsPolicy)
		if strings.HasPrefix(r.URL.Path, apiPrefix) {
			header.Set("Cache-Control", "no-store")
		} else {
			header.Set("Cache-Control", "no-cache")
		}
		next.ServeHTTP(w, r)
	})
}

// policyFor picks the content security policy of one path.
func policyFor(path string) string {
	if strings.HasPrefix(path, apiPrefix) {
		return apiCSP
	}
	return uiCSP
}

// stripForwarded removes hop claims an untrusted peer made.
func (s *Server) stripForwarded(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.trustsPeer(r) {
			for _, name := range forwardedHeaders {
				r.Header.Del(name)
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) trustsPeer(r *http.Request) bool {
	if len(s.trusted) == 0 {
		return false
	}
	addr, err := netip.ParseAddr(peerAddress(r))
	return err == nil && inPrefixes(addr, s.trusted)
}

// recoverPanic turns a handler panic into an error response.
func (s *Server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if value := recover(); value != nil {
				s.logger.Error("handler panic", "path", r.URL.Path, "value", value)
				writeError(w, http.StatusInternalServerError, codeInternal, "the request could not be served")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// capBody bounds a request body before a handler reads it.
func (s *Server) capBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodySize)
		}
		next.ServeHTTP(w, r)
	})
}

// observe logs each request without the client's address.
func (s *Server) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		rec := &recorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		s.logger.Info("request", "method", r.Method, "path", r.URL.Path,
			"status", rec.status, "duration_ms", time.Since(started).Milliseconds())
	})
}
