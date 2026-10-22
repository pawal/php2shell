// Package server is the HTTP service: the page, the check API and the
// limits around it.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// Server holds everything one running instance shares.
type Server struct {
	cfg      Config
	version  string
	checker  Checker
	logger   *slog.Logger
	trusted  []netip.Prefix
	limiter  *RateLimiter
	cooldown *cooldown
	slots    chan struct{}
	scanlog  *scanLog
	pages    map[string][]byte
	now      func() time.Time
}

// route is one registered method and path, for the contract test.
type route struct {
	Method string
	Path   string
}

// New validates the configuration and builds a server.
func New(cfg Config, version string, checker Checker, logger *slog.Logger) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	trusted, err := parsePrefixes(cfg.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}
	log, err := openScanLog(cfg.LogFile)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{
		cfg: cfg, version: version, checker: checker, logger: logger, trusted: trusted,
		limiter: NewRateLimiter(cfg.RateLimit),
		slots:   make(chan struct{}, cfg.MaxConcurrentChecks),
		scanlog: log,
		now:     func() time.Time { return time.Now().UTC() },
	}
	s.cooldown = newCooldown(cfg.TargetCooldown.Duration, func() time.Time { return s.now() })
	if s.pages, err = s.renderDocuments(); err != nil {
		return nil, err
	}
	return s, nil
}

// routes is the table the mux is built from.
func (s *Server) routes() []struct {
	route
	handler http.Handler
} {
	return []struct {
		route
		handler http.Handler
	}{
		{route{"GET", "/"}, s.serveDocument("/")},
		{route{"GET", "/about"}, s.serveDocument("/about")},
		{route{"GET", "/static/"}, staticHandler()},
		{route{"GET", "/robots.txt"}, http.HandlerFunc(s.handleRobots)},
		{route{"GET", "/sitemap.xml"}, http.HandlerFunc(s.handleSitemap)},
		{route{"GET", "/healthz"}, http.HandlerFunc(handleHealth)},
		{route{"POST", "/api/v1/check"}, http.HandlerFunc(s.handleCheck)},
		{route{"GET", "/api/v1/version"}, http.HandlerFunc(s.handleVersion)},
		{route{"GET", "/api/v1/info"}, http.HandlerFunc(s.handleInfo)},
	}
}

// Handler is the whole service with its middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	for _, rt := range s.routes() {
		pattern := rt.Method + " " + rt.Path
		if rt.Path == "/" {
			pattern += "{$}"
		}
		mux.Handle(pattern, rt.handler)
	}
	mux.HandleFunc(apiPrefix, handleAPINotFound)
	mux.HandleFunc("/", handlePageNotFound)
	return s.recoverPanic(s.observe(securityHeaders(s.stripForwarded(s.capBody(mux)))))
}

// Run serves until ctx ends, then drains for up to ten seconds.
func (s *Server) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, listener)
}

// Serve is Run on a listener the caller opened.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadTimeout:       s.cfg.ReadTimeout.Duration,
		ReadHeaderTimeout: s.cfg.ReadTimeout.Duration,
		WriteTimeout:      s.cfg.WriteTimeout.Duration,
		IdleTimeout:       s.cfg.IdleTimeout.Duration,
		MaxHeaderBytes:    32 << 10,
	}
	errs := make(chan error, 1)
	go func() { errs <- srv.Serve(listener) }()
	s.logger.Info("serving", "addr", listener.Addr().String(), "version", s.version,
		"allow_non_global_addresses", s.cfg.AllowNonGlobalAddresses)
	if s.cfg.AllowNonGlobalAddresses {
		s.logger.Warn("allow_non_global_addresses is set; this instance checks private addresses and any port")
	}
	select {
	case err := <-errs:
		_ = s.scanlog.close()
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := srv.Shutdown(shutdown)
	if serveErr := <-errs; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && err == nil {
		err = serveErr
	}
	if closeErr := s.scanlog.close(); err == nil {
		err = closeErr
	}
	return err
}
