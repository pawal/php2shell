package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/pawal/php2shell/engine/probe"
	"github.com/pawal/php2shell/engine/verdict"
)

// errBusy is a check refused because every slot is taken.
var errBusy = errors.New("busy")

// checkRequest is the body of POST /api/v1/check.
type checkRequest struct {
	URL      string `json:"url"`
	Attested bool   `json:"attested"`
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	if err := checkOrigin(r, s.trusted); err != nil {
		writeError(w, http.StatusForbidden, codeCSRFOrigin, err.Error())
		return
	}
	if s.limiter.Enabled() {
		if ok, retry := s.limiter.Allow(clientAddress(r, s.trusted)); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(max(1, int(retry.Round(time.Second)/time.Second))))
			writeError(w, http.StatusTooManyRequests, codeRateLimited, "too many checks from this address")
			return
		}
	}
	var req checkRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, codeRequestTooLarge, "the request body is too large")
			return
		}
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "the body must be a JSON object with url and attested")
		return
	}
	target, err := probe.ParseTarget(req.URL)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidTarget, err.Error())
		return
	}

	report, cached, err := s.cooldown.do(target.Host, req.Attested, func() (Report, error) {
		return s.run(r.Context(), target, req.Attested)
	})
	if err != nil {
		s.writeCheckError(w, target, err)
		return
	}
	report.Cached = cached
	writeJSON(w, http.StatusOK, report)
}

// run takes a slot, runs the checker under the check timeout, and judges.
func (s *Server) run(ctx context.Context, target probe.Target, oracle bool) (Report, error) {
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return Report{}, errBusy
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.CheckTimeout.Duration)
	defer cancel()
	input, evidence, err := s.checker.Check(ctx, target, oracle)
	mode := map[bool]string{true: "oracle", false: "passive"}[oracle]
	if err != nil {
		s.scanlog.record(s.now(), target.Host, failureLabel(err), mode)
		return Report{}, err
	}
	result := verdict.Judge(input)
	s.scanlog.record(s.now(), target.Host, result.Verdict, mode)
	return Report{
		Target:     target.URL(),
		Result:     result,
		OracleRun:  oracle && input.Oracle != verdict.OracleNotRun,
		Evidence:   evidence,
		LocalCheck: LocalCheck,
		CheckedAt:  s.now().UTC(),
	}, nil
}

// errorCode maps a checker failure to its API code.
func errorCode(err error) string {
	var policy *probe.PolicyError
	switch {
	case errors.As(err, &policy):
		return codeNonGlobalAddress
	case errors.Is(err, probe.ErrUnresolvable):
		return codeUnresolvable
	case errors.Is(err, errBusy):
		return codeBusy
	case errors.Is(err, context.DeadlineExceeded):
		return codeCheckTimeout
	}
	return codeCheckFailed
}

// failureLabel is the log outcome of a check that drew no verdict.
func failureLabel(err error) string {
	switch code := errorCode(err); code {
	case codeNonGlobalAddress, codeUnresolvable:
		return "refused:" + code
	default:
		return "error:" + code
	}
}

func (s *Server) writeCheckError(w http.ResponseWriter, target probe.Target, err error) {
	switch code := errorCode(err); code {
	case codeNonGlobalAddress, codeUnresolvable:
		writeError(w, http.StatusBadRequest, code, err.Error())
	case codeBusy:
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusServiceUnavailable, code, "every check slot is taken, try again shortly")
	case codeCheckTimeout:
		writeError(w, http.StatusGatewayTimeout, code, "the check of "+target.Host+" took too long")
	default:
		s.logger.Warn("check failed", "error", err)
		writeError(w, http.StatusBadGateway, code, "the check of "+target.Host+" failed")
	}
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": s.version})
}

// info is what a client may know of this instance's limits.
type info struct {
	Version                 string          `json:"version"`
	AllowNonGlobalAddresses bool            `json:"allow_non_global_addresses"`
	RateLimit               RateLimitConfig `json:"rate_limit"`
	TargetCooldown          Duration        `json:"target_cooldown"`
	CheckTimeout            Duration        `json:"check_timeout"`
}

func (s *Server) handleInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, info{
		Version:                 s.version,
		AllowNonGlobalAddresses: s.cfg.AllowNonGlobalAddresses,
		RateLimit:               s.cfg.RateLimit,
		TargetCooldown:          s.cfg.TargetCooldown,
		CheckTimeout:            s.cfg.CheckTimeout,
	})
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func handleAPINotFound(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotFound, codeNotFound, "no such route")
}
