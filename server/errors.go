package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// Error codes. They are part of the contract and are never renamed.
const (
	codeInvalidRequest   = "invalid_request"
	codeInvalidTarget    = "invalid_target"
	codeNonGlobalAddress = "non_global_address"
	codeUnresolvable     = "unresolvable"
	codeRateLimited      = "rate_limited"
	codeBusy             = "busy"
	codeCheckTimeout     = "check_timeout"
	codeCheckFailed      = "check_failed"
	codeCSRFOrigin       = "csrf_origin_mismatch"
	codeRequestTooLarge  = "request_too_large"
	codeNotFound         = "not_found"
	codeInternal         = "internal_error"
)

// APIError is the body of every failed request.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type errorEnvelope struct {
	Error APIError `json:"error"`
}

// writeJSON renders a payload; a failure past the header is logged only.
func writeJSON(w http.ResponseWriter, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "the response could not be rendered")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if _, err := w.Write(append(body, '\n')); err != nil {
		slog.Debug("writing the response body", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	body, _ := json.Marshal(errorEnvelope{Error: APIError{Code: code, Message: message}})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n'))
}
