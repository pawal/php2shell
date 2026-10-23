package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"syscall"

	"github.com/pawal/php2shell/engine/verdict"
)

// failureReason says in plain words why a request got no answer.
func failureReason(err error) string {
	var certificate *tls.CertificateVerificationError
	var timeout net.Error
	switch {
	case errors.As(err, &certificate):
		return verdict.FailedCertificate
	case strings.Contains(err.Error(), "tls:"):
		return verdict.FailedHandshake
	case errors.Is(err, syscall.ECONNREFUSED):
		return verdict.FailedRefused
	case errors.Is(err, syscall.ECONNRESET):
		return verdict.FailedReset
	case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout():
		return verdict.FailedTimeout
	}
	return verdict.FailedConnection
}
