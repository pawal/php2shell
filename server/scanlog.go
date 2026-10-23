package server

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pawal/php2shell/engine/verdict"
)

// scanLog appends one line per check: time, target host, outcome, mode and any reason.
// It never records who asked.
type scanLog struct {
	mu   sync.Mutex
	file *os.File
}

func openScanLog(path string) (*scanLog, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open log_file: %w", err)
	}
	return &scanLog{file: file}, nil
}

func (l *scanLog) record(at time.Time, host, outcome, mode, reason string) {
	if l == nil {
		return
	}
	if reason != "" {
		mode += " " + reason
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.file, "%s %s %s %s\n", at.UTC().Format(time.RFC3339), host, outcome, mode)
}

// failureCodes name the reasons a site did not answer in the log.
var failureCodes = map[string]string{
	verdict.FailedTimeout:     "timeout",
	verdict.FailedRefused:     "refused",
	verdict.FailedReset:       "reset",
	verdict.FailedCertificate: "certificate",
	verdict.FailedHandshake:   "handshake",
	verdict.FailedConnection:  "connection",
}

// logReason is the one-word reason an unreachable or blocked result gets in the log.
func logReason(in verdict.Input, outcome string) string {
	switch outcome {
	case verdict.Unreachable:
		return failureCodes[in.Failure]
	case verdict.InspectionBlocked:
		return strings.Trim(strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
				return r
			}
			return '-'
		}, strings.ToLower(in.InspectionBlocked)), "-")
	}
	return ""
}

func (l *scanLog) close() error {
	if l == nil {
		return nil
	}
	return l.file.Close()
}
