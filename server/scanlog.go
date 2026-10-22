package server

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// scanLog appends one line per check: time, target host, outcome and mode.
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

func (l *scanLog) record(at time.Time, host, outcome, mode string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.file, "%s %s %s %s\n", at.UTC().Format(time.RFC3339), host, outcome, mode)
}

func (l *scanLog) close() error {
	if l == nil {
		return nil
	}
	return l.file.Close()
}
