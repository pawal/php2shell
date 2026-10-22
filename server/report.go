package server

import (
	"context"
	"time"

	"github.com/pawal/php2shell/engine/probe"
	"github.com/pawal/php2shell/engine/verdict"
)

// Checker runs the network side of one check; oracle asks for the session
// path request beside the passive fetch.
type Checker interface {
	Check(ctx context.Context, target probe.Target, oracle bool) (verdict.Input, any, error)
}

// LocalCheck is what an owner runs on the server for a conclusive answer.
var LocalCheck = []string{
	"php -v; php-fpm -v",
	"dpkg -l 'php*' | grep -E 'fpm|apache'",
	"rpm -q php php-fpm",
	"php -i | grep -iE 'session.upload_progress.enabled|display_errors'",
	"systemctl restart php-fpm apache2",
}

// Report is one finished check as the API returns it.
type Report struct {
	Target string `json:"target"`
	verdict.Result
	OracleRun  bool      `json:"oracle_run"`
	Evidence   any       `json:"evidence,omitempty"`
	LocalCheck []string  `json:"local_check"`
	CheckedAt  time.Time `json:"checked_at"`
	Cached     bool      `json:"cached"`
}
