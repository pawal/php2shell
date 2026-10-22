package server

import (
	"context"
	"strings"
	"time"

	"github.com/pawal/php2shell/engine/probe"
	"github.com/pawal/php2shell/engine/verdict"
)

// Checker runs the network side of one check; oracle asks for the session
// path request beside the passive fetch.
type Checker interface {
	Check(ctx context.Context, target probe.Target, oracle bool) (verdict.Input, any, error)
}

// localCheck is what an owner runs on the server for a conclusive answer.
var localCheck = []string{
	"php -v; php-fpm -v",
	`php -r 'echo phpversion("session"), PHP_EOL;'`,
	"dpkg -l 'php*' | grep -E 'fpm|apache'",
	"rpm -q php php-fpm",
	"php -i | grep -iE 'session.upload_progress.enabled|display_errors'",
	"systemctl restart php-fpm apache2",
}

// freebsdCheck lists every PHP package, since FreeBSD ships the session extension apart.
var freebsdCheck = []string{
	"php -v; php-fpm -v",
	`php -r 'echo phpversion("session"), PHP_EOL;'`,
	"pkg info -x php",
	"php -i | grep -iE 'session.upload_progress.enabled|display_errors'",
	"service apache24 restart; service php_fpm restart",
}

// LocalCheck picks the commands for the system the Server header names.
func LocalCheck(in verdict.Input) []string {
	if strings.Contains(strings.ToLower(in.Server), "freebsd") {
		return freebsdCheck
	}
	return localCheck
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
