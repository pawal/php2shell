package verdict

import (
	"fmt"
	"strings"
)

// Settings kept from a phpinfo() page, by the names it shows.
const (
	ServerAPI       = "Server API"
	DisplayErrors   = "display_errors"
	SaveHandler     = "session.save_handler"
	UploadProgress  = "session.upload_progress.enabled"
	FatalBacktraces = "fatal_error_backtraces"
	IgnoreArgs      = "zend.exception_ignore_args"
	FixPathinfo     = "cgi.fix_pathinfo"
	ErrorLog        = "error_log"
)

// PHPInfoSettings lists the settings a check reads from a phpinfo() page.
var PHPInfoSettings = []string{ServerAPI, DisplayErrors, SaveHandler, UploadProgress, FatalBacktraces, IgnoreArgs, FixPathinfo, ErrorLog}

func on(value string) bool {
	switch strings.ToLower(value) {
	case "on", "1", "yes", "true", "stdout":
		return true
	}
	return false
}

// hiding names the settings that keep the session request from answering.
func hiding(settings map[string]string) []string {
	var out []string
	if v, ok := settings[UploadProgress]; ok && !on(v) {
		out = append(out, UploadProgress+" "+v)
	}
	if v, ok := settings[DisplayErrors]; ok && !on(v) {
		out = append(out, DisplayErrors+" "+v)
	}
	if v, ok := settings[SaveHandler]; ok && !strings.EqualFold(v, "files") {
		out = append(out, SaveHandler+" "+v)
	}
	return out
}

// measureNote credits the interim measure on an affected version without calling it a fix.
func measureNote(in Input) string {
	v, ok := in.PHPInfoSettings[UploadProgress]
	if !ok || on(v) {
		return ""
	}
	if in.Oracle == OracleSilent {
		return " Upload progress off narrows the session paths of CVE-2026-109619; it does not mitigate CVE-2026-109618 or establish a complete fix."
	}
	return fmt.Sprintf(" The phpinfo() page shows %s %s, an interim measure for the session paths of CVE-2026-109619; it does not mitigate CVE-2026-109618 or establish a complete fix.", UploadProgress, v)
}

// exposureNote names the November flaws whose preconditions a phpinfo() page shows, or whose stopgaps it shows in place.
func exposureNote(v Version, settings map[string]string) string {
	var parts []string
	fatal, hasFatal := settings[FatalBacktraces]
	ignore, hasIgnore := settings[IgnoreArgs]
	if v.Major == 8 && v.Minor == 5 && hasFatal && hasIgnore {
		if on(fatal) && !on(ignore) {
			parts = append(parts, fmt.Sprintf("%s %s and %s %s, which CVE-2026-129474 needs", FatalBacktraces, fatal, IgnoreArgs, ignore))
		} else {
			parts = append(parts, "the stopgap for CVE-2026-129474 in place")
		}
	}
	api := strings.ToLower(settings[ServerAPI])
	switch {
	case strings.Contains(api, "fpm"):
		parts = append(parts, "the "+settings[ServerAPI]+" server API, which CVE-2026-129289 needs together with FastCGI connection reuse")
	case strings.Contains(api, "cgi"):
		if fix, ok := settings[FixPathinfo]; ok && !on(fix) {
			parts = append(parts, "php-cgi with the stopgap for CVE-2026-129538 in place")
		} else {
			parts = append(parts, "the "+settings[ServerAPI]+" server API of php-cgi, which CVE-2026-129538 needs")
		}
	}
	if file, ok := settings[ErrorLog]; ok {
		switch {
		case file == "":
			parts = append(parts, "no error_log file, so the demonstrated trigger of CVE-2026-129496 is absent")
		case strings.EqualFold(file, "syslog"):
			parts = append(parts, "errors logged to syslog, the stopgap for CVE-2026-129496")
		default:
			parts = append(parts, "errors logged to a file, which CVE-2026-129496 needs")
		}
	}
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return " The phpinfo() page shows " + parts[0] + "."
	}
	return " The phpinfo() page shows " + strings.Join(parts[:len(parts)-1], "; ") + "; and " + parts[len(parts)-1] + "."
}

// restartFor names what to restart for the server API a phpinfo() page shows.
func restartFor(api string) string {
	lower := strings.ToLower(api)
	var what string
	switch {
	case strings.Contains(lower, "fpm"):
		what = "every PHP-FPM pool"
	case strings.Contains(lower, "apache"):
		what = "Apache, which runs PHP inside it"
	case strings.Contains(lower, "litespeed"):
		what = "the LiteSpeed PHP processes"
	case strings.Contains(lower, "cgi"):
		what = "the PHP CGI and FastCGI processes"
	default:
		return ""
	}
	return fmt.Sprintf("Restart %s after upgrading; the phpinfo() page shows the %s server API.", what, api)
}
