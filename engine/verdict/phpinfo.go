package verdict

import (
	"fmt"
	"strings"
)

// Settings kept from a phpinfo() page, by the names it shows.
const (
	ServerAPI      = "Server API"
	DisplayErrors  = "display_errors"
	SaveHandler    = "session.save_handler"
	UploadProgress = "session.upload_progress.enabled"
)

// PHPInfoSettings lists the settings a check reads from a phpinfo() page.
var PHPInfoSettings = []string{ServerAPI, DisplayErrors, SaveHandler, UploadProgress}

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
