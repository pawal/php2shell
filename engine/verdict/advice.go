package verdict

// Upgrade names the fixed releases.
const Upgrade = "Upgrade PHP to 8.5.13, 8.4.28, 8.3.37 or 8.2.36, released on 19 November 2026, or to 8.6, or apply your vendor's fixed package."

// Restart is required after any upgrade.
const Restart = "Restart every PHP worker after upgrading: PHP-FPM pools, Apache and long-running workers."

// Verify points at the local check, the only conclusive one.
const Verify = "Verify on the server: the version the web server runs, the package changelog, and session.upload_progress.enabled."

// RemovePHPInfo follows any verdict drawn with a public phpinfo() page.
const RemovePHPInfo = "Remove the public phpinfo() page; it discloses the PHP version and configuration."

// Offline is the agencies' advice while an upgrade waits.
const Offline = "If you cannot upgrade at once, take the site offline until it is fixed, as CISA, the NCSC and CERT-EU advise."

// Assess asks for a compromise check, since attempts began before the fix.
const Assess = "Exploitation attempts began on 17 October 2026, before the fix was released, and upgrading does not remove a backdoor. Look on the server for signs of compromise since then: PHP workers that started shells or downloaded tools, unexpected processes, and changed files."

// Mitigate lists the PHP advisory's stopgaps for CVE-2026-109618.
const Mitigate = "Until upgraded, reduce exposure to CVE-2026-109618 as the PHP advisory lists: set memory_limit=-1 where applications cannot override it, such as with php_admin_value; set post_max_size to 8M, or 32M where uploads are needed, with upload_max_filesize below it; limit request size, fields, parts, headers and nesting at the web server or proxy; and bound memory with a container or cgroup limit, not RLIMIT_AS or RLIMIT_DATA."

// MitigateSession lists the PHP advisory's stopgaps for CVE-2026-109619.
const MitigateSession = "For CVE-2026-109619, set session.upload_progress.enabled=0 in php.ini or the pool, not with ini_set() or .user.ini, and fatal_error_backtraces=0 on PHP 8.5; remove invalid per-request settings; fix fatal errors and timeouts attackers can reach; restart every worker. These measures are partial, not complete fixes. Keep upload progress off after upgrading unless the site needs it."

// MitigateNovember lists the stopgaps of the advisories of 19 November 2026.
const MitigateNovember = "Until upgraded, apply the stopgaps of the 19 November advisories: on PHP 8.5, set zend.exception_ignore_args=1 or fatal_error_backtraces=0 (CVE-2026-129474); turn off FastCGI connection reuse in front of PHP-FPM, such as nginx fastcgi_keep_conn and Apache enablereuse (CVE-2026-129289); fix configuration errors and deprecated settings that PHP logs at startup, or log errors to syslog (CVE-2026-129496); and set cgi.fix_pathinfo=0 for php-cgi (CVE-2026-129538)."

// ProgressOff advises keeping session upload progress off, the default since 19 November 2026.
const ProgressOff = "Keep session.upload_progress.enabled=0 unless the site needs upload progress: it is an input path of CVE-2026-115560 and CVE-2026-126714, and the 19 November releases turn it off by default. Where it stays on, every application that shares the session store must use the same session.serialize_handler."

// octoberAdvice replaces the likely-vulnerable advice for a release with the October fixes only.
var octoberAdvice = []string{Upgrade, Restart, MitigateNovember, ProgressOff, Assess, Verify}

var recommendations = map[string][]string{
	Vulnerable:         {Upgrade, Restart, Offline, Mitigate, MitigateSession, MitigateNovember, Assess},
	Patched:            {Verify, "Confirm vendor fixes for both CVEs on every PHP runtime serving the site.", Assess, ProgressOff},
	LikelyVulnerable:   {Upgrade, Restart, Offline, Mitigate, MitigateSession, MitigateNovember, Assess, Verify},
	PossiblyBackported: {"Check the installed package against your distribution's advisories for CVE-2026-109618, CVE-2026-109619 and the PHP security releases of 19 November 2026.", Restart, Verify, Assess, ProgressOff},
	EOLBranch:          {"Upgrade to a supported branch. Until then, apply your vendor's fixed package or, for 7.4, 8.0 and 8.1, build PHP with the PHP security team's source backport.", Restart, Offline, Mitigate, MitigateSession, Assess},
	LikelyPatched:      {Restart, Verify, Assess, ProgressOff},
	Inconclusive:       {Verify, Upgrade, Restart, Assess, ProgressOff},
	NoPHPSignal:        {"If the site runs PHP, verify on the server.", Verify},
	InspectionBlocked:  {"Check the PHP version and vendor patch status on the server, or let the checker's addresses and User-Agent, listed on the about page, through the site's access controls and retry.", Verify},
	Unreachable:        {"Check that the address is right and that the site answers over HTTP or HTTPS.", "If the site opens in a browser, allow the checker's addresses and User-Agent, listed on the about page."},
}
