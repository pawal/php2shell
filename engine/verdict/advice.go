package verdict

// Upgrade names the fixed releases.
const Upgrade = "Upgrade PHP to 8.5.12, 8.4.27, 8.3.36 or 8.2.35, or apply your vendor's fixed package."

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
const MitigateSession = "For CVE-2026-109619, set session.upload_progress.enabled=0 in php.ini or the pool, not with ini_set() or .user.ini, and fatal_error_backtraces=0 on PHP 8.5; remove invalid per-request settings; fix fatal errors and timeouts attackers can reach; restart every worker. These measures are partial, not complete fixes. Keep upload progress off after upgrading until PHP's next bugfix release, which fixes CVE-2026-115560."

// ProgressOff relays PHP's interim advice for CVE-2026-115560.
const ProgressOff = "PHP suggests session.upload_progress.enabled=0 until its next bugfix release, which fixes CVE-2026-115560. That flaw needs an application that switches session.serialize_handler to php at runtime; applications that never do can keep upload progress on."

var recommendations = map[string][]string{
	Vulnerable:         {Upgrade, Restart, Offline, Mitigate, MitigateSession, Assess},
	Patched:            {Verify, "Confirm vendor fixes for both CVEs on every PHP runtime serving the site.", Assess, ProgressOff},
	LikelyVulnerable:   {Upgrade, Restart, Offline, Mitigate, MitigateSession, Assess, Verify},
	PossiblyBackported: {"Check the installed package against your distribution's advisory for CVE-2026-109618 and CVE-2026-109619.", Restart, Verify, Assess, ProgressOff},
	EOLBranch:          {"Upgrade to a supported branch. Until then, apply your vendor's fixed package or, for 7.4, 8.0 and 8.1, build PHP with the PHP security team's source backport.", Restart, Offline, Mitigate, MitigateSession, Assess},
	LikelyPatched:      {Restart, Verify, Assess, ProgressOff},
	Inconclusive:       {Verify, Upgrade, Restart, Assess, ProgressOff},
	NoPHPSignal:        {"If the site runs PHP, verify on the server.", Verify},
	InspectionBlocked:  {"Check the PHP version and vendor patch status on the server, or let the checker's addresses and User-Agent, listed on the about page, through the site's access controls and retry.", Verify},
	Unreachable:        {"Check that the address is right and that the site answers over HTTP or HTTPS.", "If the site opens in a browser, allow the checker's addresses and User-Agent, listed on the about page."},
}
