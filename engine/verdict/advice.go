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

// Mitigate lists the official stopgaps.
const Mitigate = "Until upgraded, enforce memory_limit=-1 administratively for the OOM paths of CVE-2026-109618. Disable session.upload_progress.enabled for the session paths of CVE-2026-109619, and fatal_error_backtraces on PHP 8.5 for its backtrace path. Restart every worker. These are partial measures, not complete fixes."

var recommendations = map[string][]string{
	Vulnerable:         {Upgrade, Restart, Offline, Mitigate, Assess},
	Patched:            {Verify, "Confirm vendor fixes for both CVEs on every PHP runtime serving the site.", Assess},
	LikelyVulnerable:   {Upgrade, Restart, Offline, Mitigate, Assess, Verify},
	PossiblyBackported: {"Check the installed package against your distribution's advisory for CVE-2026-109618 and CVE-2026-109619.", Restart, Verify, Assess},
	EOLBranch:          {"Upgrade to a supported branch. Until then, apply your vendor's fixed package or, for 7.4, 8.0 and 8.1, build PHP with the PHP security team's source backport.", Restart, Offline, Mitigate, Assess},
	LikelyPatched:      {Restart, Verify, Assess},
	Inconclusive:       {Verify, Upgrade, Restart, Assess},
	NoPHPSignal:        {"If the site runs PHP, verify on the server.", Verify},
	InspectionBlocked:  {"Check the PHP version and vendor patch status on the server, or let the checker's addresses and User-Agent, listed on the about page, through the site's access controls and retry.", Verify},
	Unreachable:        {"Check that the address is right and that the site answers over HTTP or HTTPS.", "If the site opens in a browser, allow the checker's addresses and User-Agent, listed on the about page."},
}
