package verdict

// Upgrade names the fixed releases.
const Upgrade = "Upgrade PHP to 8.5.12, 8.4.27, 8.3.36 or 8.2.35, or apply your vendor's fixed package."

// Restart is required after any upgrade.
const Restart = "Restart every PHP worker after upgrading: PHP-FPM pools, Apache and long-running workers."

// Verify points at the local check, the only conclusive one.
const Verify = "Verify on the server: the version the web server runs, the package changelog, and session.upload_progress.enabled."

// RemovePHPInfo follows any verdict drawn with a public phpinfo() page.
const RemovePHPInfo = "Remove the public phpinfo() page; it discloses the PHP version and configuration."

// Mitigate lists the official stopgaps.
const Mitigate = "Until upgraded, set session.upload_progress.enabled=0 and memory_limit=-1 in php.ini and restart the workers. These narrow the exposure but do not fix it."

var recommendations = map[string][]string{
	Vulnerable:         {Upgrade, Restart, Mitigate},
	Patched:            {"No action is needed for this path. Keep session.upload_progress.enabled=0 if the feature is unused."},
	LikelyVulnerable:   {Upgrade, Restart, Mitigate, Verify},
	PossiblyBackported: {"Check the installed package against your distribution's advisory for CVE-2026-109618 and CVE-2026-109619.", Restart, Verify},
	EOLBranch:          {"Upgrade to a supported branch, or confirm that your vendor ships a fixed package for this one.", Restart, Mitigate},
	LikelyPatched:      {Restart, Verify},
	Inconclusive:       {Verify, Upgrade, Restart},
	NoPHPSignal:        {"If the site runs PHP, verify on the server.", Verify},
	InspectionBlocked:  {"Check the PHP version and vendor patch status on the server. If needed, allow the checker through the site access controls and retry.", Verify},
	Unreachable:        {"Check that the address is right and that the site answers over HTTP or HTTPS."},
}
