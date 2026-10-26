# Changelog

A release is a tag in the repository, and the tag is the only place a version
number is written.

## Unreleased

- The page and results say exploitation attempts began on 17 October 2026.
- Results drawn from PHP evidence ask for a check for signs of compromise.
- The server commands list the process tree and files changed since 17 October 2026.
- Affected and end-of-life results advise taking the site offline when an upgrade must wait.
- The about page links to the government advisories, the Amazon and Cloudflare reports and the Delft attack dashboard.
- Results relay PHP's advice on CVE-2026-115560 until its next bugfix release.
- Affected results list every interim measure from the PHP advisory.
- Possibly unfixed results name WordPress, Drupal or Joomla as demonstrated targets.
- Possibly unfixed results behind Cloudflare say its firewall rules do not replace the fix.

## v1.0.14 (2026-10-23)

A small release about the session request. It now carries its invalid
session ID as a form field as well as a cookie, so a site behind a proxy
that strips cookies still yields a session observation, and the about page
and the results explain the request to administrators who meet it in
firewall logs. No configuration change is needed on upgrade.

- The session request also sends its invalid session ID as a form field, so a proxy that strips cookies does not hide the observation.
- The about page describes the session request, so firewall logs can be matched to it.
- A blocked session request's summary says a firewall rule against upload-progress requests is a partial measure, not a fix.

## v1.0.13 (2026-10-23)

A hardening release from a security audit of the public service. A hostile
site can no longer inflate reports or the result cache, the service's memory
is capped, IPv6 clients are rate limited per /64, and release tooling is
pinned. No configuration change is needed on upgrade.

- Evidence keeps bounded amounts of a site's own text, so a hostile site cannot inflate a report.
- The result cache holds at most 64 MiB besides its 10,000 entries.
- The systemd unit caps the service's memory at 512 MB.
- The rate limit counts an IPv6 client by its /64 and tracks at most 100,000 clients.
- Releases pin nfpm and the GitHub actions to exact versions.
- A refused address is named by its kind only, so the service does not show how it resolves names.
- deploy.md documents an optional kernel address filter for the service.

## v1.0.12 (2026-10-23)

A security release: the binaries are built with Go 1.27.3, which fixes 13
standard-library vulnerabilities. Earlier releases were built with Go
1.27.0, and some of those flaws are in the HTTP client the checks use
against untrusted sites, so upgrading is recommended.

- Builds require Go 1.27.3, which fixes 13 standard-library vulnerabilities, some in the HTTP client the checks use.

## v1.0.11 (2026-10-23)

Owners can check again a minute after a cached result, for example after
patching. A site whose HTTPS does not answer is checked over plain HTTP,
results are cached per scheme, host and port, and the check log names why
a site was unreachable or blocked.

- An assumed HTTPS that does not answer is retried over plain HTTP too, while time remains.
- Cached results are kept per scheme, host and port instead of per host.
- The report's target is the address actually checked, after a retry over HTTP.
- Unreachable and blocked lines in the check log name the reason.
- The API specification describes every evidence field, and a test keeps it complete.
- CI runs govulncheck, and `make vulncheck` needs no separate install.
- Check again runs a fresh check once a cached result is a minute old, for example after patching.

## v1.0.10 (2026-10-23)

End-of-life results now match the PHP advisory on source backports, and a
site whose HTTPS fails fast is checked over plain HTTP when no scheme was
given.

- End-of-life results name the PHP security team's source backports for 7.4, 8.0 and 8.1.
- A host given without a scheme is checked over plain HTTP when HTTPS fails fast, as with a provider's default certificate.

## v1.0.9 (2026-10-23)

Session findings are reported as likelihoods for the paths they were seen
on, never as a confirmed fix or vulnerability. Incomplete, redirected,
blocked and long responses no longer hide or overstate what was seen.

- Keep session observations path-scoped and reject incomplete response classifications.
- Report likelihoods without asserting complete CVE fixes or vendor backports from session warnings.
- Older session behaviour counts even when the response body breaks off.
- Session answers on pages longer than the 64 KiB cap count once page output follows the warnings.
- Session requests stop at the first older-behaviour answer, and a check out of time keeps the answers it has.
- A blocked session request no longer overrides a version or other PHP evidence.
- Session warnings that could not be classified are named instead of reported as nothing.
- Older session behaviour on an end-of-life version keeps the end-of-life verdict and advice.

## v1.0.8 (2026-10-23)

When nothing shows PHP, results name the platform the answers point to
instead, such as Java or Express, from each platform's documented defaults.

- When nothing shows PHP, the result names another platform the answers point to, such as Java.

## v1.0.7 (2026-10-23)

Blocked and unreachable results now say what stopped the check: the reason
a connection failed, or a named firewall such as Sansec Shield. The about
page lists the addresses checks come from, so owners can let them through.

- An unreachable result says why the site did not answer.
- Sansec Shield's block page is named instead of a bare HTTP 403.
- A block the result already names no longer also names the layer in front.
- The about page lists the addresses checks come from, set by `source_addresses`, so owners can let the check through.

## v1.0.6 (2026-10-23)

Results name a CDN, firewall or cache that shows itself in front of the
site, and say in plain words that it limits what a remote check can see.

- Results name a CDN, firewall or cache in front of the site when it limits what the check sees.

## v1.0.5 (2026-10-22)

More sites that hide their PHP version are recognised as PHP, from
WordPress, Drupal, phpBB and Shopware headers and cookies, further session
cookies and a Matomo header, and six new catalogue applications. Every
signal was checked against the application's own source.

- WordPress redirects, Drupal cache headers, and phpBB and Shopware cookies count as PHP hints.
- Session cookies identify Flarum, GLPI, Chamilo and LimeSurvey, and a request header Matomo.
- Zen Cart, Zabbix, Elgg, SquirrelMail, Horde and XOOPS join the application catalogue.

## v1.0.4 (2026-10-22)

Results draw on phpinfo() pages and Apache server signatures, name
disagreeing PHP versions and follow the unfixed one, and explain a FreeBSD
session extension older than PHP itself. Attested checks without a version
also ask for `/phpinfo.php` and `/info.php`.

- Document the isolated OOM-control experiment and detection limits.
- Narrow screens hide the logo.
- The vulnerable summary names an outdated session extension as a cause.
- The server check reports the session extension's version.
- FreeBSD sites get `pkg` and `service` commands for the server check.
- A phpinfo() page supplies the PHP version when no header carries one.
- Attested checks without a version ask for `/phpinfo.php` and `/info.php`.
- A phpinfo() page's server API and session settings shape the summary and advice.
- Session request evidence keeps the warning lines it counted.
- Disagreeing PHP versions are named in the summary, and the unfixed one decides.
- An Apache server signature footer that names PHP supplies a version.

## v1.0.3 (2026-10-22)

- The start page names the covered CVEs and their first fixed PHP releases.
- The address field has focus when the page loads.

## v1.0.2 (2026-10-22)

- `php2shell fingerprints` downloads the optional PHP fingerprint database.
- The service loads `/etc/php2shell/fingerprints/php.json` when present.

## v1.0.1 (2026-10-22)

- Optional PHP-focused WebAppAnalyzer database with sourced passive evidence.
- Broader passive application detection for Bludit, ProcessWire, Serendipity and Piwigo.
- The Debian package enables the service on a first install.
- The Caddy example drops the `Server` header.
- The pages carry a share image and structured data for search engines.

## v1.0.0 (2026-10-22)

Initial release.
