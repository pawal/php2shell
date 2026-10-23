# Changelog

A release is a tag in the repository, and the tag is the only place a version
number is written.

## Unreleased

- Keep session observations path-scoped and reject incomplete response classifications.
- Report likelihoods without asserting complete CVE fixes or vendor backports from session warnings.
- Older session behaviour counts even when the response body breaks off.
- Session answers on pages longer than the 64 KiB cap count once page output follows the warnings.

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
