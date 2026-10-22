# Changelog

A release is a tag in the repository, and the tag is the only place a version
number is written.

## Unreleased

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
