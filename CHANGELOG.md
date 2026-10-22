# Changelog

A release is a tag in the repository, and the tag is the only place a version
number is written.

## Unreleased

- Attested checks try `/wp-login.php` when WordPress is detected and earlier paths are silent.

- Passive fetching and the session patch-state request, with bounded redirects and pinned addresses.
- Lab acceptance passes for unpatched, patched, hardened PHP and a static server.
- `make test-live` runs the lab's expectations against public instances under the public policy.
- A PHP application behind a cache is recognised from its cookies, its Link header and its page markers, not only from a PHP header.

- Targets are public names and addresses on ports 80, 443, 8080 and 8443.
- IPv4 carried in IPv6 is refused in every form, not unwrapped.
- A host is resolved once per check and only its validated addresses are dialled.
- The verdict matrix reads the advertised version, the distribution and the session request.
- `php2shell check`, `serve` and `version`.
- The page and the about page, with canonical links, robots.txt and sitemap.xml.
- Security headers on every route; a content policy with no inline style or script.
- Rate limit per client, cooldown per host, a cap on checks in flight.
- The check log holds time, host and verdict, never the client.
- deb and rpm packages with a hardened unit, logrotate and the Caddy example.
