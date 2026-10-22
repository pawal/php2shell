# What a check observes

PHP2Shell is the name of CVE-2026-109618 and CVE-2026-109619, two critical
flaws in PHP itself. The PHP project fixed them on 21 October 2026 in 8.5.12,
8.4.27, 8.3.36 and 8.2.35; branches 8.1 and older receive no fix from the
project. The [PHP security advisory](https://www.php.net/archive/2026.php#2026-10-21-5)
is the authoritative description and lists the interim measures.

A check is remote, so it can show that a site is unpatched but never that it
is safe. Only a check on the server is conclusive.

## The advertised version

The check fetches the start page once and reads the PHP version from
`X-Powered-By`, or from `Server` when the first carries none. The version is
compared with the fixed release of its branch.

When no header carries a version and the start page or a discovered page
is phpinfo() output, the version that page shows is used instead, and the
result advises removing the page. The check never requests a phpinfo() page
it was not given or linked to.

The header is often absent: `expose_php=Off` removes it, and proxies and CDNs
strip it. Its number is not always upstream's either. Ubuntu and Red Hat fix
PHP without changing the version they advertise, and Debian does so on
branches the PHP project no longer maintains, so such a version is reported
as possibly backported rather than vulnerable. The header also cannot show
whether the workers were restarted after an upgrade.

## Recognising PHP without a version

Without a version, the check looks for other signs of PHP: headers,
cookies, redirect responses, generator tags, application asset paths,
sourced framework fingerprints, PHP diagnostics, and same-origin navigation
or form URLs with PHP extensions. Generator attributes may appear in any
order; comments and script text are not read as navigation or generator
tags. A CMS version is never taken for a PHP version. A hint shows PHP
somewhere on the site and is no proof of the runtime behind every path, and
exported static pages and proxies can preserve old application markers.

The check reads at most two discovered, query-free PHP endpoints on the
final origin, within a shared three-second budget, and neither follows
their redirects nor recurses. Paths naming actions such as logout, delete,
reset or installation are excluded. The address policy, pinned connections,
body cap and User-Agent apply to every request. A failed discovery request
is recorded in the evidence and does not discard the start page.

The evidence names each inspected URL and what it showed. A framework
fingerprint carries its source, its confidence and whether it is a
declaration, a default cookie or a component.
[fingerprints.md](fingerprints.md) documents the twenty covered families and
their detection limits.

Challenge pages, authentication requirements, access denials and rate limits
produce `inspection_blocked` instead of an ordinary absence of PHP evidence.
A blocked start page ends the check before discovery or session requests,
and a challenge met during the session request stops further probes.
Cloudflare's documented challenge header and known challenge-page signatures
are recognised, including the JavaScript challenge observed at 99musik.se.
The checker does not execute JavaScript or solve challenges.

[detection.md](detection.md) records the research behind these choices.

## The session request

When the visitor attests that the site is theirs, the check adds one small
request to the start page, then `/index.php` and the final redirect URL
when earlier paths give no answer. When the page identifies WordPress, the
check also tries `/wp-login.php` on the final origin, and discovered
endpoints that were inspected successfully are further candidates. Passive
checks send no session requests. Patched and unpatched releases answer
differently when the server displays PHP warnings. The request writes
nothing on the server, triggers no fault, and is a few hundred bytes.

It shows nothing when warnings are hidden, which is the production default,
when session upload progress is disabled, when the session handler is not the
file handler, or when the path is not served by PHP.

## Verdicts

| Verdict | Ground | Confidence |
|---|---|---|
| `vulnerable` | The session request answered as only unpatched releases do | high |
| `patched` | The session request answered as patched releases do | high |
| `likely_vulnerable` | The advertised version is below its branch's fix | medium |
| `possibly_backported` | As above, from a distribution that fixes without renumbering | low |
| `eol_branch` | The advertised version is 8.1 or older | medium |
| `likely_patched` | The advertised version carries the fix | medium |
| `inconclusive` | PHP indicators were found without a version or patch-state answer | low |
| `no_php_signal` | Nothing showed PHP | low |
| `inspection_blocked` | A challenge or access control prevented inspection | low |
| `unreachable` | The site did not answer | low |

The session request outranks the header: a patched answer under an old
version number is a backport, and an unpatched answer under a fixed number
means the workers were not restarted, the session extension is older than
PHP itself, or another PHP serves the page. FreeBSD packages the session
extension separately, as `php85-session`, so upgrading `mod_php85` alone
leaves the flaw in place while the header shows the fixed version.

Every result carries the evidence it was drawn from and the commands that
settle the question on the server. They include the session extension's own
version, and when the `Server` header names FreeBSD they use `pkg` and
`service` in place of the Debian and Red Hat tools.
