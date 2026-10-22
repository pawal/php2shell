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

The header is often absent: `expose_php=Off` removes it, and proxies and CDNs
strip it. Its number is not always upstream's either. Ubuntu and Red Hat fix
PHP without changing the version they advertise, and Debian does so on
branches the PHP project no longer maintains, so such a version is reported
as possibly backported rather than vulnerable. The header also cannot show
whether the workers were restarted after an upgrade.

## The session request

When the visitor attests that the site is theirs, the check adds one small
request to the start page, and to `/index.php` when the first gives no
answer. Patched and unpatched releases answer it differently when the server
displays PHP warnings. The request writes nothing on the server, triggers no
fault, and is a few hundred bytes.

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
| `inconclusive` | PHP is present but showed neither version nor answer | low |
| `no_php_signal` | Nothing showed PHP | low |
| `unreachable` | The site did not answer | low |

The session request outranks the header: a patched answer under an old
version number is a backport, and an unpatched answer under a fixed number
means the workers were not restarted or another PHP serves the page.

Every result carries the evidence it was drawn from and the commands that
settle the question on the server.
