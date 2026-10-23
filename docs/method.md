# What a check observes

PHP2Shell is the name of CVE-2026-109618 and CVE-2026-109619, two critical
flaws in PHP itself. The PHP project fixed them on 21 October 2026 in 8.5.12,
8.4.27, 8.3.36 and 8.2.35. Older branches have no maintained upstream release;
the project provides minimal source backports for 7.4, 8.0 and 8.1, and
vendors may provide fixed packages. The [PHP security advisory](https://www.php.net/archive/2026.php#2026-10-21-5)
is the authoritative description and lists the interim measures.

A check is remote, so its result is an assessment of the observed paths,
not proof of a complete fix or exploitability. Only verification of the
running PHP builds and vendor patches on the server is conclusive.

## The advertised version

The check fetches the start page once and reads the PHP version from
`X-Powered-By`, or from `Server` when the first carries none. The version is
compared with the fixed release of its branch.

A host name or address given without a scheme is checked over HTTPS. When
that fails fast, with a refused or reset connection or a certificate or
handshake failure, the check retries over plain HTTP, on port 80 in place of
the default 443, and the result says so. An address given with `https://` is
not retried, and neither is a timeout.

When no header carries a version and the start page or a discovered page
is phpinfo() output, the version that page shows is used instead, and the
result advises removing the page. When the visitor attests that the site is
theirs and nothing has shown a version, the check also asks for
`/phpinfo.php` and then `/info.php` on the final origin, without following
redirects, and stops at the first phpinfo() page or blocked answer. Passive
checks ask for no page they were not given or linked to.

From a phpinfo() page the check keeps four settings and nothing else:
`Server API`, `display_errors`, `session.save_handler` and
`session.upload_progress.enabled`. They explain a silent session request,
show whether the interim measure is in place, and name the processes to
restart. Such a page is read up to 256 KiB, since phpinfo() prints the
session section late.

Apache prints a server signature on error pages and directory listings,
such as `<address>Apache/2.4.62 (Debian) PHP/8.4.27 Server at example.com
Port 443</address>`. The check reads the PHP version from it on every page
it inspects, including a missing `/phpinfo.php`. The signature names PHP
only when the origin's `Server` header does, so it adds a version where a
proxy or CDN rewrote that header but passed the body through.

Every version the check sees is kept, from the headers, phpinfo() output
and server signatures of each page it reads. When they disagree, the verdict follows the one least
likely to carry the fix, and the summary names the others: more than one
PHP serves the site, or some workers were not restarted.

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
A body that breaks off is recorded as incomplete with its read error, and
the headers and text that arrived still count; only a request that got no
response at all is recorded as failed.

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
are recognised, including the JavaScript challenge observed at 99musik.se,
as is the block page of Sansec Shield, a firewall for Magento stores.
The checker does not execute JavaScript or solve challenges.

When a CDN, firewall or cache shows itself in the start page's headers,
the evidence names it. A blocked result, or one drawn without an answer
from the session request, then adds that such a layer can replace headers,
serve cached pages and filter requests. A layer that does not show itself goes unnoticed, so a
missing note proves nothing.

When nothing shows PHP but the answers carry another platform's documented
default, such as the Java servlet cookie `JSESSIONID`, the result names that
platform instead of suggesting hardened PHP. It covers only the paths the
check read; other paths on the host may still run PHP. With any PHP sign the
result stays `inconclusive`, since one host can run both.

[detection.md](detection.md) records the research behind these choices.

## The session request

When the visitor attests that the site is theirs, the check sends a small
request to each candidate: the start page, `/index.php` and the final
redirect URL. When the page identifies WordPress, the
check also tries `/wp-login.php` on the final origin, and discovered
endpoints that were inspected successfully are further candidates. Passive
checks send no session requests. The existing candidate list remains bounded
and deduplicated. An answer with the pattern associated with the fix MUST NOT
stop checks of other candidates, since another path may run older PHP. An
answer with older behaviour ends the requests, since no later answer can
change the result. A blocked answer stops further requests. It makes the
result `inspection_blocked` only when nothing else showed PHP: no version, no
PHP hint and no session answer. Otherwise the result stands on that evidence
and says the session request was blocked. When the check's
time runs out, the answers already collected stand.

The request uses an invalid session key and a one-byte upload with a fixed
benign marker; it is a few hundred bytes. It is not an exploit or an
out-of-memory probe. The displayed warning pattern differs between the
unmodified lab releases, but establishes only a session-handling observation.
It MUST NOT establish a complete fix or confirmed vulnerability for either CVE.

CVE-2026-109618 concerns OOM corruption in the engine. It is assessed from
reported versions and vendor patch information, not independently tested by
the session request. Session handling is associated with one lifecycle path
of CVE-2026-109619; the complete fixes cover more state and operations than
this observation exercises. The evidence does not establish that either
vulnerability is exploitable on the target.

Each session observation keeps its URL, status, warning counts, completeness,
read error if any, and `session_result`. A response MUST be unblocked and
HTTP 2xx or 3xx before a warning pattern is classified; with output buffering
on, an application can answer the request with a redirect whose body still
carries the warnings. Older behaviour, all three
warnings, is classified from whatever arrived, since a cut-off body can hide
the third warning but not invent it. The pattern associated with the fix,
the first two warnings without the third, requires that every startup
warning was read: a complete body, or at least 1 KiB of output after the last
session warning. PHP prints these warnings during request startup, before any
page output, so a page longer than the body cap still counts once its output
follows them. Body caps are detected with a bounded extra byte; an exact-size
complete body remains eligible. A body that breaks off or ends at the cap
within 1 KiB of the last session warning leaves the first two warnings
unclassified, since the absence of a third warning is then not evidence of a
fix. Partial passive responses MAY
still supply headers and hints, with their incompleteness recorded.

It shows nothing when warnings are hidden, which is the production default,
when session upload progress is disabled, when the session handler is not the
file handler, or when the path is not served by PHP.

The evidence keeps each distinct warning line the answer was counted from,
as plain text, at most six lines of 300 bytes each.

## Verdicts

| Verdict | Ground | Confidence |
|---|---|---|
| `likely_vulnerable` | An affected reported version, or older session behaviour on a named path | medium |
| `possibly_backported` | As above, from a distribution that fixes without renumbering | low |
| `eol_branch` | The advertised version is 8.1 or older | medium |
| `likely_patched` | The advertised version carries the fix | medium |
| `inconclusive` | PHP indicators or a changed session response without a usable version | low |
| `no_php_signal` | Nothing showed PHP | low |
| `inspection_blocked` | A challenge or access control prevented inspection | low |
| `unreachable` | The site did not answer | low |

The `vulnerable` and `patched` API codes remain reserved for compatibility;
current checks MUST NOT emit these confirmed, high-confidence verdicts.

An `unreachable` result names the reason: the connection timed out, was
refused or reset, or TLS failed. A site that opens in a browser but times
out or refuses the checker is most likely blocking the checker's address.

Changed session behaviour MUST NOT override an older version on any
inspected path or establish a complete backport. With no version it remains
inconclusive. With a fixed reported version the overall result is at most
likely patched. Older session behaviour takes priority in aggregation and
produces a likely-vulnerable result naming the affected path, but
still does not prove exploitability or the state of the separate OOM fix.
On an end-of-life version the result stays `eol_branch` with its advice. On
a distribution version that may carry a backport, the older behaviour argues
against the backport, so the result is likely vulnerable rather than possibly
backported.

A fixed version accompanied by older session behaviour is conflicting
evidence. The result advises verifying the running workers, vendor patches
and the session extension rather than asserting an explanation. FreeBSD
packages the session extension separately, so mixed component versions are
one possible cause. No result advises that no action is needed merely
because a session response changed.

Every result carries the evidence it was drawn from and the commands that
settle the question on the server. They include the session extension's own
version, and when the `Server` header names FreeBSD they use `pkg` and
`service` in place of the Debian and Red Hat tools.
