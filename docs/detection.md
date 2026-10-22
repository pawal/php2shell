# PHP detection research

Research date: 2026-10-22.

The [PHP manual](https://www.php.net/manual/en/security.hiding.php) explains
that a server can suppress PHP identification and process arbitrary file
extensions through PHP. A remote checker therefore cannot determine the
runtime of every site. Absence of a header, cookie or extension is not
proof that PHP is absent.

[WhatWeb's PHP detector](https://github.com/urbanadventurer/WhatWeb/blob/master/plugins/php.rb)
uses several independent channels, including HTTP headers, diagnostics and
file extensions. [WhatCMS](https://whatcms.org/Support) also matches
patterns in software artifacts, and its
[per-page detection model](https://whatcms.org/About) applies here: a PHP
application on one path does not establish the runtime on every other path.
The php2shell rules are written independently. Neither WhatWeb's code nor its
signature catalogue is imported, and no runtime dependency is added.

[Cloudflare documents](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/)
`cf-mitigated: challenge` as a challenge indicator even when the response is
HTML. Treating that HTML as the application page would lose the distinction
between blocked inspection and a successful inspection without PHP hints.
A GET of 99musik.se returned HTTP 200 with a `One moment, please...` title,
script execution and a `wsidchk` marker. Their combination is recognised as
a JavaScript challenge; the title alone is insufficient.

The checker SHOULD combine independent hints and retain their source URLs.
Generator and application versions MUST NOT become PHP versions. A PHP
extension or application asset SHOULD be reported as an indicator rather
than proof of a live PHP handler. A failed request to an arbitrary `.php`
path MUST NOT create a PHP-extension hint merely because it returned 404.

Discovery is limited to two additional GETs, on the final origin, from PHP
links and form actions in the start page. Requests contain no query string,
forward no cookies, and do not follow redirects or recurse. A shared
three-second timeout keeps discovery within the caller's overall budget.
The same network policy applies throughout. Successful discovered endpoints
can join the attested session-request candidates; passive checks perform
only GETs. An intercepted start page stops discovery and session requests.

The small attribute scanner handles quoted and unquoted attributes, HTML
entities and attribute order, and skips comments and raw-text elements. It
is deliberately conservative and is no browser or full HTML5 parser, so
malformed HTML, or a body cut off at the size cap, can reduce coverage.

A sourced framework catalogue supplements these generic signals.
[fingerprints.md](fingerprints.md) lists all twenty framework families, the
per-signal sources and confidence, and the distinction between declared
identity, default-cookie hints and component evidence. Roundcube application
rules are maintained separately from the twenty framework families.

Unknown challenge products, hidden warnings, static exports and stripped
headers still limit what the check can see. [method.md](method.md) defines
the resulting verdicts and the owner's local verification step.

## Verification

`make test`, `make build` and `make test-lab` passed on 2026-10-22.
Regression tests cover discovery limits, origin restrictions, redirect refusal,
query and action filtering, timeout preservation, passive-mode behavior,
attested discovered paths, generator parsing, redirect cookies, diagnostic
hints, challenge handling, the verdict matrix and the API response.

GET-only checks of the public examples on that date returned:

| Site | Result | Observations |
|---|---|---|
| 99musik.se | `inspection_blocked` | HTTP 200 JavaScript bot challenge |
| huvudstacentrum.se | `inconclusive` | WordPress assets and REST API, Elementor generator, WP Engine header; no PHP version |

No session requests were sent to these public examples during verification.
