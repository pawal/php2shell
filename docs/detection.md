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

A GET of flowr.dk on 2026-10-23 returned HTTP 403 with a page reading
`Your request was blocked and logged by Sansec Shield` and linking to
[Sansec's guide](https://sansec.io/guides/sansec-shield). The same request
with a browser or curl User-Agent returned HTTP 200, so Shield refused the
checker's User-Agent, which names php2shell; the guide says only that Shield
blocks attack probes. The text and the guide link together identify the
page. The checker keeps its User-Agent and does not try to pass the block.

Four header and cookie hints come from the applications' own code.
WordPress sends `X-Redirect-By: WordPress` on its redirects
([source](https://raw.githubusercontent.com/WordPress/WordPress/master/wp-includes/pluggable.php)).
Drupal core sends `X-Drupal-Dynamic-Cache`
([source](https://raw.githubusercontent.com/drupal/drupal/11.x/core/modules/dynamic_page_cache/src/EventSubscriber/DynamicPageCacheSubscriber.php))
and `X-Drupal-Cache`
([source](https://raw.githubusercontent.com/drupal/drupal/11.x/core/modules/page_cache/src/StackMiddleware/PageCache.php)).
phpBB names its session cookies `phpbb3_` in 3.3
([source](https://raw.githubusercontent.com/phpbb/phpbb/3.3.x/phpBB/phpbb/install/module/install_database/task/add_config_settings.php))
and `phpbb_` in 4.0
([source](https://raw.githubusercontent.com/phpbb/phpbb/master/phpBB/phpbb/install/module/install_database/task/add_config_settings.php)),
each followed by five random characters and `_sid`, `_u` or `_k`.
Shopware 6 names its session `session-`
([source](https://raw.githubusercontent.com/shopware/shopware/trunk/src/Core/Framework/Resources/config/packages/framework.yaml))
and Shopware 5 `session-` followed by the shop ID
([source](https://raw.githubusercontent.com/shopware5/shopware/5.7/engine/Shopware/Components/DependencyInjection/Bridge/Session.php)).

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
[applications.md](applications.md) lists fifty further researched applications
and distinguishes production artifacts from conditional diagnostic coverage.

Unknown challenge products, hidden warnings, static exports and stripped
headers still limit what the check can see. [method.md](method.md) defines
the resulting verdicts and the owner's local verification step.

## Layers in front of the site

A layer is named only from a header its vendor documents. Load balancers
that pass the origin's headers through unchanged are not named, nor are
vendors whose response headers are not publicly documented, such as
Imperva. Fastly runs on Varnish and sends `X-Varnish` too, so Varnish is
named only without Fastly. A `Via` header with no recognised vendor names a
proxy.

| Layer | Signal | Source |
|---|---|---|
| Cloudflare | header `CF-Ray` | [Source](https://developers.cloudflare.com/fundamentals/reference/http-headers/) |
| Amazon CloudFront | header `X-Amz-Cf-Id`; `Via` naming `(CloudFront)` | [Source](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/RequestAndResponseBehaviorCustomOrigin.html) |
| Fastly | `X-Served-By` entry `cache-{datacenter}{nodeid}-{datacenter}` | [Source](https://www.fastly.com/documentation/reference/http/http-headers/X-Served-By/) |
| Akamai | `Server: AkamaiGHost`; header `Akamai-GRN` | [Source](https://techdocs.akamai.com/edgeworkers/docs/common-errors), [Source](https://techdocs.akamai.com/property-mgr/docs/global-req-number) |
| Azure Front Door | header `X-Azure-Ref` | [Source](https://learn.microsoft.com/en-us/azure/frontdoor/front-door-http-headers-protocol) |
| Sucuri | header `X-Sucuri-ID`; `Server: Sucuri/` | [Source](https://docs.sucuri.net/website-firewall/troubleshooting/investigating-cache-headers/) |
| Varnish | header `X-Varnish` | [Source](https://www.varnish.org/docs/reference/vsl-query/) |
| Any proxy | header `Via` | [RFC 9110, section 7.6.3](https://www.rfc-editor.org/rfc/rfc9110#section-7.6.3) |

## Other platforms

When no answer shows PHP, the documented defaults of other platforms name
what the answers point to. Each signal is the platform's own default; a
renamed cookie or a disabled header goes unnoticed. `X-Powered-By: ASP.NET`
is not used, because IIS adds it to every response, PHP pages included.

| Platform | Signal | Source |
|---|---|---|
| Java servlets | cookie `JSESSIONID` | [Jakarta Servlet 6.0](https://jakarta.ee/specifications/servlet/6.0/jakarta-servlet-spec-6.0.html) |
| Play Framework | cookies `PLAY_SESSION`, `PLAY_FLASH` | [Source](https://raw.githubusercontent.com/playframework/playframework/main/core/play/src/main/resources/reference.conf) |
| ASP.NET | cookie `ASP.NET_SessionId` | [Source](https://learn.microsoft.com/en-us/previous-versions/dotnet/netframework-4.0/h6bb9cz9(v=vs.100)) |
| Express | cookie `connect.sid`; `X-Powered-By: Express` | [Source](https://raw.githubusercontent.com/expressjs/session/master/README.md), [Source](https://raw.githubusercontent.com/expressjs/express/master/lib/application.js) |
| Next.js | `X-Powered-By: Next.js` | [Source](https://nextjs.org/docs/app/api-reference/config/next-config-js/poweredByHeader) |
| Django | cookie `csrftoken` | [Source](https://docs.djangoproject.com/en/5.2/ref/settings/) |

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
| flowr.dk (2026-10-23) | `inspection_blocked` | HTTP 403 Sansec Shield block page, passed through Sucuri |
| cartographie.pevelecarembault.fr (2026-10-23) | `no_php_signal` | OpenID login redirects, `JSESSIONID` and renamed Play cookies; Java |

No session requests were sent to these public examples during verification.
