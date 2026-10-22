# External PHP fingerprints

The checker MAY load a separately downloaded PHP subset of
[Enthec WebAppAnalyzer](https://github.com/enthec/webappanalyzer).
The rules supplement the built-in application and framework catalogues.
They inspect existing responses and MUST NOT add requests or execute JavaScript.

## Use

Run from the source checkout:

```sh
make fingerprints
make test-fingerprint-db
make build
bin/php2shell check -passive -fingerprints local/fingerprints/php.json https://example.com/
```

The downloader uses pinned revision
`d91f7e510e93457041bea874e8a9ffb011e3e4fe`, not a moving branch.
It writes the adapted database, upstream licence, attribution notice and
input/output SHA-256 hashes under ignored `local/fingerprints/`.
The command uses Go and network access. Normal checks and
`make test` require no upstream access. Downloading rules contacts GitHub
and sends no requests to websites described by the rules.

For the service, set `fingerprint_file` to an absolute database path in
the JSON configuration, use `-fingerprints`, or set
`PHP2SHELL_FINGERPRINT_FILE`. The service account MUST be able to read the
file. The database loads once at startup; restart after changing it.
An invalid configured database MUST fail startup instead of silently
disabling the additional rules. An omitted path keeps built-in detection.

## Selection and coverage

The import selects technologies whose upstream `implies` dependency graph
reaches PHP, plus known PHP families already in our catalogues and Zen Cart.
Dependency cycles terminate. Dependencies select candidates only: a match
MUST NOT fabricate detections for implied frameworks, databases or PHP.

The pinned subset contains 261 technology labels and 429 supported passive
rules. Labels include applications, frameworks, components, plugins and
hosting products; they are not a count of independently validated applications.
Examples include Open Journal Systems, osCommerce, Zen Cart, Backdrop,
CMS Made Simple, e107, ExpressionEngine, Discuz! X and additional Symfony,
CakePHP and ThinkPHP signals.

Supported channels are exact cookie names with optional value expressions,
response headers, named meta tags and script source attributes. HTML tags
are parsed with the existing scanner; comments, inline script contents and
product mentions in prose MUST NOT become meta or script-source matches.
Repeated response headers are inspected. Missing fields MUST NOT match
an empty expression. Matching uses Go's RE2 regular expressions.

The import omits conditional `requires`/`requiresCategory` entries, raw HTML,
legacy `scripts`, CSS, DOM selectors, JavaScript objects, request observations,
URLs and incompatible lookaround/backreference expressions. It MUST NOT
remove an unsupported assertion and keep a broader replacement expression.
The manifest lists skipped applications and incompatible expressions.
Supported rules for an application remain usable when other channels are omitted.
Upstream exclusion lists are not evaluated; competing direct matches remain
low-confidence evidence rather than being resolved into a single product.

Every external match carries `database_*` signal, component scope, low
confidence, the observed URL and a link to the pinned upstream rule file.
Cookie values and matched header/meta contents MUST NOT be copied into
fingerprint evidence. Upstream version extraction is discarded; application
versions MUST NOT become PHP runtime versions. A matched component may be
served from a CDN or remain after a migration; it does not prove the runtime
or the patch state. See [method.md](method.md).

## Evaluation

`make test-fingerprint-db` compiles the downloaded rules and checks saved
synthetic responses for nine application/framework signals. It also compares
the external rules against the existing application fixtures. The pinned
subset identifies 11 of the 53 existing fixtures; those fixtures exercise
signals that often differ from the upstream database. Built-in rules remain
enabled to preserve that coverage. These are fixture results, not a measured
detection rate on public websites.

Offline tests cover dependency selection, omitted conditional/incompatible
rules, all supported response channels, false positives, secret exclusion,
PHP-version separation, concurrent matching, configuration errors and unchanged
request counts across redirects.

## Reuse and attribution

[wappalyzergo](https://github.com/projectdiscovery/wappalyzergo) offers an MIT
Go engine whose response-based API fits the checker. Its embedded database
draws from WebAppAnalyzer and HTTPArchive; the engine licence does not replace
the licences of those rule sources. This implementation uses an independently
written format adapter and downloads the selected data separately. It adds
no dependency on that library and copies none of its engine source.

WebAppAnalyzer's [GPL-3.0 licence](https://github.com/enthec/webappanalyzer/blob/d91f7e510e93457041bea874e8a9ffb011e3e4fe/LICENSE)
and attribution accompany the adapted database. The downloaded data is not
checked into this BSD repository or included in release packages. Operators
who redistribute it MUST retain its licence and notices and comply with its
terms. The downloader records the upstream revision and describes the changes.

[WhatWeb](https://github.com/urbanadventurer/WhatWeb) remains a useful
independent comparison tool. Its GPL-2.0 Ruby plugins are not imported or
executed by this checker.
