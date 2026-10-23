# Lightweight session-probe comparison

Tested on 2026-10-23. This experiment evaluates small session-ID variants
for PHP reachability and session-handling signals. It does not reproduce
exploitation payloads, serialization attacks, memory exhaustion or either
complete CVE.

## Reproduce

Run `make test-session-variants` with Docker or Colima available and the
official `php:8.5.11-apache` and `php:8.5.12-apache` images installed.
The test creates ten disposable containers with networking disabled, no
published ports, a read-only fixture mount, a 256 MiB memory cap, one CPU
and a 64-process limit. It sends nine container-loopback requests per
container and removes each container afterwards. Ordinary `make test` skips it.

The images used for this run were:

- PHP 8.5.11: `sha256:47e6d8849049375e0d19e81f1b391ed88828d4653e0d1b00822185b66b564e8b`
- PHP 8.5.12: `sha256:e25ab14ef2cfec3bab9dd66c6cf871691146f428fbd72241b1a2c38fcacf92f5`

Every request contains a fixed benign upload-progress marker and a one-byte
plain-text file, with a total multipart body below 400 bytes. Cases cover:

- No session ID.
- A valid fixed ID in a cookie, multipart form field or query string.
- An invalid underscore ID in each of those three locations.
- A NUL ID in a form field or URL-encoded query string.

Each release runs with errors visible or hidden, with
`session.use_only_cookies` on or off, plus an upload-progress-off control.
`expose_php=0` applies throughout. The fixture does not start an application
session or print a PHP version. Its body records the worker PID and effective
settings so the test can verify the server configuration and worker survival.
The PHP CLI client uses `-n` to avoid mixing its own startup diagnostics into
the response evidence. Disabling `session.use_only_cookies` produces a PHP
startup deprecation in server logs; it is not a remote patch-state signal.

## Observations

For errors visible and upload progress enabled, the counts below are
`invalid ID / failed read / failed write` occurrences in the response:

| Session ID variant | PHP 8.5.11 | PHP 8.5.12 |
|---|---|---|
| Invalid cookie | 2 / 2 / 2 | 2 / 2 / 0 |
| Invalid form field, including with cookies-only enabled | 2 / 2 / 2 | 2 / 2 / 0 |
| Invalid query, cookies-only disabled | 2 / 2 / 2 | 2 / 2 / 0 |
| Invalid query, cookies-only enabled | 0 / 0 / 0 | 0 / 0 / 0 |
| No ID, valid IDs, or NUL IDs | 0 / 0 / 0 | 0 / 0 / 0 |

Hiding errors removed all these response warnings on both releases.
Disabling upload progress also removed them.

Form-field NUL IDs caused a `Set-Cookie: PHPSESSID=...` response on both
releases when upload progress was enabled, including with errors hidden
and cookies-only enabled. Query-string NUL IDs did the same only with
cookies-only disabled. No other case emitted a session cookie. With upload
progress disabled, neither NUL variant emitted a cookie.

All 90 requests returned HTTP 200, reached the fixture and left the responding
worker alive. No container was marked OOM-killed. Status alone did not
distinguish the releases. The server did not advertise `X-Powered-By`.

## Implications for the checker

The form-field invalid-ID variant is a candidate alternative transport for
our existing warning observation. It did not expose a new vulnerability
signal or recover warning evidence with errors hidden. Testing an actual
frontend that handles cookies and form fields differently would be needed
to establish a coverage improvement in that environment.

The form-field NUL variant may supply a PHP/session reachability hint when
errors and version headers are hidden. It is identical across the tested
releases, so it MUST NOT affect vulnerability or patched verdicts. A session
cookie alone is also not unique proof of PHP. This variant can create session
state rather than merely observing it; these results do not justify enabling
it in the public checker automatically.

The query variants add no signal over the form variants in this matrix.
The current public requests and verdict logic are unchanged. Results apply
to these Apache mod_php images, the default file session handler, the tested
configuration and this fixture. They do not establish behavior for FPM,
custom session handlers, strict mode, vendor backports or application routes.
The warning distinction remains a session-path observation, not proof of
exploitability or the complete fixes for either PHP2Shell CVE.
