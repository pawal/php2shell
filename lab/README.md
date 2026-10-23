# php2shell detection lab

Three official PHP Apache images with a one-line index.php baked in, and a
static nginx for contrast:

| Service | Port | Image | Config |
|---|---|---|---|
| vuln | 18081 | php:8.5.11-apache | defaults (display_errors on, expose_php on) |
| patched | 18082 | php:8.5.12-apache | defaults |
| vuln-hardened | 18083 | php:8.5.11-apache | display_errors=Off, expose_php=Off |
| static | 18084 | nginx:1.29-alpine | no PHP at all |

```
docker compose up -d --build
./run-checks.sh          # passive header check + oracle POST against all three
./oracle.sh http://host/ # the oracle alone, prints the full HTTP response
./valid-id.sh http://host/ [sid]  # rejected valid-id probe, identical on both
docker compose down --rmi local
```

Expected: vuln shows "Failed to write session data" in the oracle response,
patched shows only the two "read" warnings, vuln-hardened shows nothing.
The fix returns early when session initialization fails; before it, PHP
forced the session active and tried to write it anyway.
`make test-lab` now expects `likely_vulnerable` for the unpatched container
and `likely_patched` for the patched container. The session warning pattern
is an observation on that URL, not proof of both complete CVE fixes.

## Ordinary OOM control

`make test-oom-control`, run from the repository root, compares ordinary
application allocation failures on PHP 8.5.11 and 8.5.12 with errors shown
and hidden. It uses disposable containers with networking disabled and no
published ports. The test requests its fixtures over container loopback,
checks worker survival and removes its containers afterwards.

The fatal-error text occurs on both releases. This is a negative control
for error-message detection, not a CVE-triggering or exploit test. See
[the results and limitations](../docs/oom-detection.md). The test is skipped
during ordinary `make test` and runs only through `make test-oom-control`.

## Lightweight session variants

`make test-session-variants` compares cookie, form and query-string IDs,
including invalid and NUL IDs, in disconnected PHP 8.5.11 and 8.5.12
containers. It varies error visibility, cookie-only configuration and upload
progress. The form variant reproduces the existing warning signal; NUL IDs
can produce a session cookie on both releases even with errors hidden.
It also sends cookie-only, form-only and combined IDs through two Apache
reverse proxies on container loopback, one forwarding cookies and one
stripping them. The form field keeps the warning signal when the cookie is
stripped, which is why the public request now carries the ID in both places.
See [docs/session-variants.md](../docs/session-variants.md) for the results
and limits. `make test` skips the experiment.
