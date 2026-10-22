# Memory-exhaustion detection control

Reviewed and tested 2026-10-22. This experiment evaluates whether a PHP
memory-exhaustion fatal error alone distinguishes PHP2Shell patch state.
It does not reproduce a memory-corruption exploit or O3's exact probe.

## Published criterion

[O3's scanner page](https://o3.security/tools/php2shell-scanner) describes a
multipart probe intended to exhaust PHP memory. It says that a returned
memory-exhaustion fatal-error signature produces a vulnerable verdict.
The page associates the scanner with CVE-2026-109618 and CVE-2026-109619.
Its [technical article](https://o3.security/blog/php2shell-cve-2026-109618-109619-analysis)
describes both vulnerability families.

The [PHP advisory for CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
describes invalid request state caused by an early out-of-memory exit.
The fix changes allocation-failure handling and preserves memory limits.
An ordinary allocation failure MUST NOT, by itself, be treated as evidence
that this memory-corruption condition occurred.

## Reproduction

Run `make test-oom-control` from the source checkout. Docker or Colima and
the official `php:8.5.11-apache` and `php:8.5.12-apache` images are required.
The test creates four disposable containers, each with networking disabled,
no published ports, a 256 MiB memory cap, one CPU and a 64-process limit.
Only the test's read-only document root is mounted. Containers are removed
after their individual tests.

The fixture sets PHP's request memory limit to 16 MiB, then attempts a
single ordinary 32 MiB string allocation. A small HTTP client inside the
container requests this endpoint over loopback. This is application-level
allocation failure, not a multipart parser attack. The test repeats with
`display_errors` enabled and disabled on each PHP version.

It records the response status and presence of `Allowed memory size of`,
checks the Apache log for the fatal error, verifies that the responding
worker PID still exists, requests the normal health page, and checks that
the container was not killed by its memory cap.

## Observed results

| PHP | display_errors | HTTP status | Memory fatal in body | Fatal in log | Worker survived | Next request |
|---|---|---|---|---|---|---|
| 8.5.11 | On | 200 | Yes | Yes | Yes | OK |
| 8.5.12 | On | 200 | Yes | Yes | Yes | OK |
| 8.5.11 | Off | 500 | No | Yes | Yes | OK |
| 8.5.12 | Off | 500 | No | Yes | Yes | OK |

None of the four containers was marked as killed by the container memory limit.
The error message appeared on both patched and unpatched PHP, and did
not imply that the worker process crashed. Hiding errors removed the
response signature on both versions. HTTP status did not distinguish them.

## Conclusion and limits

A generic PHP memory-exhaustion fatal error MUST NOT produce a confirmed
PHP2Shell vulnerability verdict. It is evidence of allocation failure.
An absent error MUST NOT produce a patched verdict either.

This control demonstrates that the message itself is not patch-specific.
It does not establish O3's actual false-positive rate or reproduce O3's
specific multipart probe. No published server-side probe implementation
was identified in the reviewed pages or public client code. Assessing that
probe requires its exact request and decision logic, followed by comparison
on controlled patched and unpatched targets with matched configuration.

The checker MUST NOT add memory-exhaustion probes to its public workflow
on the strength of the published error-message criterion. Its existing
session-path observations are a separate patch-associated signal, with
the limits described in [method.md](method.md).
