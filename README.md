# PHP2Shell check

A public service that tells site owners whether their website runs a PHP
release exposed to PHP2Shell, CVE-2026-109618 and CVE-2026-109619, and what
to do about it. It ships as one Go binary with no dependencies beyond the
standard library: a command line check, and a web service with the page
embedded.

## Status

The address policy, passive fetch, session request, verdict engine, service
and page are implemented. Unit tests cover the network checks against local
HTTP and HTTPS servers, and the Docker lab acceptance tests pass using
Colima. The manual Firefox pass and public deployment remain to be verified.

## Overview

A check reads the PHP version a site advertises and compares it with the
fixed releases. When the visitor attests that the site is theirs, it adds one
small request whose answer differs between patched and unpatched PHP. A
remote check can show that a site is unpatched but never that it is safe, so
every result says what it was drawn from and how to settle the question on
the server. [docs/method.md](docs/method.md) describes what is observed and
what each verdict means.

Without a version, the check looks for other signs of PHP in the response
and in up to two PHP pages the start page links to on the same origin. A
challenge page or an access denial is reported as blocked inspection.
[docs/detection.md](docs/detection.md) records the research and its limits,
and [docs/fingerprints.md](docs/fingerprints.md) lists the twenty framework
families in the sourced fingerprint catalogue.
[docs/applications.md](docs/applications.md) lists 53 further PHP
applications and their supported signals.

Only public domain names and public IP addresses are checked, on ports 80,
443, 8080 and 8443. Non-public addresses are refused before any request is
sent, including every form that carries IPv4 inside IPv6.

## Installation

Go 1.27 or later is required.

    make build            # bin/php2shell

A tagged release also carries a `.deb` and an `.rpm` for amd64 and arm64,
which install the binary, a configuration, a logrotate rule and a systemd
unit; [docs/deploy.md](docs/deploy.md) says what they place where.

## Command line

    php2shell check example.com
    php2shell check -json https://www.example.com/
    php2shell check -passive example.com
    php2shell serve -config /etc/php2shell/config.json
    php2shell version

`check` sends the session request unless `-passive` is given, since the
person at the command line is taken to own the target. `-allow-non-global`
lifts the address and port policy for the lab.

## Service

`php2shell serve` answers the page at `/` and `/about`, and the API under
`/api/v1`, specified in [docs/openapi.yaml](docs/openapi.yaml). It keeps no
database. The only file it writes is the check log: the time, the checked
host and the verdict, never the client's address.
[docs/deploy.md](docs/deploy.md) covers the configuration, the systemd unit,
the Caddy configuration and the security headers.

## Development

    make test        # gofmt, vet, race tests, content policy
    make test-lab    # live acceptance tests against the Docker lab
    make test-live   # the same against public instances named in PHP2SHELL_LIVE_*

`make test` is the gate. `make test-lab` needs Docker; the lab in
[lab/README.md](lab/README.md) runs an unpatched, a patched and a hardened
PHP side by side.

## License

BSD 2-Clause; see [LICENSE](LICENSE).
