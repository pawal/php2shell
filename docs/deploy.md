# Running a public instance

`php2shell serve` is one static binary with the page embedded. It serves plain
HTTP and expects a reverse proxy in front of it to terminate TLS. It keeps no
database: rate limits and cached results live in the process, and the only
file it writes is the check log. The HTTP API is specified in
[openapi.yaml](openapi.yaml), and what a check observes is described in
[method.md](method.md).

    make build            # bin/php2shell
    php2shell serve -config /etc/php2shell/config.json

A build reports its version as the module version and the short commit it was
built from; a tree holding uncommitted changes adds `.dirty`. The version is
answered by `/api/v1/version` and shown in the page footer.

## Installing from a package

A tagged release carries a `.deb` and an `.rpm` for amd64 and arm64. They
install the binary as `/usr/bin/php2shell`, the configuration as
`/etc/php2shell/config.json`, the unit below, a logrotate rule as
`/etc/logrotate.d/php2shell`, and this document with
[external-fingerprints.md](external-fingerprints.md) and the Caddy example
under `/usr/share/doc/php2shell/`. The service is enabled according to the
distribution's preset policy and is restarted on upgrade.

The optional PHP fingerprint database is not packaged. Run as root,
`php2shell fingerprints` downloads it to `/etc/php2shell/fingerprints/`,
where the service finds it at the next restart without a configuration change.

## Configuration

Four layers, each overriding the one before: the built-in defaults, the
`-config` file, `PHP2SHELL_*` environment variables, then flags. Every key has
a flag and a variable of its own: `php2shell serve -h` lists them, and
`php2shell serve -dump-config` prints the effective configuration in a form
that loads back unchanged. A file naming an unknown key is refused.

```json
{
  "listen_addr": "127.0.0.1:8080",
  "public_url": "https://php2shell.evilbit.de",
  "provider": "evilbit.de",
  "provider_url": "https://evilbit.de/",
  "source_url": "https://github.com/pawal/php2shell",
  "contact": "abuse@evilbit.de",
  "trusted_proxy_cidrs": ["127.0.0.1/32", "::1/128"],
  "source_addresses": ["5.75.244.113", "2a01:4f8:c012:1000::1"],
  "rate_limit": { "enabled": true, "max": 10, "window": "1h" },
  "target_cooldown": "5m",
  "max_concurrent_checks": 10,
  "check_timeout": "15s",
  "log_file": "/var/lib/php2shell/checks.log",
  "max_body_size": 4096,
  "read_timeout": "10s",
  "write_timeout": "30s",
  "idle_timeout": "60s"
}
```

Notes on the keys:

- `listen_addr` SHOULD be a loopback address; the proxy is the only client.
- `public_url` is the origin the canonical links, the share image, the
  structured data, the sitemap and the outbound `User-Agent` name. It MUST be
  the name the proxy answers on. Left empty, the documents carry no canonical
  link, share image or structured data, and `/sitemap.xml` answers 404.
- `provider` and `provider_url` fill the footer line "This service is
  provided by". `source_url` is the source link of the footer and the about
  page. `contact`, when set, is offered on the about page for opt-out
  requests.
- `source_addresses` lists the addresses checks leave from. The about page
  shows them so that site owners can let the check through a firewall. Each
  MUST be an IP address; empty shows none.
- `trusted_proxy_cidrs` lists the peers whose forwarded client address and
  protocol are trusted. From any other peer those headers are stripped.
  Without the proxy in the list, the rate limit counts the proxy instead of
  the client and the origin check cannot see `https`.
- `rate_limit` bounds checks per client address: `max` per `window`, counted
  on every POST to `/api/v1/check`. An IPv6 client is counted by its `/64`,
  the block one subscriber or host is given, so rotating addresses inside it
  gains nothing. A refusal is 429 with `Retry-After`. The counters live in the
  process and are forgotten when they leave the window. At most 100,000
  clients are tracked; while the table is full, new clients are refused until
  the next sweep.
- `target_cooldown` is how long a result answers repeated checks of the same
  origin, the scheme, host and port; another path on it receives the same
  result. Two checks of one origin at once run once. A result made without
  the session request does not answer a request for it. A request with
  `refresh` runs a fresh check once the cached result is a minute old, so an
  owner can check again after patching. The cache holds at most 10,000
  results and 64 MiB of them, measured as encoded JSON; past either bound it
  starts over. Zero disables the cache.
- `max_concurrent_checks` bounds checks in flight; past it a check is refused
  with 503 and `Retry-After`. `check_timeout` bounds one check.
- `log_file` receives one line per check; see below. Empty logs nothing.
- `fingerprint_file` MAY name a separately downloaded PHP fingerprint database.
  Empty loads `/etc/php2shell/fingerprints/php.json` when that file exists.
  The database loads once at startup; an invalid one prevents startup. See
  [external-fingerprints.md](external-fingerprints.md) for installation,
  coverage and the external data licence.
- `allow_non_global_addresses` lifts the address and port policy, so private
  addresses and any port can be checked. It exists for the lab and MUST NOT
  be set on a public instance. A node that sets it logs a warning at start,
  and `/api/v1/info` reports it to any client.

## Address policy

A target is a public domain name or a public IP address, on port 80, 443,
8080 or 8443. A name must have at least two labels and a top label that is
not numeric. Every address the name resolves to must be public unicast; if
any is not, the target is refused with 400 `non_global_address` before a
request is sent. The policy declines the IANA special-purpose ranges that
are not globally reachable, multicast, and every IPv6 address outside
`2000::/3`.
Every form that carries an IPv4 address inside IPv6 is refused rather than
unwrapped: IPv4-mapped, IPv4-compatible, IPv4-translated, NAT64, 6to4,
Teredo and ISATAP. A host is resolved once per check and only the validated
addresses are dialled, so a second DNS answer cannot move the connection.
The same policy applies to every redirect.

## systemd unit

```ini
[Unit]
Description=PHP2Shell check service
Documentation=file:/usr/share/doc/php2shell/deploy.md
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/php2shell serve -config /etc/php2shell/config.json
EnvironmentFile=-/etc/php2shell/php2shell.env
DynamicUser=yes
StateDirectory=php2shell
UMask=0027
Restart=on-failure
RestartSec=5s
LimitNOFILE=8192
MemoryHigh=384M
MemoryMax=512M
Environment=GOMEMLIMIT=320MiB
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
```

`StateDirectory` is the one directory the service may write, so `log_file`
MUST lie under `/var/lib/php2shell/`. `MemoryMax` caps the service at 512 MB,
so an attack on its memory cannot starve Caddy or the host; past it the
service is killed and restarted. `GOMEMLIMIT` makes the Go runtime collect
garbage harder well before that, and `MemoryHigh` starts reclaiming at 384 MB.

## Address filter in the kernel

The address policy in the binary is the only barrier between a check and
non-public addresses. A systemd drop-in adds a second barrier that the kernel
enforces, so a fault in the binary cannot reach the provider's metadata
service, private networks or multicast:

```ini
[Service]
IPAddressAllow=localhost
IPAddressDeny=link-local multicast 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fc00::/7
```

Install it with `systemctl edit php2shell` and restart the service. The
loopback stays allowed, because the reverse proxy reaches the service there
and a local resolver such as systemd-resolved listens there; services on the
loopback remain protected by the address policy alone.

The drop-in is not part of the package, because some hosts need a denied
range. It MUST NOT be used when `/etc/resolv.conf` names a resolver in a
denied range, such as `169.254.169.253` on AWS or a resolver on a private
network. A resolver on the loopback is fine, since it queries its upstream
servers outside this unit.

To verify, a request to the metadata address under the same rule MUST fail,
and a check of a public site MUST still succeed:

    systemd-run -p IPAddressDeny=link-local --wait --pipe curl -sS -m 3 http://169.254.169.254/
    curl -s -X POST http://127.0.0.1:8080/api/v1/check -H 'Content-Type: application/json' -d '{"url":"example.com"}'

Without kernel support for the BPF filter, systemd logs a warning and lets
the traffic through.

## Reverse proxy

The binary has no TLS listener. Terminate TLS in Caddy and keep `listen_addr`
on the loopback:

```caddyfile
php2shell.evilbit.de {
	encode zstd gzip
	header Strict-Transport-Security "max-age=31536000"
	header -Server
	reverse_proxy 127.0.0.1:8080
}
```

Caddy obtains the certificate, redirects plain HTTP to HTTPS, passes `Host`
through and sets `X-Forwarded-For` and `X-Forwarded-Proto`. Five rules:

- Pass `Host` through unchanged. A check is accepted only when its `Origin`
  matches the request's own host.
- Set `Strict-Transport-Security` at the proxy. The binary does not know
  that TLS terminates in front of it.
- Drop the `Server` header Caddy adds, on a `header` line of its own. A
  delete defers every operation on its line to the upstream response, so
  HSTS beside it would be missing from the errors Caddy writes itself. Those
  errors and the HTTP redirect still name Caddy.
- Add no Content-Security-Policy. The binary sets its own per route, and a
  second policy intersects with it and can only break the page.
- Enable no access log. Caddy logs no requests unless told to. An access log
  records client addresses, which the service promises not to keep.

## Security headers

The binary sets these on every response:

| Header | Documents | API |
|---|---|---|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'` | `default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` |
| `X-Content-Type-Options` | `nosniff` | `nosniff` |
| `X-Frame-Options` | `DENY` | `DENY` |
| `Referrer-Policy` | `no-referrer` | `no-referrer` |
| `Cross-Origin-Opener-Policy` | `same-origin` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-origin` | `same-origin` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=(), usb=()` | the same |
| `Cache-Control` | `no-cache`, and `public, max-age=86400` under `/static/` | `no-store` |

## The check log

One line per check, appended to `log_file`:

    2026-10-22T12:00:00Z example.com likely_patched passive
    2026-10-23T08:43:11Z threeman.info unreachable oracle timeout

The fields are the time in UTC, the host that was checked, the verdict,
`refused:<code>` for a target the policy declined, or `error:<code>` for a
check that failed, and whether the session request was sent (`oracle`) or not
(`passive`). An `unreachable` line adds why: `timeout`, `refused`, `reset`,
`certificate`, `handshake` or `connection`. An `inspection_blocked` line adds
what blocked it, such as `http-403-access-denied` or `sansec-shield-firewall`. The address of the client is never written, and the request log
on standard error omits it too. The packaged logrotate rule keeps 30 days.

## Health

`GET /healthz` answers `ok`. `GET /api/v1/info` reports the version, the rate
limit, the cooldown and whether `allow_non_global_addresses` is set.
