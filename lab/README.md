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
