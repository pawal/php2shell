#!/bin/sh
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

# /var/lib/php2shell holds the check log, which logrotate keeps for 30 days;
# an operator who wants it gone at once removes the directory.

exit 0
