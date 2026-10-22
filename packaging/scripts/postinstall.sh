#!/bin/sh
set -e

if [ ! -d /run/systemd/system ]; then
    exit 0
fi

systemctl daemon-reload >/dev/null 2>&1 || true

# Respect distro preset policy on first install, and pick up the new binary
# on an upgrade without starting a service the operator had stopped.
case "$1" in
    configure)
        # deb: $2 is the previous version on upgrade, empty on first install.
        if [ -z "$2" ]; then
            if [ -x /usr/bin/deb-systemd-helper ]; then
                # enable applies the preset on a first install; there is no preset action.
                deb-systemd-helper enable php2shell.service >/dev/null 2>&1 || true
            else
                systemctl preset php2shell.service >/dev/null 2>&1 || true
            fi
        else
            systemctl try-restart php2shell.service >/dev/null 2>&1 || true
        fi
        ;;
    1)
        # rpm: 1 = first install, 2 = upgrade.
        systemctl preset php2shell.service >/dev/null 2>&1 || true
        ;;
    2)
        systemctl try-restart php2shell.service >/dev/null 2>&1 || true
        ;;
esac

exit 0
