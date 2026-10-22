#!/bin/sh
# Installs the amd64 packages on the current stable of each distribution the
# release targets, and has the installed binary read the configuration its
# own package shipped. Requires docker. Pass the directory holding the
# packages, default dist/packages.
set -eu

cd "${1:-dist/packages}"

run() {
    docker run --rm -v "$PWD:/pkg:ro" "$1" sh -eux -c "$2
        php2shell version
        php2shell serve -config /etc/php2shell/config.json -dump-config > /dev/null
        test -f /usr/lib/systemd/system/php2shell.service
        test -f /etc/logrotate.d/php2shell"
}

run debian:stable 'dpkg -i /pkg/php2shell_*_amd64.deb'
run fedora:latest 'rpm -i /pkg/php2shell-*.x86_64.rpm'

echo "the deb and the rpm install, and the installed binary reads its configuration"
