#!/bin/sh
# Benign php2shell session observation: one small multipart POST with an
# invalid session id in both cookie and form. Unpatched PHP tries to write
# the session anyway and emits "Failed to write session data"; patched PHP
# returns early.
url="$1"
b="----p2s$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
body=$(printf -- '--%s\r\nContent-Disposition: form-data; name="PHPSESSID"\r\n\r\n_\r\n--%s\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nprobe\r\n--%s\r\nContent-Disposition: form-data; name="f"; filename="probe.txt"\r\nContent-Type: text/plain\r\n\r\n1\r\n--%s--\r\n' "$b" "$b" "$b" "$b")
printf '%s' "$body" | curl -s -i -X POST "$url" -H "Cookie: PHPSESSID=_" -H "Content-Type: multipart/form-data; boundary=$b" --data-binary @-
