#!/bin/bash
# Same multipart probe as oracle.sh but with a VALID session id.
url="$1"; sid="${2:-p2svalid0123456789}"
b="----p2s$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
body=$(printf -- '--%s\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nprobe\r\n--%s\r\nContent-Disposition: form-data; name="f"; filename="probe.txt"\r\nContent-Type: text/plain\r\n\r\n1\r\n--%s--\r\n' "$b" "$b" "$b")
printf '%s' "$body" | curl -s -i -X POST "$url" -H "Cookie: PHPSESSID=$sid" -H "Content-Type: multipart/form-data; boundary=$b" --data-binary @-
