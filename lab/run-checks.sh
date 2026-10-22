#!/bin/bash
LAB="$(cd "$(dirname "$0")" && pwd)"
run() {
  name="$1"; port="$2"
  echo "################ $name  (http://127.0.0.1:$port/) ################"
  echo "--- passive GET headers ---"
  curl -s -I "http://127.0.0.1:$port/" | grep -i -E "^(HTTP|server|x-powered-by|set-cookie)"
  echo "--- oracle POST ---"
  out=$("$LAB/oracle.sh" "http://127.0.0.1:$port/")
  echo "$out" | head -1
  echo "$out" | grep -i -E "^set-cookie" || echo "(no Set-Cookie)"
  echo "markers: too_long=$(echo "$out" | grep -c 'Session ID is too long') failed_read=$(echo "$out" | grep -c 'Failed to read session data') failed_write=$(echo "$out" | grep -c 'Failed to write session data')"
  echo "--- body (tags stripped) ---"
  echo "$out" | sed -n '/^\r$/,$p' | sed 's/<[^>]*>//g' | grep -v '^\s*$' | head -8
  echo
}
run vuln 18081
run patched 18082
run "vuln-hardened (display_errors=Off, expose_php=Off)" 18083
