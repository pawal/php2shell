#!/usr/bin/env bash
# Checks a list of domain names, IP addresses and URLs with php2shell check.
set -eu

usage() {
	cat >&2 <<'EOF'
Usage: tools/batch.sh [-a] [-j jobs] [-t timeout] [-o dir] [file ...]

Reads one target per line from the files, or from standard input. Blank
lines and lines starting with # are skipped; a bare IPv6 address is
bracketed. Prints one line per target, "target: verdict (confidence)",
and the verdict counts. Writes one JSON report per target and summary.tsv
to dir.

  -a          also send the session and phpinfo() requests; only for sites
              you own or may test. The default is passive.
  -j jobs     checks run at once (default 8)
  -t timeout  wall clock one check may take (default 15s)
  -o dir      output directory (default batch-YYYYmmdd-HHMMSS)

PHP2SHELL names the binary; the default is bin/php2shell, else the PATH.
EOF
	exit 1
}

mode=-passive jobs=8 timeout=15s out=batch-$(date +%Y%m%d-%H%M%S)
while getopts aj:t:o:h opt; do
	case $opt in
	a) mode= ;;
	j) jobs=$OPTARG ;;
	t) timeout=$OPTARG ;;
	o) out=$OPTARG ;;
	*) usage ;;
	esac
done
shift $((OPTIND - 1))

root=$(cd "$(dirname "$0")/.." && pwd)
bin=${PHP2SHELL:-}
if [ -z "$bin" ]; then
	if [ -x "$root/bin/php2shell" ]; then bin=$root/bin/php2shell; else bin=php2shell; fi
fi
command -v "$bin" >/dev/null || { echo "batch.sh: $bin not found; run make build" >&2; exit 1; }
command -v jq >/dev/null || { echo "batch.sh: jq is required" >&2; exit 1; }

mkdir -p "$out/json"
export bin mode timeout out

# One check, printed as target, verdict, confidence, PHP version, checked URL.
one() {
	local target=$1 file err
	file=$out/json/$(printf '%s' "$target" | tr -c 'A-Za-z0-9.-' '_').json
	if err=$("$bin" check -json $mode -timeout "$timeout" "$target" 2>&1 >"$file"); then
		jq -r --arg t "$target" '[$t, .verdict, .confidence, (.php_version.raw // "-"), .target] | @tsv' "$file"
	else
		rm -f "$file"
		err=${err#php2shell check: }
		printf '%s\terror\t-\t-\t%s\n' "$target" "$(printf '%s' "$err" | tr '\t\n' '  ')"
	fi
}
export -f one

cat "$@" | tr -d '\r' | awk '
	{ sub(/^[ \t]+/, ""); sub(/[ \t]+$/, "") }
	$0 == "" || /^#/ { next }
	!/:\/\// && !/^\[/ && gsub(/:/, ":") > 1 { $0 = "[" $0 "]" }
	!seen[$0]++' |
	tr '\n' '\0' | xargs -0 -n 1 -P "$jobs" bash -c 'one "$1"' _ |
	tee "$out/summary.tsv" |
	awk -F '\t' '
	$2 == "error" { print $1 ": error: " $5; fflush(); next }
	{ printf "%s: %s (%s confidence)%s\n", $1, $2, $3, ($4 == "-" ? "" : ", PHP " $4); fflush() }'

echo >&2
cut -f2 "$out/summary.tsv" | sort | uniq -c | sort -rn >&2
echo "reports in $out" >&2
