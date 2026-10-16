#!/usr/bin/env bash
# Read-only: from a shell obtained through a service, report which systemd
# confinements apply so a working exploit is not mistaken for a failed one, and
# where you can actually write. Reads only; changes nothing. Authorized and
# educational use only.
# Writeup: https://jperezduerto.info/techniques/systemd-confinement-gotchas/

section() { printf '\n=== %s ===\n' "$1"; }

section "NoNewPrivileges on this process tree"
if grep -q '^NoNewPrivs:\s*1' /proc/self/status 2>/dev/null; then
  echo "NoNewPrivs=1  -> su/sudo/SUID will FAIL here even with a valid password."
  echo "   Way out: reuse the credential over SSH (sshd is a separate unit)."
else
  echo "NoNewPrivs=0  -> setuid escalation is not blocked by this flag."
fi

section "nosuid mounts (SUID payloads are inert on these)"
mount 2>/dev/null | grep -E 'nosuid' | grep -E '/tmp|/home|/dev/shm|/var' || echo "none on the usual drop dirs"

section "PrivateTmp / Protect* on local service units"
grep -rilE 'PrivateTmp|ProtectHome|ProtectSystem' /lib/systemd/system/ /etc/systemd/system/ 2>/dev/null | head -20
echo "(if your daemon is listed, a file you 'wrote' to /tmp is in its private namespace, not yours)"

section "Writable, non-namespaced drop targets (prove exec here)"
for d in /dev/shm /run/shm /var/tmp /opt /var/backups; do
  [ -d "$d" ] && [ -w "$d" ] && echo "writable: $d"
done
[ -w /root/.ssh ] 2>/dev/null && echo "writable: /root/.ssh  (running as root -> drop an authorized_keys entry and SSH in)"

section "Am I namespaced? (compare /tmp views)"
echo "this shell's /tmp inode: $(stat -c %i /tmp 2>/dev/null)"
echo "systemd private tmp dirs present: $(ls -d /tmp/systemd-private-*/ 2>/dev/null | wc -l)"

printf '\nRule: if an exec primitive returned success but the artifact is missing or su failed, that is confinement, not a failed exploit. Prove exec in /dev/shm, then pick a delivery the confinement does not block.\n'
