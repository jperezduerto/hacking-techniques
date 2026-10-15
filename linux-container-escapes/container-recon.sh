#!/usr/bin/env bash
# Read-only container reconnaissance: am I contained, and what bridges to the
# host? Reads only; writes nothing and escapes nothing. Authorized and
# educational use only.
# Writeup: https://jperezduerto.info/techniques/linux-container-escapes/

section() { printf '\n=== %s ===\n' "$1"; }

section "Containment markers"
ls -la /.dockerenv 2>/dev/null && echo "/.dockerenv present"
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/cgroup 2>/dev/null

section "Capabilities in effect"
grep CapEff /proc/self/status 2>/dev/null
capsh --decode="$(grep CapEff /proc/self/status 2>/dev/null | awk '{print $2}')" 2>/dev/null

section "Docker socket mounted in?"
ls -la /var/run/docker.sock 2>/dev/null && echo "docker.sock is reachable"

section "Mounts (host paths, cgroups)"
(findmnt 2>/dev/null || cat /proc/mounts 2>/dev/null) | grep -iE 'host|/root|/etc|cgroup|docker' | head -40

section "Host PID namespace shared?"
ls /proc/1/root 2>/dev/null && echo "can see host root via /proc/1/root (shared PID ns likely)"

section "Device access (privileged indicator)"
ls -la /dev 2>/dev/null | grep -iE 'sd|nvme|xvd|mapper' | head

printf '\nDone. A mounted docker.sock, a privileged container, CAP_SYS_ADMIN, a shared host PID ns, or a host dir mounted rw is the bridge; the writeup maps each to its escape.\n'
