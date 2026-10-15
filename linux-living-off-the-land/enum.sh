#!/usr/bin/env bash
# Living off the land: read-only local enumeration using only base tools.
# Surfaces the privilege-escalation path; it does NOT exploit anything and
# writes nothing. Authorized and educational use only.
# Writeup: https://jperezduerto.info/techniques/linux-living-off-the-land/

section() { printf '\n=== %s ===\n' "$1"; }

section "Orientation"
id; whoami; hostname; uname -a; cat /etc/os-release 2>/dev/null; echo "PATH=$PATH"

section "Listening sockets"
ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null

section "Network"
ip -4 addr 2>/dev/null; ip route 2>/dev/null; ip neigh 2>/dev/null
cat /etc/hosts /etc/resolv.conf 2>/dev/null

section "Users and groups"
awk -F: '$3>=1000 || $1=="root"{print}' /etc/passwd 2>/dev/null
getent group 2>/dev/null | grep -vE ':$'
sudo -n -l 2>/dev/null
w 2>/dev/null; last -n 20 2>/dev/null
ls -la /home/*/ "$HOME/.ssh" 2>/dev/null

section "SUID / SGID"
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

section "Capabilities"
getcap -r / 2>/dev/null

section "Scheduled jobs"
cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null

section "Writable locations"
echo "$PATH" | tr ':' '\n' | while read -r d; do [ -w "$d" ] && echo "writable PATH: $d"; done
find / -writable -type f 2>/dev/null | grep -vE '^/proc|^/sys' | head -50
ls -la /etc/passwd /etc/shadow 2>/dev/null

section "Root processes and exports"
ps -eo user,pid,cmd 2>/dev/null | awk '$1=="root"'
cat /etc/exports 2>/dev/null
id 2>/dev/null | grep -qE 'docker|lxd' && echo "container group: likely root-equivalent"

printf '\nDone. Read each result for the privilege boundary it crosses; GTFOBins has the technique.\n'
