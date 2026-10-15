# Living off the land on Linux

Full writeup: [jperezduerto.info/techniques/linux-living-off-the-land](https://jperezduerto.info/techniques/linux-living-off-the-land/)

Enumerate a Linux host you already have a shell on using only what is installed:
bash, coreutils, `/proc`, and the standard admin binaries. Quieter than dropping
tooling, works when you cannot download anything, and exactly what a defender
should be able to see. Everything here is read-only reconnaissance that surfaces
the privilege-escalation path; the exploitation step for a given finding lives
at [GTFOBins](https://gtfobins.github.io/), not here.

`enum.sh` bundles the read-only checks below into one pass.

## Orientation

```bash
id; whoami; hostname; uname -a; cat /etc/os-release; echo "$PATH"
```

## Port scan with bash (no nmap)

```bash
# localhost 1-1024
for p in $(seq 1 1024); do (echo >/dev/tcp/127.0.0.1/"$p") 2>/dev/null && echo "open: $p"; done
# one host:port
timeout 1 bash -c 'echo >/dev/tcp/10.0.0.5/22' 2>/dev/null && echo open || echo closed
```

Finds loopback-only services and reachable neighbors. Loud: a shell opening many
connections in a burst is a strong signal.

## Network

```bash
ip -4 addr; ip route
ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null
cat /proc/net/tcp 2>/dev/null; cat /etc/hosts /etc/resolv.conf; ip neigh
```

## Users

```bash
awk -F: '$3>=1000 || $1=="root"{print}' /etc/passwd
getent group | grep -vE ':$'
sudo -n -l 2>/dev/null
w; who; last -n 20
ls -la /home/*/ ~/.ssh 2>/dev/null
```

Watch for powerful group membership: `docker`, `lxd`, `disk`, `sudo`, `adm`.

## Privilege-escalation surface

Enumeration only; each result points at a path, and GTFOBins has the technique.

```bash
find / -perm -4000 -type f 2>/dev/null          # SUID
find / -perm -2000 -type f 2>/dev/null          # SGID
getcap -r / 2>/dev/null                          # file capabilities
cat /etc/crontab; ls -la /etc/cron.* 2>/dev/null # scheduled jobs
echo "$PATH" | tr ':' '\n' | while read d; do [ -w "$d" ] && echo "writable PATH: $d"; done
find / -writable -type f 2>/dev/null | grep -vE '^/proc|^/sys'
ls -la /etc/passwd /etc/shadow 2>/dev/null
ps -eo user,pid,cmd | awk '$1=="root"'
cat /etc/exports 2>/dev/null
id | grep -qE 'docker|lxd' && echo "container group: likely root-equivalent"
```

A non-standard SUID binary, `cap_setuid` on an ordinary program, a writable
cron script, a writable `PATH` dir ahead of the real one, a world-writable
`/etc/passwd`, or a root-equivalent group is usually the escalation.

## Detection

- **auditd** on the recon binaries and sensitive reads:

  ```
  -a always,exit -F arch=b64 -S execve -F exe=/usr/bin/find -k recon
  -a always,exit -F arch=b64 -S execve -F exe=/usr/sbin/getcap -k recon
  -w /etc/shadow -p r -k shadow_read
  -w /etc/exports -p r -k exports_read
  ```

  One user firing `find`, `getcap`, `sudo -l`, `ss`, and `/etc/passwd` reads
  within seconds is the enumeration pattern.
- **Bash port scanner.** A shell opening many short-lived TCP connections to
  sequential ports (loopback or a subnet) stands out in connection telemetry
  and `/proc` socket churn, with no scanner binary involved.
- **Process ancestry.** A service account whose shell suddenly runs interactive
  recon, with the process tree rooted in that service, is high-signal.

## Hardening, briefly

Least privilege for service accounts; remove SUID from what does not need it and
baseline the rest; tight, specific `sudo` rules; patch the kernel; keep auditd
on so the recon burst is recorded.

## Use

Authorized and educational use only: your own systems, a lab you control, or an
engagement with written permission. Read-only enumeration to map a host you are
authorized to assess and to show defenders what that mapping looks like.
