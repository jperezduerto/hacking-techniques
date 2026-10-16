# systemd confinement gotchas

Full writeup: [jperezduerto.info/techniques/systemd-confinement-gotchas](https://jperezduerto.info/techniques/systemd-confinement-gotchas/)

A working exploit through a service can read as broken because of systemd
confinement, not a failed primitive. `PrivateTmp` hides the file you wrote;
`NoNewPrivileges` (or a `nosuid` mount) kills `su` and SUID with a valid
password. This is how to tell, how to work around it on an engagement, and why
enabling these is cheap, high-value post-exploitation hardening.

`confinement-check.sh` is a read-only diagnostic: run it from a service shell
and it reports which confinements apply and where you can actually write.

## PrivateTmp

The daemon ships `PrivateTmp=yes`, so it has its own `/tmp` and `/var/tmp`
namespace. Your file was written, into the service's namespace, not yours.

```bash
grep -r PrivateTmp /lib/systemd/system/ /etc/systemd/system/ 2>/dev/null
ls -l /tmp/systemd-private-*/tmp/ 2>/dev/null
```

Write outside the namespace instead: `/dev/shm` (best canary to prove exec),
`/root/.ssh/authorized_keys` (if root, converts blind exec to SSH), or a dir
the service account owns. Record exec as confirmed and delivery as the failure.

## NoNewPrivileges / nosuid

`su`/`sudo`/SUID fail with a valid password because the unit sets
`NoNewPrivileges=true` (inherited by the whole tree) or mounts the dir `nosuid`.

```bash
grep NoNewPrivs /proc/self/status          # 1 = under it
mount | grep nosuid
```

Escape the flag with a new process tree: reuse the credential over SSH (`sshd`
is its own unit). A SUID payload is inert to the service shell but works once
you re-enter over SSH.

## Defense (the confinement is the control)

Enable these on exposed service units; they shrink what a compromise becomes:
`PrivateTmp=yes`, `NoNewPrivileges=yes`, `ProtectHome=yes`,
`ProtectSystem=strict`, `nosuid,nodev,noexec` on writable temp, and a dedicated
non-root service account. Audit with `systemd-analyze security <unit>`.

## Detection

A service account writing to `/dev/shm` or `/root/.ssh/authorized_keys`, a new
interactive SSH session for a service account, and SUID files in
service-writable directories are all narrow, high-signal events.

## Use

Authorized and educational use only: your own systems, a lab you control, or an
engagement with written permission.
