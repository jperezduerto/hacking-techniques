# SSH tunneling (local, remote, dynamic SOCKS) + tunnelctl

Full writeup: [jperezduerto.info/techniques/ssh-tunneling](https://jperezduerto.info/techniques/ssh-tunneling/)

An SSH session multiplexes arbitrary TCP, so one login on a reachable host is a
route onto a network you cannot otherwise reach. Three forward directions, then
a small dependency-free CLI (`tunnelctl.py`) that manages them.

## The three forwards

```bash
# -L local: a local port reaches target_host:target_port via the SSH host
ssh -L 8445:172.16.0.9:445 user@ssh_host

# -R remote: a port on the SSH host reaches a service on your side
ssh -R 9001:127.0.0.1:80 user@ssh_host

# -D dynamic: one local SOCKS5 proxy reaches anything the SSH host can
ssh -D 1080 user@ssh_host
proxychains -q curl http://172.16.0.20/
```

Run with `-N` (no shell), keepalives (`-o ServerAliveInterval=30`),
`-o ExitOnForwardFailure=yes`, and `-J hop1,hop2` to chain hops. Resolve names
at the far end (`--socks5-hostname`, proxychains `proxy_dns`).

## tunnelctl

Dependency-free (Python 3 stdlib; `sshpass` only for password hosts). It builds
the command interactively, backgrounds it, and tracks an inventory so you can
list/reopen/kill tunnels across runs. It remembers username + key path per host
and never stores a password (password hosts prompt each time, passed via
`sshpass -e` in the environment, never on the argv or disk).

```bash
python3 tunnelctl.py new        # interactive: mode, SSH host, ports, auth
python3 tunnelctl.py list       # routes + whether each is actually up
python3 tunnelctl.py up <id>    # reopen a saved tunnel
python3 tunnelctl.py down <id>  # stop (keep in inventory)
python3 tunnelctl.py rm <id>    # stop and forget
python3 tunnelctl.py hosts      # remembered host profiles
python3 tunnelctl.py --selftest # verify the ssh-command builder
```

State lives under `~/.ssh-tunnels/` (`tunnels.json`, `hosts.json`, `logs/`).
Liveness = the tracked PID is alive and, for `-L`/`-D`, the local port listens.

## Defense

`AllowTcpForwarding no` (or scoped `local`/`remote`), `AllowStreamLocalForwarding
no`, `GatewayPorts no`, `PermitTunnel no`, `Match` blocks per account, and
`no-port-forwarding` in `authorized_keys`. Funnel admin SSH through a bastion
with `LogLevel VERBOSE` and ship the logs. Default-deny egress and segmentation.

## Detection

Long-lived `ssh` with `-L`/`-R`/`-D`; a host listening on odd local ports owned
by `ssh`; `sshd` VERBOSE `direct-tcpip`/`forwarded-tcpip` channel opens; one
internal host relaying to many others; DNS resolved at a jump host.

## Use

Authorized and educational use only: your own hosts, a lab you control, or an
engagement with written permission. Run `tunnelctl` only against hosts you are
authorized to reach.
