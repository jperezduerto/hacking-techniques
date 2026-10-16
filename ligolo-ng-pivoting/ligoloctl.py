#!/usr/bin/env python3
"""
ligoloctl: the attack-box plumbing for ligolo-ng, so the fiddly part is not
done by hand. It creates and tears down the `ligolo` TUN interface, adds and
removes routes while normalizing each CIDR to its network address (so a host
address like 172.16.5.129/23 becomes 172.16.4.0/23 instead of a route that
matches nothing), tracks what it added in a local inventory, and cleans up
exactly what it created. The ligolo-ng proxy and agent are still their own
binaries; this only manages the OS interface and routes.

Linux only (it drives `ip`); uses sudo automatically when not run as root.
No third-party dependencies.

Authorized and educational use only: route only networks you are authorized to
reach, and run `cleanup` when the engagement ends.
Writeup: https://jperezduerto.info/techniques/ligolo-ng-pivoting/

    sudo python3 ligoloctl.py up                 # create + bring up the ligolo tun
    python3 ligoloctl.py add 172.16.1.0/24       # route a subnet to it (normalized)
    python3 ligoloctl.py list                    # show tun + routes (ours and the kernel's)
    python3 ligoloctl.py del 172.16.1.0/24
    python3 ligoloctl.py down                     # remove the tun
    python3 ligoloctl.py cleanup                  # remove every route we added, then the tun
    python3 ligoloctl.py --selftest
"""
import argparse
import ipaddress
import json
import os
import subprocess
import sys

STATE = os.path.expanduser("~/.ligolo")
INV = os.path.join(STATE, "routes.json")


def load():
    try:
        with open(INV) as fh:
            return json.load(fh)
    except (FileNotFoundError, ValueError):
        return {"iface": "ligolo", "routes": []}


def save(data):
    os.makedirs(STATE, exist_ok=True)
    tmp = INV + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, INV)


def normalize_cidr(cidr):
    """Return (network_cidr, was_changed). Host bits are dropped to the network
    address so the route covers what you mean. Raises ValueError on garbage."""
    net = ipaddress.ip_network(cidr, strict=False)
    normalized = str(net)
    return normalized, (normalized != cidr)


def ip_cmd(args):
    """Build the `ip` argv, prefixing sudo when not root."""
    base = [] if (hasattr(os, "geteuid") and os.geteuid() == 0) else ["sudo"]
    return base + ["ip"] + args


def run(args, check=True):
    cmd = ip_cmd(args)
    res = subprocess.run(cmd, capture_output=True, text=True)
    if check and res.returncode != 0:
        raise RuntimeError(f"`{' '.join(cmd)}` failed: {res.stderr.strip() or res.stdout.strip()}")
    return res


def iface_exists(name):
    return subprocess.run(ip_cmd(["link", "show", name]),
                          capture_output=True, text=True).returncode == 0


def cmd_up(args):
    name = args.iface
    if iface_exists(name):
        print(f"[=] {name} already exists")
    else:
        run(["tuntap", "add", "user", os.environ.get("USER", "root"), "mode", "tun", name])
        print(f"[+] created tun {name}")
    run(["link", "set", name, "up"])
    print(f"[+] {name} is up")
    inv = load(); inv["iface"] = name; save(inv)


def cmd_down(args):
    name = args.iface
    if not iface_exists(name):
        print(f"[=] {name} does not exist")
        return
    run(["link", "set", name, "down"], check=False)
    run(["tuntap", "del", "mode", "tun", name], check=False)
    print(f"[-] removed tun {name}")


def cmd_add(args):
    name = args.iface
    net, changed = normalize_cidr(args.cidr)
    if changed:
        print(f"[!] normalized {args.cidr} -> {net} (host bits dropped to the network address)")
    if not iface_exists(name):
        sys.exit(f"{name} is not up; run: ligoloctl up")
    run(["route", "add", net, "dev", name])
    inv = load()
    if net not in inv["routes"]:
        inv["routes"].append(net); save(inv)
    print(f"[+] routed {net} via {name}")


def cmd_del(args):
    name = args.iface
    net, _ = normalize_cidr(args.cidr)
    run(["route", "del", net, "dev", name], check=False)
    inv = load()
    inv["routes"] = [r for r in inv["routes"] if r != net]
    save(inv)
    print(f"[-] removed route {net}")


def cmd_list(args):
    name = args.iface
    inv = load()
    print(f"interface {name}: {'up' if iface_exists(name) else 'absent'}")
    print("routes we added (inventory):")
    for r in inv["routes"]:
        print(f"  {r}")
    if iface_exists(name):
        res = subprocess.run(ip_cmd(["route", "show", "dev", name]), capture_output=True, text=True)
        print(f"kernel routes on {name}:")
        for line in res.stdout.splitlines():
            print(f"  {line}")


def cmd_cleanup(args):
    name = args.iface
    inv = load()
    for net in list(inv["routes"]):
        run(["route", "del", net, "dev", name], check=False)
        print(f"[-] removed route {net}")
    inv["routes"] = []; save(inv)
    if iface_exists(name):
        run(["link", "set", name, "down"], check=False)
        run(["tuntap", "del", "mode", "tun", name], check=False)
        print(f"[-] removed tun {name}")
    print("[+] clean")


def selftest():
    cases = [
        ("172.16.5.129/23", "172.16.4.0/23", True),
        ("10.0.0.0/24", "10.0.0.0/24", False),
        ("192.168.1.50/24", "192.168.1.0/24", True),
        ("10.10.14.6/16", "10.10.0.0/16", True),
    ]
    for cidr, expect_net, expect_changed in cases:
        net, changed = normalize_cidr(cidr)
        assert net == expect_net and changed == expect_changed, f"{cidr} -> {net},{changed}"
    assert ip_cmd(["route", "add", "x"])[-3:] == ["route", "add", "x"]
    print(f"selftest ok: {len(cases)}/{len(cases)} CIDR normalizations + ip argv")


def main():
    p = argparse.ArgumentParser(description="attack-box TUN/route plumbing for ligolo-ng")
    p.add_argument("--iface", default="ligolo", help="tun interface name (default: ligolo)")
    p.add_argument("--selftest", action="store_true", help="verify CIDR normalization and exit")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("up"); sub.add_parser("down"); sub.add_parser("list")
    sub.add_parser("status"); sub.add_parser("cleanup")
    for name in ("add", "del"):
        sp = sub.add_parser(name); sp.add_argument("cidr")
    args = p.parse_args()

    if args.selftest:
        return selftest()
    dispatch = {"up": cmd_up, "down": cmd_down, "add": cmd_add, "del": cmd_del,
                "list": cmd_list, "status": cmd_list, "cleanup": cmd_cleanup}
    if args.cmd not in dispatch:
        p.print_help()
        return
    try:
        dispatch[args.cmd](args)
    except (RuntimeError, ValueError) as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
