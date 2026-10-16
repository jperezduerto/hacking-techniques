#!/usr/bin/env python3
"""
tunnelctl: a small, dependency-free helper for SSH tunnels (local -L, remote -R,
and dynamic SOCKS -D). It builds the ssh command for you interactively, starts
it in the background, and keeps a local inventory so you can list, re-open, and
tear down tunnels across separate invocations.

Design choices (see the writeup):
  - It shells out to the system `ssh` (as `ssh -N`, backgrounded by this process)
    so tunnels outlive the CLI and the OS handles keys and known_hosts.
  - It remembers only the USERNAME and KEY PATH per host. It never writes a
    password to disk. Password-auth hosts prompt each time and the password is
    passed to `sshpass -e` via an environment variable, never on the argv.
  - Liveness = the tracked PID is alive AND (for -L/-D) the local port listens.

Authorized and educational use only: for your own hosts, a lab, or an engagement
with written permission.
Writeup: https://jperezduerto.info/techniques/ssh-tunneling/

    python3 tunnelctl.py new        # interactive: create a tunnel
    python3 tunnelctl.py list       # show tracked tunnels and whether they are up
    python3 tunnelctl.py up <id>    # re-open a saved tunnel
    python3 tunnelctl.py down <id>  # stop a running tunnel (keeps it in inventory)
    python3 tunnelctl.py rm <id>    # stop and forget a tunnel
    python3 tunnelctl.py hosts      # list remembered host profiles
    python3 tunnelctl.py --selftest # verify the ssh-command builder
"""
import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from getpass import getpass

HOME = os.path.expanduser("~/.ssh-tunnels")
INV = os.path.join(HOME, "tunnels.json")
HOSTS = os.path.join(HOME, "hosts.json")
LOGDIR = os.path.join(HOME, "logs")


# ----- storage -------------------------------------------------------------

def _load(path, default):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (FileNotFoundError, ValueError):
        return default


def _save(path, data):
    os.makedirs(HOME, exist_ok=True)
    os.makedirs(LOGDIR, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, path)


def load_inv():
    return _load(INV, [])


def load_hosts():
    return _load(HOSTS, {})


# ----- the one piece worth testing: the ssh command --------------------------

def build_ssh_cmd(t):
    """Return the ssh argv for a tunnel dict. Pure function, covered by --selftest.

    t keys: mode (L|R|D), user, ssh_host, ssh_port, key (path or None),
            local_port, target_host, target_port (L/R only), bind_host (R only).
    """
    cmd = [
        "ssh", "-N",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "ServerAliveInterval=30",
        "-o", "ServerAliveCountMax=3",
        "-o", "StrictHostKeyChecking=accept-new",
    ]
    if t.get("key"):
        cmd += ["-i", t["key"]]
    cmd += ["-p", str(t.get("ssh_port", 22))]
    mode = t["mode"]
    if mode == "L":
        cmd += ["-L", f"{t['local_port']}:{t['target_host']}:{t['target_port']}"]
    elif mode == "R":
        cmd += ["-R", f"{t['target_port']}:{t.get('bind_host', '127.0.0.1')}:{t['local_port']}"]
    elif mode == "D":
        cmd += ["-D", str(t["local_port"])]
    else:
        raise ValueError(f"unknown mode {mode!r}")
    cmd += [f"{t['user']}@{t['ssh_host']}"]
    return cmd


# ----- liveness --------------------------------------------------------------

def pid_alive(pid):
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return pid_alive_perm(pid)
    except OSError:
        return False


def pid_alive_perm(pid):
    # PermissionError means it exists but we may not signal it; treat as alive.
    return os.path.exists(f"/proc/{pid}")


def port_listening(port, host="127.0.0.1"):
    try:
        with socket.create_connection((host, int(port)), timeout=1.5):
            return True
    except OSError:
        return False


def status(t):
    if not pid_alive(t.get("pid")):
        return "down"
    if t["mode"] in ("L", "D") and not port_listening(t["local_port"]):
        return "starting"   # process up but port not bound yet / forward failed
    return "up"


# ----- establish / stop ------------------------------------------------------

def establish(t, password=None):
    """Start the tunnel in the background; return (pid, logfile) or raise."""
    cmd = build_ssh_cmd(t)
    env = dict(os.environ)
    if password is not None:
        if not shutil.which("sshpass"):
            raise RuntimeError("password auth needs `sshpass` installed (or use a key)")
        env["SSHPASS"] = password
        cmd = ["sshpass", "-e"] + cmd      # -e reads the password from $SSHPASS, not argv
    os.makedirs(LOGDIR, exist_ok=True)
    logfile = os.path.join(LOGDIR, f"{t['id']}.log")
    log = open(logfile, "ab")
    proc = subprocess.Popen(
        cmd, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
        start_new_session=True, env=env,
    )
    time.sleep(1.5)                        # give ssh a moment to bind or fail
    if proc.poll() is not None:            # exited already = failed
        tail = open(logfile).read()[-500:]
        raise RuntimeError(f"ssh exited immediately:\n{tail.strip()}")
    return proc.pid, logfile


def stop(t):
    pid = t.get("pid")
    if pid_alive(pid):
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except OSError:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
    t["pid"] = None


# ----- host profiles (username + key path only; never a secret) --------------

def remember_host(user, ssh_host, ssh_port, auth, key):
    hosts = load_hosts()
    hosts[f"{user}@{ssh_host}:{ssh_port}"] = {
        "user": user, "ssh_host": ssh_host, "ssh_port": ssh_port,
        "auth": auth, "key": key,
    }
    _save(HOSTS, hosts)


# ----- interactive helpers ---------------------------------------------------

def ask(prompt, default=None):
    d = f" [{default}]" if default is not None else ""
    val = input(f"{prompt}{d}: ").strip()
    return val or (default if default is not None else "")


def ask_int(prompt, default=None):
    while True:
        v = ask(prompt, default)
        try:
            return int(v)
        except ValueError:
            print("  enter a number")


def pick_ssh_host():
    """Return (user, ssh_host, ssh_port, auth, key, password_or_None)."""
    hosts = load_hosts()
    if hosts:
        print("\nRemembered hosts:")
        keys = list(hosts)
        for i, k in enumerate(keys, 1):
            h = hosts[k]
            how = f"key {h['key']}" if h["auth"] == "key" else "password"
            print(f"  {i}) {k}  ({how})")
        print("  n) new host")
        choice = ask("Pick a host or 'n'", "n")
        if choice.isdigit() and 1 <= int(choice) <= len(keys):
            h = hosts[keys[int(choice) - 1]]
            pw = getpass("  SSH password (not stored): ") if h["auth"] == "password" else None
            return h["user"], h["ssh_host"], h["ssh_port"], h["auth"], h["key"], pw

    target = ask("SSH host as user@host")
    user, _, ssh_host = target.partition("@")
    if not ssh_host:
        user, ssh_host = ask("SSH username"), user
    ssh_port = ask_int("SSH port", 22)
    how = ask("Auth: (k)ey or (p)assword", "k").lower()
    if how.startswith("p"):
        pw = getpass("  SSH password (used now, not stored): ")
        remember_host(user, ssh_host, ssh_port, "password", None)
        return user, ssh_host, ssh_port, "password", None, pw
    key = ask("Private key path", os.path.expanduser("~/.ssh/id_rsa"))
    remember_host(user, ssh_host, ssh_port, "key", key)
    return user, ssh_host, ssh_port, "key", key, None


def next_id(inv):
    used = {t["id"] for t in inv}
    n = 1
    while f"t{n}" in used:
        n += 1
    return f"t{n}"


# ----- commands --------------------------------------------------------------

def cmd_new(_args):
    print("Tunnel mode:")
    print("  L) local forward   : a local port reaches a host:port through the SSH host")
    print("  R) remote forward  : a port on the SSH host reaches a service on your side")
    print("  D) dynamic SOCKS   : one local proxy port routes anything through the SSH host")
    mode = ask("Mode (L/R/D)", "L").upper()
    if mode not in ("L", "R", "D"):
        sys.exit("mode must be L, R, or D")

    user, ssh_host, ssh_port, auth, key, pw = pick_ssh_host()
    inv = load_inv()
    t = {"id": next_id(inv), "mode": mode, "user": user, "ssh_host": ssh_host,
         "ssh_port": ssh_port, "auth": auth, "key": key, "pid": None,
         "created": time.strftime("%Y-%m-%d %H:%M:%S")}

    if mode == "L":
        t["local_port"] = ask_int("Local port to open on this box")
        t["target_host"] = ask("Target host to reach (as seen from the SSH host)", "127.0.0.1")
        t["target_port"] = ask_int("Target port to reach")
    elif mode == "R":
        t["target_port"] = ask_int("Port to open ON the SSH host")
        t["bind_host"] = ask("Host your side forwards to", "127.0.0.1")
        t["local_port"] = ask_int("Port on your side to expose")
    else:  # D
        t["local_port"] = ask_int("Local SOCKS port", 1080)

    print("\n  " + " ".join(build_ssh_cmd(t)))
    if ask("Start it? (y/n)", "y").lower().startswith("n"):
        return
    try:
        t["pid"], t["logfile"] = establish(t, password=pw)
    except Exception as e:
        sys.exit(f"failed: {e}")
    inv.append(t)
    _save(INV, inv)
    print(f"[+] {t['id']} up (pid {t['pid']})")
    cmd_list(None)


def _fmt(t):
    if t["mode"] == "L":
        route = f"127.0.0.1:{t['local_port']} -> {t['target_host']}:{t['target_port']}"
    elif t["mode"] == "R":
        route = f"{t['ssh_host']}:{t['target_port']} -> {t.get('bind_host','127.0.0.1')}:{t['local_port']}"
    else:
        route = f"socks5://127.0.0.1:{t['local_port']}"
    return route


def cmd_list(_args):
    inv = load_inv()
    if not inv:
        print("no tunnels yet; run: tunnelctl new")
        return
    changed = False
    print(f"{'ID':4} {'MODE':5} {'STATUS':9} {'VIA':28} ROUTE")
    for t in inv:
        st = status(t)
        if st == "down" and t.get("pid"):
            t["pid"] = None
            changed = True
        via = f"{t['user']}@{t['ssh_host']}:{t['ssh_port']}"
        print(f"{t['id']:4} {t['mode']:5} {st:9} {via:28} {_fmt(t)}")
    if changed:
        _save(INV, inv)


def _find(inv, tid):
    for t in inv:
        if t["id"] == tid:
            return t
    sys.exit(f"no tunnel {tid!r} (see: tunnelctl list)")


def cmd_up(args):
    inv = load_inv()
    t = _find(inv, args.id)
    if status(t) == "up":
        print(f"{t['id']} already up")
        return
    pw = getpass("SSH password (not stored): ") if t["auth"] == "password" else None
    try:
        t["pid"], t["logfile"] = establish(t, password=pw)
    except Exception as e:
        sys.exit(f"failed: {e}")
    _save(INV, inv)
    print(f"[+] {t['id']} up (pid {t['pid']})")


def cmd_down(args):
    inv = load_inv()
    t = _find(inv, args.id)
    stop(t)
    _save(INV, inv)
    print(f"[-] {t['id']} stopped")


def cmd_rm(args):
    inv = load_inv()
    t = _find(inv, args.id)
    stop(t)
    inv = [x for x in inv if x["id"] != args.id]
    _save(INV, inv)
    print(f"[-] {t['id']} removed")


def cmd_hosts(_args):
    hosts = load_hosts()
    if not hosts:
        print("no remembered hosts yet")
        return
    for k, h in hosts.items():
        how = f"key {h['key']}" if h["auth"] == "key" else "password (prompted each time)"
        print(f"{k:34} {how}")


def selftest():
    cases = [
        ({"mode": "L", "user": "kali", "ssh_host": "10.0.0.5", "ssh_port": 22,
          "key": "/home/kali/.ssh/id_rsa", "local_port": 8080,
          "target_host": "172.16.0.9", "target_port": 445},
         ["ssh", "-N", "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=30",
          "-o", "ServerAliveCountMax=3", "-o", "StrictHostKeyChecking=accept-new",
          "-i", "/home/kali/.ssh/id_rsa", "-p", "22",
          "-L", "8080:172.16.0.9:445", "kali@10.0.0.5"]),
        ({"mode": "D", "user": "u", "ssh_host": "h", "ssh_port": 2222, "key": None,
          "local_port": 1080},
         ["ssh", "-N", "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=30",
          "-o", "ServerAliveCountMax=3", "-o", "StrictHostKeyChecking=accept-new",
          "-p", "2222", "-D", "1080", "u@h"]),
        ({"mode": "R", "user": "u", "ssh_host": "h", "ssh_port": 22, "key": None,
          "target_port": 9001, "bind_host": "127.0.0.1", "local_port": 80},
         ["ssh", "-N", "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=30",
          "-o", "ServerAliveCountMax=3", "-o", "StrictHostKeyChecking=accept-new",
          "-p", "22", "-R", "9001:127.0.0.1:80", "u@h"]),
    ]
    for t, expected in cases:
        got = build_ssh_cmd(t)
        assert got == expected, f"\n mode {t['mode']} expected\n  {expected}\n got\n  {got}"
    print("selftest ok: 3/3 ssh commands built correctly")


def main():
    p = argparse.ArgumentParser(description="SSH tunnel helper (local -L, remote -R, SOCKS -D)")
    p.add_argument("--selftest", action="store_true", help="verify the ssh command builder and exit")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("new", help="interactively create a tunnel")
    sub.add_parser("list", help="list tracked tunnels and whether they are up")
    sub.add_parser("hosts", help="list remembered host profiles")
    for name in ("up", "down", "rm"):
        sp = sub.add_parser(name, help=f"{name} a tunnel by id")
        sp.add_argument("id")
    args = p.parse_args()

    if args.selftest:
        return selftest()
    dispatch = {"new": cmd_new, "list": cmd_list, "hosts": cmd_hosts,
                "up": cmd_up, "down": cmd_down, "rm": cmd_rm}
    if args.cmd not in dispatch:
        p.print_help()
        return
    dispatch[args.cmd](args)


if __name__ == "__main__":
    main()
