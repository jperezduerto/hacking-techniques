# The curl dot-dot trap (path-traversal false negatives)

Full writeup: [jperezduerto.info/techniques/curl-path-traversal-false-negative](https://jperezduerto.info/techniques/curl-path-traversal-false-negative/)

curl collapses `../` in a URL path client-side before sending, so a vulnerable
endpoint answers normally and you record it as safe. Fix: `--path-as-is`, and
read the request you actually sent. `traversal-check.sh` sends a payload both
ways (normalized vs verbatim) and tries the common encoded variants, printing
the request line each time.

## The trap

```bash
curl -v   'http://TARGET/download?file=../../etc/passwd'              # ../ stripped before sending
curl -v --path-as-is 'http://TARGET/download?file=../../etc/passwd'   # sent verbatim
```

Use `--path-as-is` unconditionally for traversal work and confirm with `-v`.

## The real rule

The tool quietly changed your payload. Same class of self-inflicted false
negative: shells eating backslashes, `-G` moving data into the query, `-L`
following a redirect that drops your parameter. Encoded variants (`%2e%2e%2f`,
`..%2f`, `....//`) defeat server filters, not curl's normalization: try a plain
`../ --path-as-is` first.

## For defenders

Do not trust a single tool's negative in a test or scanner. Server-side, resolve
the path to a canonical absolute form and verify it stays within the intended
base directory, rather than filtering `../` substrings.

## Detection

Raw and encoded traversal in paths/queries (`..%2f`, `%2e%2e`, `....//`, `../`)
plus reads of `/etc/passwd` or `web.config`; normalize the request the way the
server will, then flag an escape above the web root.

## Use

Authorized and educational use only: your own systems, a lab you control, or an
engagement with written permission.
