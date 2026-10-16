# Registry hive credential dumping (+ hivekit)

Full writeup: [jperezduerto.info/techniques/offline-registry-hive-dumping](https://jperezduerto.info/techniques/offline-registry-hive-dumping/)

Local Windows account secrets are split across three registry hives that are
useless apart:

- **SAM** holds the local accounts and their encrypted hashes.
- **SYSTEM** holds the pieces of the boot key (syskey) that decrypt them.
- **SECURITY** holds the LSA secrets, including a cleartext autologon
  `DefaultPassword`, and the cached domain logons (DCC2).

SYSTEM is the key ring for the other two, which is why you copy all three or
nothing decrypts. Every hive file starts with the ASCII bytes `regf`.

## The concept, end to end

1. Save the three hives (`reg save HKLM\SAM|SYSTEM|SECURITY`), which needs admin
   or backup rights and serializes a consistent copy of the kernel-locked files.
2. Move them off the host. If the only channel is text, encode the binary first
   (`certutil -encode`), and for a large hive read it in ordered pieces.
3. Reassemble and validate the bytes (that is all `hivekit.py` does).
4. Parse offline with the Impacket `secretsdump` `LOCAL` mode (not included here)
   to get local NT hashes and LSA secrets.
5. A recovered local Administrator hash can authenticate directly over WinRM/SMB
   (pass-the-hash) if the account allows network logon.

## hivekit

Dependency-free Python 3 stdlib. It is **inert on purpose**: it joins base64
parts in order, strips `certutil` PEM framing, decodes, and checks the `regf`
magic so you know the reassembly worked. It does not connect anywhere, read the
registry, or parse any secret. It is the glue you would otherwise hand-write
while practicing.

```bash
python3 hivekit.py --out system.save part00.b64 part01.b64 part02.b64
python3 hivekit.py --out sam.save sam.b64
python3 hivekit.py --selftest
```

## Defense (short version, full version in the writeup)

- **LAPS** so each host has a unique rotating local admin password. This is the
  highest-value control: it kills the pass-the-hash fan-out that makes dumping
  one hive worthwhile.
- **Turn autologon off** where it is not essential (the `DefaultPassword` LSA
  secret is a cleartext credential).
- **Tier admin scope** so one host's local admin cannot reach tier-0.
- **Lower `CachedLogonsCount`** on servers that do not need offline logon.
- Keep local admin membership and `SeBackupPrivilege` minimal.

## Detection

- `reg.exe save` / `esentutl.exe` / VSS referencing `SAM`, `SYSTEM`, `SECURITY`
  (event 4688 or Sysmon 1 with command line).
- `certutil -encode`/`-decode` against a non-certificate file, especially right
  after a hive save.
- A `--local-auth` WinRM/SMB logon (NTLM local account, logon type 3) from an
  unusual source, which is the dumped hash being used.

## Use

Authorized and educational use only: your own systems, a lab you control, or an
engagement with written permission. Practice against a VM you built. This folder
carries no extraction tooling.
