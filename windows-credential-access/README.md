# Windows credential access

Full writeup: [jperezduerto.info/techniques/windows-credential-access](https://jperezduerto.info/techniques/windows-credential-access/)

Where Windows keeps secrets once you are admin or SYSTEM, how each store is
read, and, as the main event, what pulling it looks like to a defender.
Extraction tools (mimikatz, Impacket `secretsdump`, pypykatz, SharpDPAPI,
Rubeus) are named, not carried. A tunable Sigma ruleset is in
[`detection/sigma-credential-access.yml`](detection/sigma-credential-access.yml).

## The stores

- **SAM + SYSTEM hives** (local hashes): `reg save HKLM\SAM` + `HKLM\SYSTEM`,
  parse offline. Harden: LAPS, limit local admin.
- **LSASS memory** (hashes, tickets, sometimes plaintext): minidump via
  `rundll32 comsvcs.dll, MiniDump <pid> out.dmp full`, parse offline. Harden:
  Credential Guard, `RunAsPPL`, the LSASS ASR rule, disable WDigest.
- **LSA secrets + cached domain logons** (`SECURITY` hive, DCC2): same hive
  theft with the LSA option. Harden: limit cached logons, Credential Guard.
- **DPAPI** (browser, Credential Manager, RDP, Wi-Fi): masterkey or domain
  backup key decrypts user secrets. Harden: Credential Guard, protect the
  backup key as tier-0.
- **Stored creds / files**: `cmdkey /list`, `vaultcmd`, `unattend.xml`, SYSVOL
  `Groups.xml` cpassword, `web.config`. Harden: scrub them.
- **DCSync** (domain-wide): replication rights pull any hash incl. `krbtgt`
  from a DC. Harden: minimize replication rights, alert on non-DC replication.

## Detection, highest value first

- **LSASS access**: Sysmon 10 with sensitive `GrantedAccess` (e.g. `0x1010`,
  `0x1410`), `comsvcs.dll MiniDump`, `.dmp` near lsass.
- **DCSync from a non-DC**: event 4662 with replication GUIDs, or DRSUAPI from a
  non-DC. Near-zero false positives.
- **Hive theft**: `reg save` / `esentutl` / VSS against SAM/SYSTEM/SECURITY.
- **DPAPI backup key** pulled from a DC; masterkey-directory access.
- **GPP/SYSVOL** cpassword reads; known credential-file access.

Collect 4688 with command line and deploy Sysmon, or most of this is invisible.

## Hardening

Credential Guard + LSASS PPL + the ASR rule; LAPS; tiered admin so a workstation
credential cannot reach a DC; disable WDigest; limit cached logons; minimize and
monitor replication rights; protect the DPAPI backup key and `krbtgt` as tier-0.

## Use

Authorized and educational use only: your own systems, a lab you control, or an
engagement with written permission. Describes where credentials live and how
their extraction looks so defenders can detect and close it; carries no
extraction tooling.
