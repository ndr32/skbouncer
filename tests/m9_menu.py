#!/usr/bin/env python3
"""Drives `sudo -n ./skbouncer` with no arguments through a pseudo-terminal,
the way a person at the keyboard would, and records what the menu printed.

usage: m9_menu.py OUTDIR CONTAINER POLICY SERVER_IP VETH
"""
import json
import os
import pty
import re
import select
import subprocess
import sys
import time

out, cont, policy, sip, veth = sys.argv[1:]
log = open(f"{out}/menu.transcript", "w")
buf = ""
steps = {}


def read_until(pattern, timeout=15):
    """Reads the terminal until `pattern` appears in the text since the last
    match. Returns that text, or None on timeout."""
    global buf
    end = time.time() + timeout
    while time.time() < end:
        m = re.search(pattern, buf)
        if m:
            seen, buf = buf[:m.end()], buf[m.end():]
            return seen
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                data = os.read(fd, 4096).decode(errors="replace")
            except OSError:
                break
            log.write(data)
            log.flush()
            buf += data
    return None


def send(text):
    os.write(fd, text.encode())


def attached():
    o = subprocess.run(["sudo", "-n", "bpftool", "net", "show", "dev", veth],
                       capture_output=True, text=True).stdout
    return o.count("skb_tc")


def handshake(args):
    o = subprocess.run(["docker", "exec", cont, "sh", "-c",
                        f"timeout 5 openssl s_client -brief -connect {sip}:4433 {args} </dev/null 2>&1"],
                       capture_output=True, text=True).stdout
    return "CONNECTION ESTABLISHED" in o


pid, fd = pty.fork()
if pid == 0:
    os.execvp("sudo", ["sudo", "-n", "./skbouncer"])

steps["menu"] = read_until(r"Choose: ") is not None

# 5: list containers.
send("5\n")
seen = read_until(r"Choose: ")
steps["list"] = bool(seen and cont in seen and veth in seen)

# 4: check a policy.
send("4\n")
steps["check_prompt"] = read_until(r"Policy file: ") is not None
send(policy + "\n")
seen = read_until(r"Choose: ")
steps["check"] = seen or ""

# 3: enforce, declined. Nothing may be attached.
send("3\n")
seen = read_until(r"Container: ")
num = re.search(rf"(\d+)\s+{re.escape(cont)}\b", seen or "")
steps["picker"] = bool(num)
send((num.group(1) if num else "1") + "\n")
read_until(r"Policy file: ")
send(policy + "\n")
steps["confirm_prompt"] = read_until(r"Continue\? \[y/N\] ") is not None
send("n\n")
steps["declined_back"] = read_until(r"Choose: ") is not None
steps["declined_attached"] = attached()

# 2: audit with live handshakes, then Ctrl-C back to the menu.
send("2\n")
read_until(r"Container: ")
send((num.group(1) if num else "1") + "\n")
read_until(r"Policy file: ")
send(policy + "\n")
# skbouncer's own start line, printed once attached; the menu's
# "(Ctrl-C ends the run ...)" line comes before the program attaches.
seen = read_until(r"container \S+ \(\S+ ingress\); Ctrl-C to stop", timeout=20)
steps["running_line"] = bool(seen and re.search(r"Running: \S*skbouncer .*--container " + re.escape(cont), seen))
steps["audit_attached"] = attached()
steps["violating_ok"] = handshake("")
steps["allowed_ok"] = handshake("-tls1_3")
time.sleep(1)
send("\x03")
seen = read_until(r"Choose: ", timeout=20)
steps["after_ctrl_c"] = seen or ""
steps["after_attached"] = attached()

# q: quit.
send("q\n")
read_until(r"$^", timeout=3)
_, status = os.waitpid(pid, 0)
steps["exit_status"] = os.waitstatus_to_exitcode(status)
json.dump(steps, open(f"{out}/menu.json", "w"), indent=1)
